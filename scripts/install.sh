#!/usr/bin/env bash
set -euo pipefail

readonly service_name="antiddos.service"
readonly service_user="antiddos"
readonly service_group="antiddos"
readonly binary_path="/usr/local/bin/antiddos"
readonly config_dir="/etc/antiddos"
readonly config_path="${config_dir}/config.json"
readonly environment_path="/etc/default/antiddos"
readonly unit_path="/etc/systemd/system/${service_name}"
readonly state_dir="/var/lib/antiddos"
readonly github_repository="it-nsk/antiddos"

log_file_override=""
release_version="latest"
start_service=1

usage() {
    cat <<'EOF'
Usage: sudo ./scripts/install.sh [OPTIONS]

Download a verified antiddos release and install the systemd service.

Options:
  --log-file PATH  Override config log_file through /etc/default/antiddos
  --version TAG    Install a specific release, for example v0.1.0
  --no-start       Install files without enabling or starting the service
  -h, --help       Show this help

Existing /etc/antiddos/config.json and SQLite data are preserved.
EOF
}

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

while (($# > 0)); do
    case "$1" in
        --log-file)
            (($# >= 2)) || fail "--log-file requires a path"
            log_file_override="$2"
            shift 2
            ;;
        --version)
            (($# >= 2)) || fail "--version requires a tag"
            release_version="$2"
            shift 2
            ;;
        --no-start)
            start_service=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown option: $1"
            ;;
    esac
done

((EUID == 0)) || fail "run this script through sudo"

if [[ -n "$log_file_override" ]]; then
    [[ "$log_file_override" == /* ]] || fail "--log-file must be an absolute path"
    [[ "$log_file_override" != *$'\n'* && "$log_file_override" != *$'\r'* ]] || fail "--log-file must be one line"
fi
if [[ "$release_version" != "latest" ]]; then
    [[ "$release_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || \
        fail "--version must look like v0.1.0"
fi

for command in curl tar sha256sum install mktemp getent groupadd useradd usermod \
    chown chmod systemctl runuser journalctl sed head tail stat dirname mv rm \
    sleep uname; do
    command -v "$command" >/dev/null || fail "required command is not installed: $command"
done

build_dir="$(mktemp -d /tmp/antiddos-install.XXXXXX)"
cleanup() {
    rm -rf "$build_dir"
}
trap cleanup EXIT

case "$(uname -m)" in
    x86_64|amd64)
        release_arch="amd64"
        ;;
    *)
        fail "unsupported architecture: $(uname -m); available release architecture: amd64"
        ;;
esac

asset="antiddos-linux-${release_arch}.tar.gz"
checksum_asset="${asset}.sha256"
if [[ "$release_version" == "latest" ]]; then
    release_url="https://github.com/${github_repository}/releases/latest/download"
else
    release_url="https://github.com/${github_repository}/releases/download/${release_version}"
fi

echo "[1/7] Downloading antiddos ${release_version} for linux/${release_arch}"
curl --fail --location --silent --show-error \
    "${release_url}/${asset}" \
    --output "${build_dir}/${asset}"
curl --fail --location --silent --show-error \
    "${release_url}/${checksum_asset}" \
    --output "${build_dir}/${checksum_asset}"
(
    cd "$build_dir"
    sha256sum --check "$checksum_asset"
    tar -xzf "$asset"
)

for payload in antiddos antiddos.service config.example.json antiddos.env.example; do
    [[ -f "${build_dir}/${payload}" ]] || fail "release archive is missing ${payload}"
done

echo "[2/7] Creating service account"
if ! getent group "$service_group" >/dev/null; then
    groupadd --system "$service_group"
fi
if ! getent passwd "$service_user" >/dev/null; then
    useradd \
        --system \
        --gid "$service_group" \
        --home-dir "$state_dir" \
        --shell /usr/sbin/nologin \
        "$service_user"
fi

echo "[3/7] Installing binary, unit, and configuration"
install -d -o root -g "$service_group" -m 0750 "$config_dir"
install -d -o "$service_user" -g "$service_group" -m 0700 "$state_dir"

install -o root -g root -m 0755 "${build_dir}/antiddos" "${binary_path}.new"
mv -f "${binary_path}.new" "$binary_path"
install -o root -g root -m 0644 "${build_dir}/antiddos.service" "$unit_path"

if [[ ! -e "$config_path" ]]; then
    install -o root -g "$service_group" -m 0640 "${build_dir}/config.example.json" "$config_path"
    echo "      Created ${config_path} from the example"
else
    chown root:"$service_group" "$config_path"
    chmod 0640 "$config_path"
    echo "      Preserved existing ${config_path}"
fi

if [[ -n "$log_file_override" ]]; then
    printf 'ANTIDDOS_LOG_FILE=%s\n' "$log_file_override" >"${environment_path}.new"
    chown root:"$service_group" "${environment_path}.new"
    chmod 0640 "${environment_path}.new"
    mv -f "${environment_path}.new" "$environment_path"
elif [[ ! -e "$environment_path" ]]; then
    install -o root -g "$service_group" -m 0640 "${build_dir}/antiddos.env.example" "$environment_path"
fi

chown -R "$service_user":"$service_group" "$state_dir"
chmod 0700 "$state_dir"

configured_log="$log_file_override"
if [[ -z "$configured_log" && -r "$environment_path" ]]; then
    configured_log="$(sed -n 's/^[[:space:]]*ANTIDDOS_LOG_FILE[[:space:]]*=[[:space:]]*//p' "$environment_path" | tail -n 1)"
    configured_log="${configured_log%\"}"
    configured_log="${configured_log#\"}"
fi
if [[ -z "$configured_log" ]]; then
    configured_log="$(sed -n 's/^[[:space:]]*"log_file"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$config_path" | head -n 1)"
fi
if [[ -n "$configured_log" && ! -d "$(dirname "$configured_log")" ]]; then
    fail "log directory does not exist: $(dirname "$configured_log")"
fi

echo "[4/7] Granting access to the Nginx log"
if getent group adm >/dev/null; then
    usermod -a -G adm "$service_user"
fi
if [[ -n "$configured_log" ]]; then
    for readable_path in "$(dirname "$configured_log")" "$configured_log"; do
        if [[ -e "$readable_path" ]]; then
            path_group="$(stat -c '%G' "$readable_path")"
            if [[ "$path_group" != "root" && "$path_group" != "$service_group" ]]; then
                usermod -a -G "$path_group" "$service_user"
            fi
        fi
    done
fi

echo "[5/7] Reloading systemd"
systemctl daemon-reload

if ((start_service == 0)); then
    echo "[6/7] Service start skipped (--no-start)"
    echo "[7/7] Installation complete"
    echo "Edit ${config_path}, then run: sudo systemctl enable --now ${service_name}"
    exit 0
fi

if [[ -n "$configured_log" && -e "$configured_log" ]]; then
    if ! runuser -u "$service_user" -- head -c 0 "$configured_log" >/dev/null; then
        fail "${service_user} cannot read ${configured_log}; grant its group read access and rerun the installer"
    fi
fi

echo "[6/7] Enabling and restarting service"
systemctl enable "$service_name" >/dev/null
if ! systemctl restart "$service_name"; then
    systemctl status "$service_name" --no-pager --full || true
    journalctl -u "$service_name" -n 30 --no-pager || true
    fail "service failed to start"
fi

if ! systemctl is-active --quiet "$service_name"; then
    systemctl status "$service_name" --no-pager --full || true
    journalctl -u "$service_name" -n 30 --no-pager || true
    fail "service is not active"
fi

monitor_ready=0
for _ in {1..10}; do
    if runuser -u "$service_user" -- "$binary_path" monitor --once >/dev/null 2>&1; then
        monitor_ready=1
        break
    fi
    sleep 1
done
((monitor_ready == 1)) || fail "service is active, but SQLite monitor did not become ready"

echo "[7/7] Installation verified"
echo "Service:  systemctl status ${service_name}"
echo "Monitor:  sudo -u ${service_user} ${binary_path} monitor"
echo "Config:   ${config_path}"
echo "Database: ${state_dir}/antiddos.sqlite"
