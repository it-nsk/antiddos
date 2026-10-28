#!/usr/bin/env bash
set -euo pipefail

readonly service_name="antiddos.service"
readonly service_user="antiddos"
readonly service_group="antiddos"
readonly challenge_service_name="antiddos-challenge.service"
readonly challenge_user="antiddos-challenge"
readonly challenge_group="antiddos-check"
readonly feed_group="antiddos-soft-feed"
readonly challenge_read_group="antiddos-challenge-read"
readonly web_user="antiddos-web"
readonly web_group="antiddos-web"
readonly binary_path="/usr/local/bin/antiddos"
readonly config_dir="/etc/antiddos"
readonly config_path="${config_dir}/config.json"
readonly environment_path="/etc/default/antiddos"
readonly unit_path="/etc/systemd/system/${service_name}"
readonly challenge_unit_path="/etc/systemd/system/${challenge_service_name}"
readonly soft_block_dropin_dir="/etc/systemd/system/${service_name}.d"
readonly soft_block_dropin_path="${soft_block_dropin_dir}/soft-block.conf"
readonly challenge_config_dir="/etc/antiddos-challenge"
readonly challenge_keys_path="${challenge_config_dir}/keys.json"
readonly state_dir="/var/lib/antiddos"
readonly web_state_dir="/var/lib/antiddos-web"
readonly web_users_db="/var/lib/antiddos-web/users.sqlite"
readonly github_repository="it-nsk/antiddos"

log_file_override=""
release_version="latest"
start_service=1
install_web=0
install_soft_block=0
disable_soft_block=0
confirm_nginx_detached=0
migrate_from_nftables=0
use_local_build=0
web_admin_created=0
web_admin_missing=0
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
checkout_dir="$(dirname -- "$script_dir")"

usage() {
    cat <<'EOF'
Usage: sudo ./scripts/install.sh [OPTIONS]

Install a verified release or a locally built checkout as systemd services.

Options:
  --log-file PATH  Override config log_file through /etc/default/antiddos
  --version TAG    Install a specific release, for example v0.1.0
  --no-start       Install files without enabling or starting the service
  --web            Install the localhost web UI and create the initial admin
  --soft-block     Install the soft-block feed and challenge checker units
  --disable-soft-block  Stop and remove the challenge checker unit
  --confirm-nginx-detached  Confirm all generated Nginx includes were removed and Nginx was reloaded
  --migrate-from-nftables  Offline removal of the validated AntiDDoS nftables table when switching to soft-block
  --local          Use the built binary and deploy files from this checkout (development only)
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
        --web)
            install_web=1
            shift
            ;;
        --soft-block)
            install_soft_block=1
            shift
            ;;
        --disable-soft-block)
            disable_soft_block=1
            shift
            ;;
        --confirm-nginx-detached)
            confirm_nginx_detached=1
            shift
            ;;
        --migrate-from-nftables)
            migrate_from_nftables=1
            shift
            ;;
        --local)
            use_local_build=1
            shift
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

if ((install_soft_block && disable_soft_block)); then
    fail "--soft-block and --disable-soft-block cannot be used together"
fi
if ((confirm_nginx_detached && !disable_soft_block)); then
    fail "--confirm-nginx-detached requires --disable-soft-block"
fi
if ((migrate_from_nftables && !install_soft_block)); then
    fail "--migrate-from-nftables requires --soft-block"
fi

# Keep an existing soft-block installation intact when the operator upgrades
# the main daemon without repeating --soft-block.
if [[ -f "$challenge_unit_path" ]]; then
    install_soft_block=1
fi

if ((disable_soft_block)); then
    command -v systemctl >/dev/null || fail "required command is not installed: systemctl"
    command -v rm >/dev/null || fail "required command is not installed: rm"
    ((confirm_nginx_detached)) || fail "remove generated Nginx includes, run nginx -t and reload Nginx, then repeat with --confirm-nginx-detached"
    if systemctl is-active --quiet "$challenge_service_name" || \
        systemctl is-enabled --quiet "$challenge_service_name"; then
        systemctl disable --now "$challenge_service_name"
    fi
    if [[ -e "$challenge_unit_path" || -L "$challenge_unit_path" ]]; then
        rm -f -- "$challenge_unit_path"
    fi
    systemctl daemon-reload
    echo "Challenge checker disabled and its unit removed after explicit Nginx-detached confirmation."
    echo "Keys, feed drop-in, groups, daemon, and database are preserved."
    echo "Reinstall the checker with: sudo bash scripts/install.sh --soft-block"
    exit 0
fi

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
    sleep uname setpriv; do
    command -v "$command" >/dev/null || fail "required command is not installed: $command"
done

if ((install_soft_block)); then
    command -v openssl >/dev/null || fail "required command is not installed: openssl"
fi
if ((migrate_from_nftables)); then
    command -v nft >/dev/null || fail "required command is not installed: nft"
fi

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

if ((use_local_build)); then
    echo "[1/7] Using the local build from ${checkout_dir}"
    [[ -x "${checkout_dir}/antiddos" ]] || fail "local binary is missing; build it first with go build -o antiddos ./cmd/antiddos"
    for payload in antiddos.service antiddos-web.service config.example.json config.security.example.json antiddos.env.example; do
        [[ -f "${checkout_dir}/deploy/${payload}" ]] || fail "local checkout is missing deploy/${payload}"
    done
    install -m 0755 "${checkout_dir}/antiddos" "${build_dir}/antiddos"
    install -m 0644 "${checkout_dir}/deploy/antiddos.service" "${build_dir}/antiddos.service"
    install -m 0644 "${checkout_dir}/deploy/antiddos-web.service" "${build_dir}/antiddos-web.service"
    install -m 0644 "${checkout_dir}/deploy/config.example.json" "${build_dir}/config.example.json"
    install -m 0644 "${checkout_dir}/deploy/config.security.example.json" "${build_dir}/config.security.example.json"
    install -m 0644 "${checkout_dir}/deploy/antiddos.env.example" "${build_dir}/antiddos.env.example"
    if ((install_soft_block)); then
        for payload in antiddos-challenge.service antiddos-soft-block.conf; do
            [[ -f "${checkout_dir}/deploy/${payload}" ]] || fail "local checkout is missing deploy/${payload}"
            install -m 0644 "${checkout_dir}/deploy/${payload}" "${build_dir}/${payload}"
        done
    fi
else
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
fi

for payload in antiddos antiddos.service config.example.json config.security.example.json antiddos.env.example; do
    [[ -f "${build_dir}/${payload}" ]] || fail "release archive is missing ${payload}"
done
if ((install_soft_block)); then
    for payload in antiddos-challenge.service antiddos-soft-block.conf; do
        [[ -f "${build_dir}/${payload}" ]] || fail "installation payload is missing ${payload}"
    done
fi

# Keep an existing web installation enabled and writable during upgrades.
if [[ -f /etc/systemd/system/antiddos-web.service ]]; then
    install_web=1
fi
if ((install_web)); then
    [[ -f "${build_dir}/antiddos-web.service" ]] || fail "release has no web UI; install a release containing the web feature"
fi

if ((migrate_from_nftables)); then
    echo "      Stopping ${service_name} for offline nftables migration"
    systemctl stop "$service_name"
fi

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
if ((install_soft_block)); then
    getent group "$feed_group" >/dev/null || groupadd --system "$feed_group"
    getent group "$challenge_group" >/dev/null || groupadd --system "$challenge_group"
    getent group "$challenge_read_group" >/dev/null || groupadd --system "$challenge_read_group"
    if ! getent passwd "$challenge_user" >/dev/null; then
        useradd --system --gid "$challenge_group" --home-dir /nonexistent \
            --shell /usr/sbin/nologin --groups "$feed_group,$challenge_read_group" "$challenge_user"
    fi
    usermod -a -G "$feed_group,$challenge_read_group" "$challenge_user"
    usermod -a -G "$challenge_read_group" "$service_user"
fi

echo "[3/7] Installing binary, unit, and configuration"
install -d -o root -g "$service_group" -m 0750 "$config_dir"
install -d -o "$service_user" -g "$service_group" -m 0700 "$state_dir"

install -o root -g root -m 0755 "${build_dir}/antiddos" "${binary_path}.new"
mv -f "${binary_path}.new" "$binary_path"
install -o root -g root -m 0644 "${build_dir}/antiddos.service" "$unit_path"

if ((install_soft_block)); then
    install -d -o root -g root -m 0700 "$challenge_config_dir"
    [[ ! -L "$challenge_keys_path" ]] || fail "refusing symlink challenge credentials path"
    if [[ ! -e "$challenge_keys_path" ]]; then
        key_tmp="$(mktemp "${challenge_keys_path}.XXXXXX")"
        provider_secret="$(openssl rand -base64 32 | tr -d '\n')"
        cookie_secret="$(openssl rand -base64 32 | tr -d '\n')"
        printf '{"provider_secret":"%s","current":{"id":"k1","secret":"%s"},"previous":[]}\n' \
            "$provider_secret" "$cookie_secret" >"$key_tmp"
        chown root:root "$key_tmp"
        chmod 0600 "$key_tmp"
        mv -n "$key_tmp" "$challenge_keys_path"
        [[ ! -e "$key_tmp" ]] || rm -f "$key_tmp"
        echo "      Created private challenge keys at ${challenge_keys_path}"
    else
        [[ -f "$challenge_keys_path" && ! -L "$challenge_keys_path" ]] || fail "challenge credentials path is not a regular non-symlink file"
        chown root:root "$challenge_keys_path"
        chmod 0600 "$challenge_keys_path"
        echo "      Preserved existing challenge keys"
    fi
    install -o root -g root -m 0644 "${build_dir}/antiddos-challenge.service" "$challenge_unit_path"
    install -d -o root -g root -m 0755 "$soft_block_dropin_dir"
    install -o root -g root -m 0644 "${build_dir}/antiddos-soft-block.conf" "$soft_block_dropin_path"
fi

if [[ ! -e "$config_path" ]]; then
    install -o root -g "$service_group" -m 0640 "${build_dir}/config.example.json" "$config_path"
    echo "      Created ${config_path} from the example"
else
    chown root:"$service_group" "$config_path"
    chmod 0640 "$config_path"
    echo "      Preserved existing ${config_path}"
fi
install -o root -g root -m 0644 "${build_dir}/config.security.example.json" "${config_dir}/config.security.example.json"

if ((install_web)); then
    if ! getent group "$web_group" >/dev/null; then
        groupadd --system "$web_group"
    fi
    if ! getent passwd "$web_user" >/dev/null; then
        useradd --system --gid "$web_group" --home-dir /var/lib/antiddos-web --shell /usr/sbin/nologin "$web_user"
    fi
    usermod -a -G "$service_group" "$web_user"
    if ((install_soft_block)); then
        usermod -a -G "$challenge_read_group" "$web_user"
    fi
    install -d -o "$web_user" -g "$web_group" -m 0700 "$web_state_dir"
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

if ((install_web)); then
    install -o root -g root -m 0644 "${build_dir}/antiddos-web.service" /etc/systemd/system/antiddos-web.service
    install -d -o "$web_user" -g "$web_group" -m 0700 /var/lib/antiddos-web
    # Only the daemon may atomically replace the config. The web process can
    # request validated whitelist edits through /run/antiddos/web.sock.
    chown "$service_user":root "$config_dir"
    chmod 0750 "$config_dir"
    chown "$service_user":"$service_group" "$config_path"
    chmod 0600 "$config_path"
    echo "      Web enabled: rule and whitelist edits are isolated behind the daemon API"
fi

echo "[5/7] Reloading systemd"
systemctl daemon-reload

if ((migrate_from_nftables)); then
    "$binary_path" soft-block migrate-from-nftables \
        --config "$config_path" \
        --confirm-daemon-stopped
fi

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

if ((install_soft_block)); then
    systemctl enable "$challenge_service_name" >/dev/null
    if ! systemctl restart "$challenge_service_name"; then
        systemctl status "$challenge_service_name" --no-pager --full || true
        journalctl -u "$challenge_service_name" -n 30 --no-pager || true
        fail "challenge checker failed to start"
    fi
    systemctl is-active --quiet "$challenge_service_name" || fail "challenge checker is not active"
fi

if ((install_web)); then
    existing_users="$(runuser -u "$web_user" -- "$binary_path" user list)" || fail "cannot read web accounts"
    if [[ -z "$existing_users" ]]; then
        if [[ -t 0 && -t 1 ]]; then
            echo "Create the first web administrator: admin"
            echo "Set a private password when prompted; enter it twice."
            runuser -u "$web_user" -- "$binary_path" user add --role admin admin || fail "could not create web administrator"
            web_admin_created=1
        else
            echo "No web administrator exists. Create one with:"
            echo "  sudo -u ${web_user} ${binary_path} user add --role admin admin"
            web_admin_missing=1
        fi
    else
        echo "Preserved existing web users: ${web_users_db}"
    fi
    systemctl enable antiddos-web.service >/dev/null
    systemctl restart antiddos-web.service
    systemctl is-active --quiet antiddos-web.service || fail "web service failed; check journalctl -u antiddos-web"
    echo
    echo "Web interface"
    echo "  URL:   http://127.0.0.1:8080"
    echo "  Users: ${web_users_db}"
    if ((web_admin_created)); then
        echo "  Login: admin (the password you just set)"
    elif ((web_admin_missing)); then
        echo "  Create the first admin before signing in (command shown above)."
    else
        echo "  Use an existing account; list users with:"
        echo "    sudo -u ${web_user} ${binary_path} user list"
    fi
    echo "  On this server: open the URL above in a browser."
    echo "  From another computer, open an SSH tunnel in a separate terminal:"
    echo "    ssh -N -L 8080:127.0.0.1:8080 <ssh-user>@<server-address>"
    echo "  Keep it open, then visit http://127.0.0.1:8080 on your computer."
    echo "  In Rules and filters, add each log source by its absolute path and format."
    echo "  Save, then apply the configuration with:"
    echo "    sudo systemctl restart ${service_name}"
fi

echo
echo "[7/7] Installation verified"
echo "AntiDDoS"
echo "  Service:  sudo systemctl status ${service_name}"
echo "  Monitor:  sudo -u ${service_user} ${binary_path} monitor"
echo "  Config:   ${config_path}"
echo "  Database: ${state_dir}/antiddos.sqlite"
echo "  Restart:  sudo systemctl restart ${service_name}"
if ((install_soft_block)); then
    echo "  Challenge: sudo systemctl status ${challenge_service_name}"
    echo "  Keys:      ${challenge_keys_path} (preserved on upgrades)"
    echo "  Nginx:     add its worker account to ${challenge_group}, then restart Nginx before enabling generated includes"
fi
