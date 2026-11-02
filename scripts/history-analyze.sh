#!/usr/bin/env bash
set -Eeuo pipefail

readonly default_config=/etc/antiddos/config.json
readonly default_binary=/usr/local/bin/antiddos
readonly default_output_root=/var/lib/antiddos-history
readonly default_users_db=/var/lib/antiddos-web/users.sqlite
readonly default_daemon_user=antiddos
readonly default_web_user=antiddos-web
readonly default_unit_prefix=antiddos-history

config=$default_config
binary=$default_binary
output_root=$default_output_root
users_db=$default_users_db
daemon_user=$default_daemon_user
web_user=$default_web_user
unit_prefix=$default_unit_prefix
nginx_log=''
ssh_log=''
nginx_source=''
ssh_source=''
web_port=8081
start_web=1

usage() {
  cat <<'EOF'
Usage: sudo history-analyze.sh [OPTIONS]

Build a separate dry-run database from current and rotated logs, then expose it
through a second localhost UI. The installed live daemon and its database are
not stopped or modified.

Options:
  --nginx PATH          current Nginx access log (normally found automatically)
  --ssh PATH            current OpenSSH auth log (normally found automatically)
  --web-port PORT       historical UI loopback port (default: 8081)
  --config PATH         live config whose sources and rules are copied
  --nginx-source ID     source ID in config (normally not needed)
  --ssh-source ID       source ID in config (normally not needed)
  --output-root PATH    directory that retains timestamped analysis runs
  --binary PATH         antiddos binary
  --users-db PATH       reuse this UI users database
  --daemon-user USER    analysis process user (default: antiddos)
  --web-user USER       historical UI process user (default: antiddos-web)
  --unit-prefix NAME    transient systemd unit prefix
  --no-web              analyze only; do not use systemd or start a UI
  -h, --help            show this help

Only standard numeric rotations are included: .N.gz, .N and the current file.
Manual .copy files are intentionally ignored to avoid duplicate events.
EOF
}

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

require_value() {
  (($# >= 2)) || fail "$1 requires a value"
}

while (($# > 0)); do
  case "$1" in
    --nginx) require_value "$@"; nginx_log=$2; shift 2 ;;
    --ssh) require_value "$@"; ssh_log=$2; shift 2 ;;
    --web-port) require_value "$@"; web_port=$2; shift 2 ;;
    --config) require_value "$@"; config=$2; shift 2 ;;
    --nginx-source) require_value "$@"; nginx_source=$2; shift 2 ;;
    --ssh-source) require_value "$@"; ssh_source=$2; shift 2 ;;
    --output-root) require_value "$@"; output_root=$2; shift 2 ;;
    --binary) require_value "$@"; binary=$2; shift 2 ;;
    --users-db) require_value "$@"; users_db=$2; shift 2 ;;
    --daemon-user) require_value "$@"; daemon_user=$2; shift 2 ;;
    --web-user) require_value "$@"; web_user=$2; shift 2 ;;
    --unit-prefix) require_value "$@"; unit_prefix=$2; shift 2 ;;
    --no-web) start_web=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown option: $1" ;;
  esac
done

for path in "$config" "$binary"; do
  [[ "$path" == /* ]] || fail "path must be absolute: $path"
done
[[ "$output_root" == /* ]] || fail "--output-root must be absolute"
[[ -f "$config" && ! -L "$config" ]] || fail "config is not a regular file: $config"
[[ -x "$binary" && ! -d "$binary" ]] || fail "binary is not executable: $binary"
[[ "$web_port" =~ ^[0-9]+$ ]] && ((web_port >= 1 && web_port <= 65535)) || fail "--web-port must be 1-65535"
[[ "$unit_prefix" =~ ^[A-Za-z0-9_.@-]+$ ]] || fail "--unit-prefix contains unsupported characters"

for command in jq gzip sort runuser date install wc getent nice ionice stat; do
  command -v "$command" >/dev/null || fail "required command not found: $command"
done
if ((start_web)); then
  ((EUID == 0)) || fail "run with sudo when starting the historical UI"
  for command in systemctl systemd-run; do
    command -v "$command" >/dev/null || fail "required command not found: $command"
  done
  [[ -f "$users_db" ]] || fail "UI users database does not exist: $users_db"
fi
[[ ! -L "$output_root" ]] || fail "--output-root must not be a symlink"
if [[ $(id -un) != "$daemon_user" ]]; then
  getent passwd "$daemon_user" >/dev/null || fail "unknown daemon user: $daemon_user"
fi

source_for_path() {
  local path=$1 format_pattern=$2
  jq -r --arg path "$path" --arg format_pattern "$format_pattern" '
    [(.log_sources // {}) | to_entries[] |
      select(.value.path == $path and (.value.format | test($format_pattern))) |
      .key] |
    if length == 1 then .[0]
    elif length == 0 then empty
    else error("multiple matching sources")
    end
  ' "$config"
}

unique_enabled_source() {
  local format_pattern=$1
  jq -r --arg format_pattern "$format_pattern" '
    .engine.rules as $rules |
    [(.log_sources // {}) | to_entries[] |
      .key as $id |
      select(.value.format | test($format_pattern)) |
      select(any($rules[]; (.enabled // true) and .log_source == $id)) |
      .key] |
    if length == 1 then .[0]
    elif length == 0 then empty
    else error("multiple enabled matching sources")
    end
  ' "$config"
}

discover_nginx_log() {
  local candidate rotation size
  local -a candidates=()
  local best='' best_size=-1

  shopt -s nullglob
  for candidate in /var/log/nginx/*access*.log; do
    [[ -f "$candidate" ]] || continue
    candidates+=("$candidate")
  done
  shopt -u nullglob

  # Prefer the site's busiest access-log family over a broader "all_access"
  # duplicate. Include rotations in the score because the current file may
  # have just been rotated and still be small.
  for candidate in "${candidates[@]}"; do
    [[ ${candidate##*/} == *all_access* ]] && continue
    size=$(stat -c %s -- "$candidate")
    shopt -s nullglob
    for rotation in "$candidate".[0-9]*; do
      size=$((size + $(stat -c %s -- "$rotation")))
    done
    shopt -u nullglob
    if ((size > best_size)); then
      best=$candidate
      best_size=$size
    fi
  done
  if [[ -n "$best" ]]; then
    printf '%s\n' "$best"
  elif ((${#candidates[@]})); then
    printf '%s\n' "${candidates[0]}"
  fi
}

discover_ssh_log() {
  local candidate
  for candidate in /var/log/auth.log /var/log/secure; do
    if [[ -f "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  done
}

path_for_source() {
  local source=$1 format_pattern=$2
  jq -er --arg source "$source" --arg format_pattern "$format_pattern" '
    .log_sources[$source] |
    select(.format | test($format_pattern)) |
    .path
  ' "$config"
}

resolve_source() {
  local label=$1 format_pattern=$2 requested_path=$3 requested_source=$4 fallback_source=$5
  local source=$requested_source path=$requested_path

  if [[ -n "$source" && -z "$path" ]]; then
    path=$(path_for_source "$source" "$format_pattern") || fail "source $source does not have the expected $label format"
  elif [[ -z "$source" && -n "$path" ]]; then
    source=$(source_for_path "$path" "$format_pattern" 2>/dev/null || true)
  elif [[ -z "$source" ]]; then
    source=$(unique_enabled_source "$format_pattern" 2>/dev/null || true)
    if [[ -n "$source" ]]; then
      path=$(path_for_source "$source" "$format_pattern") || fail "source $source does not have the expected $label format"
    fi
  fi

  if [[ -z "$path" ]]; then
    if [[ "$label" == nginx ]]; then
      path=$(discover_nginx_log)
    else
      path=$(discover_ssh_log)
    fi
  fi
  [[ -n "$path" ]] || fail "cannot find the $label log; pass --$label PATH"

  if [[ -z "$source" ]]; then
    source=$(source_for_path "$path" "$format_pattern" 2>/dev/null || true)
  fi
  [[ -n "$source" ]] || source=$fallback_source
  printf '%s\t%s\n' "$source" "$path"
}

resolved=$(resolve_source nginx '^nginx_(combined|custom)$' "$nginx_log" "$nginx_source" history_nginx)
nginx_source=${resolved%%$'\t'*}
nginx_log=${resolved#*$'\t'}
resolved=$(resolve_source ssh '^syslog_sshd$' "$ssh_log" "$ssh_source" history_ssh)
ssh_source=${resolved%%$'\t'*}
ssh_log=${resolved#*$'\t'}

for path in "$nginx_log" "$ssh_log"; do
  [[ "$path" == /* ]] || fail "log path must be absolute: $path"
  [[ -f "$path" ]] || fail "log is not a regular file: $path"
done
[[ "$nginx_source" != "$ssh_source" ]] || fail "Nginx and SSH sources must be different"

if ((start_web)); then
  getent passwd "$web_user" >/dev/null || fail "unknown web user: $web_user"
else
  if [[ $(id -un) != "$daemon_user" ]] && ((EUID != 0)); then
    fail "--no-web must run as $daemon_user or root when --daemon-user differs"
  fi
fi

timestamp=$(date +%Y%m%d-%H%M%S)
run_dir="$output_root/history-$timestamp"
logs_dir="$run_dir/logs"
database="$run_dir/history.sqlite"
viewer_config="$run_dir/config-viewer.json"
web_socket="/run/$unit_prefix/web.sock"
daemon_unit="$unit_prefix-daemon"
web_unit="$unit_prefix-web"

mkdir_owned() {
  local path=$1 mode=$2
  if ((EUID == 0)); then
    install -d -o "$daemon_user" -g "$daemon_user" -m "$mode" "$path"
  else
    install -d -m "$mode" "$path"
  fi
}

mkdir_owned "$output_root" 0750
[[ ! -e "$run_dir" ]] || fail "analysis directory already exists: $run_dir; wait one second and retry"
mkdir_owned "$run_dir" 0700
mkdir_owned "$logs_dir" 0700

merge_rotations() {
  local base=$1 output=$2 candidate suffix number entry path
  local -a numbered=()
  shopt -s nullglob
  for candidate in "$base".[0-9]*; do
    suffix=${candidate#"$base".}
    if [[ "$suffix" =~ ^([0-9]+)(\.gz)?$ ]]; then
      number=${BASH_REMATCH[1]}
      numbered+=("$(printf '%010d\t%s' "$number" "$candidate")")
    fi
  done
  shopt -u nullglob

  : >"$output"
  if ((${#numbered[@]})); then
    while IFS= read -r entry; do
      path=${entry#*$'\t'}
      if [[ "$path" == *.gz ]]; then
        gzip -cd -- "$path" >>"$output"
      else
        command cat -- "$path" >>"$output"
      fi
    done < <(printf '%s\n' "${numbered[@]}" | sort -rn -k1,1)
  fi
  command cat -- "$base" >>"$output"
  [[ -s "$output" ]] || fail "merged log is empty: $output"
}

echo "[1/5] Collecting Nginx rotations from $nginx_log"
merge_rotations "$nginx_log" "$logs_dir/nginx-access.log"
echo "[2/5] Collecting SSH rotations from $ssh_log"
merge_rotations "$ssh_log" "$logs_dir/ssh-auth.log"

base_config="$run_dir/config.json"
web_config="$run_dir/config-web.json"
ssh_config="$run_dir/config-ssh.json"

jq \
  --arg db "$database" \
  --arg web_id "$nginx_source" \
  --arg ssh_id "$ssh_source" \
  --arg web_path "$logs_dir/nginx-access.log" \
  --arg ssh_path "$logs_dir/ssh-auth.log" '
    del(.log_file, .soft_block) |
    .database_path = $db |
    .start_position = "beginning" |
    .block_mode = "dry_run" |
    .block_tcp_ports = [] |
    .log_sources = ((.log_sources // {}) | with_entries(select(.key == $web_id or .key == $ssh_id))) |
    .log_sources[$web_id] = ((.log_sources[$web_id] // {}) + {path: $web_path, format: (.log_sources[$web_id].format // "nginx_combined")}) |
    .log_sources[$ssh_id] = ((.log_sources[$ssh_id] // {}) + {path: $ssh_path, format: "syslog_sshd"}) |
    .engine.rules = (.engine.rules // []) |
    .engine.rules |= map(
      select((.enabled // true) and (.log_source == $web_id or .log_source == $ssh_id)) |
      .action = "dry_run"
    ) |
    if any(.engine.rules[]; .log_source == $web_id and .type == "rate" and .path_regex == ".*") then . else
      .engine.rules += [
        {id:"history-web-ddos",enabled:true,type:"rate",action:"dry_run",log_source:$web_id,path_regex:".*",window:"1s",threshold:50,group_by:"ip",ignore_ips:[]}
      ]
    end |
    if any(.engine.rules[]; .log_source == $web_id and .type == "signature" and ((.query_regex // "") != "")) then . else
      .engine.rules += [
        {id:"history-web-sqli",enabled:true,type:"signature",action:"dry_run",log_source:$web_id,path_regex:".*",query_regex:"(?i)(?:union(?:%20|\\+|\\s)+(?:all(?:%20|\\+|\\s)+)?select|(?:%27|%2527|\u0027)(?:%20|\\+|\\s)+(?:and|or)(?:%20|\\+|\\s)+[0-9]+(?:=|%3d)[0-9]+|extractvalue(?:%28|\\()|sleep(?:%28|\\()|benchmark(?:%28|\\())",window:"1s",threshold:1,group_by:"ip",ignore_ips:[]}
      ]
    end |
    if any(.engine.rules[]; .log_source == $ssh_id and .path_regex == "^/ssh/failed$") then . else
      .engine.rules += [
        {id:"history-ssh-bruteforce",enabled:true,type:"rate",action:"dry_run",log_source:$ssh_id,path_regex:"^/ssh/failed$",window:"60s",threshold:5,group_by:"ip",ignore_ips:[]}
      ]
    end
  ' "$config" >"$base_config"

jq --arg source "$nginx_source" '
  .log_sources |= with_entries(select(.key == $source)) |
  .engine.rules |= map(select(.log_source == $source))
' "$base_config" >"$web_config"
jq --arg source "$ssh_source" '
  .log_sources |= with_entries(select(.key == $source)) |
  .engine.rules |= map(select(.log_source == $source))
' "$base_config" >"$ssh_config"
jq '.start_position = "end"' "$base_config" >"$viewer_config"

for generated in "$base_config" "$web_config" "$ssh_config" "$viewer_config"; do
  jq -e . "$generated" >/dev/null
done

if ((EUID == 0)); then
  chown -R "$daemon_user:$daemon_user" "$run_dir"
fi
chmod 0600 "$run_dir"/config*.json "$logs_dir"/*.log

run_analyzer() {
  local selected_config=$1 output=$2
  if [[ $(id -un) == "$daemon_user" ]]; then
    ionice -c 2 -n 7 nice -n 10 \
      "$binary" run --config "$selected_config" --from-start --once >"$output" 2>&1
  else
    runuser -u "$daemon_user" -- ionice -c 2 -n 7 nice -n 10 \
      "$binary" run --config "$selected_config" --from-start --once >"$output" 2>&1
  fi
}

echo "[3/5] Analyzing Nginx history without real-time delays"
if ! run_analyzer "$web_config" "$run_dir/nginx-analysis.log"; then
  tail -50 "$run_dir/nginx-analysis.log" >&2 || true
  fail "Nginx historical analysis failed"
fi
echo "[4/5] Analyzing SSH history without real-time delays"
if ! run_analyzer "$ssh_config" "$run_dir/ssh-analysis.log"; then
  tail -50 "$run_dir/ssh-analysis.log" >&2 || true
  fail "SSH historical analysis failed"
fi
[[ -s "$database" ]] || fail "historical database was not created"

[[ ! -e "$output_root/current" || -L "$output_root/current" ]] || fail "$output_root/current exists and is not a symlink"
ln -sfn "$run_dir" "$output_root/current"

if ((!start_web)); then
  echo "[5/5] Analysis complete (--no-web)"
  echo "Run directory: $run_dir"
  echo "Database: $database"
  echo "Nginx lines: $(wc -l <"$logs_dir/nginx-access.log")"
  echo "SSH lines: $(wc -l <"$logs_dir/ssh-auth.log")"
  exit 0
fi

echo "[5/5] Starting isolated daemon and UI on 127.0.0.1:$web_port"
systemctl stop "$web_unit.service" "$daemon_unit.service" >/dev/null 2>&1 || true
systemctl reset-failed "$web_unit.service" "$daemon_unit.service" >/dev/null 2>&1 || true
for _ in $(seq 1 20); do
  web_load=$(systemctl show -p LoadState --value "$web_unit.service" 2>/dev/null || true)
  daemon_load=$(systemctl show -p LoadState --value "$daemon_unit.service" 2>/dev/null || true)
  if [[ -z "$web_load" || "$web_load" == not-found ]] && [[ -z "$daemon_load" || "$daemon_load" == not-found ]]; then
    break
  fi
  sleep 0.1
done

install -d -o "$daemon_user" -g "$daemon_user" -m 0770 "/run/$unit_prefix"

if ! systemd-run --quiet --collect --service-type=exec \
  --unit="$daemon_unit" \
  --property="User=$daemon_user" \
  --property="Group=$daemon_user" \
  --property=Nice=10 \
  --property=MemoryMax=512M \
  "$binary" run --config "$viewer_config" --web-socket "$web_socket"; then
  fail "could not start historical daemon"
fi

for _ in $(seq 1 100); do
  [[ ! -S "$web_socket" ]] || break
  if ! systemctl is-active --quiet "$daemon_unit.service"; then
    fail "historical daemon stopped; inspect journalctl -u $daemon_unit"
  fi
  sleep 0.1
done
if [[ ! -S "$web_socket" ]]; then
  systemctl stop "$daemon_unit.service" >/dev/null 2>&1 || true
  fail "historical daemon did not create $web_socket"
fi

if ! systemd-run --quiet --collect --service-type=exec \
  --unit="$web_unit" \
  --property="User=$web_user" \
  --property="Group=$web_user" \
  --property="SupplementaryGroups=$daemon_user" \
  "$binary" web \
    --daemon-socket "$web_socket" \
    --users-db "$users_db" \
    --listen "127.0.0.1:$web_port" \
    --origin "http://127.0.0.1:$web_port"; then
  systemctl stop "$daemon_unit.service" >/dev/null 2>&1 || true
  fail "could not start historical UI"
fi

for _ in $(seq 1 50); do
  systemctl is-active --quiet "$web_unit.service" && break
  sleep 0.1
done
if ! systemctl is-active --quiet "$web_unit.service"; then
  systemctl stop "$daemon_unit.service" >/dev/null 2>&1 || true
  fail "historical UI stopped; inspect journalctl -u $web_unit"
fi

echo
echo "Historical analysis is ready."
echo "Run directory: $run_dir"
echo "Historical UI: http://127.0.0.1:$web_port"
echo "Live antiddos services were not stopped or modified."
echo "In the UI, clear 'Сейчас' and select the original log dates."
echo "Stop only history: systemctl stop $web_unit $daemon_unit"
