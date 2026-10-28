#!/usr/bin/env bash
set -Eeuo pipefail

duration=3600
speed=1.0
while (($#)); do
  case "$1" in
    --speed) speed=$2; shift 2 ;;
    --dry-run) shift ;;
    *) duration=$1; shift ;;
  esac
done
((EUID == 0)) || { echo 'run through sudo'; exit 1; }
[[ "$duration" =~ ^[0-9]+$ && "$duration" -gt 0 ]] || { echo 'duration must be a positive number of seconds'; exit 1; }
command -v jq >/dev/null && command -v flock >/dev/null || { echo 'jq and flock are required'; exit 1; }

config=/etc/antiddos/config.json
stamp=$(date +%Y%m%d-%H%M%S)
out=/var/log/antiddos/log-study-replay-$stamp
src=/home/semyon/Downloads/bgtweb_logs/bgtweb_logs
exec 9>/run/antiddos-log-study-replay.lock
flock -n 9 || { echo 'another log-study replay is running'; exit 1; }
for f in nginx/bgtweb_access.log.1 nginx/bgtweb_all_access.log.1 nginx/error.log.1 system/auth.log.1 system/kern.log.1; do
  [[ -r "$src/$f" ]] || { echo "missing real log source: $src/$f"; exit 1; }
done

mkdir -p "$out"/replay
chown -R antiddos:antiddos "$out"
chmod 0750 "$out" "$out/replay"
backup=$out/config.before.json
cp -a "$config" "$backup"
sampler=''
soak_hash=''
started='not-started'

cleanup() {
  local status=$? current_hash
  trap - EXIT INT TERM
  if [[ -n "$sampler" ]]; then
    kill "$sampler" 2>/dev/null || true
    wait "$sampler" 2>/dev/null || true
  fi
  if [[ -n "$soak_hash" && -f "$config" ]]; then
    current_hash=$(sha256sum "$config" | awk '{print $1}')
    if [[ "$current_hash" == "$soak_hash" ]]; then
      cp -a "$backup" "$config.restore.$$" && mv -f "$config.restore.$$" "$config"
      systemctl restart antiddos.service >/dev/null 2>&1 || true
      echo 'Original config restored.' >>"$out/summary.txt"
    else
      echo "Config changed during replay; kept the new config. Backup: $backup" >>"$out/summary.txt"
    fi
  fi
  {
    echo "started=$started"
    echo "finished=$(date --iso-8601=seconds)"
    echo "requested_duration_seconds=$duration"
    echo "speed=$speed"
    echo "output=$out"
    echo
    echo 'replayed_lines:'
    for f in "$out"/replay/*.log; do
      [[ -e "$f" ]] && printf '%s=%s\n' "$(basename "$f")" "$(wc -l <"$f")"
    done
    echo
    echo 'detections_by_rule:'
    if [[ "$started" != not-started ]]; then
      journalctl -u antiddos --since "$started" --no-pager 2>/dev/null \
        | grep 'request pattern detected' \
        | sed -nE 's/.*rule=([^ ]+).*group_value=([^ ]+).*count=([^ ]+).*/rule=\1 source_ip=\2 count=\3/p' \
        | sort | uniq -c || true
    fi
    echo
    echo 'service:'
    systemctl is-active antiddos.service 2>/dev/null || true
    echo
    echo 'final_monitor:'
    cat "$out/final-monitor.txt" 2>/dev/null || true
  } >>"$out/summary.txt"
  echo "Replay finished (exit=$status). Report: $out/summary.txt"
  exit "$status"
}
trap cleanup EXIT INT TERM

mkdir -p "$out/replay"
touch "$out/replay/nginx_bgt_access.log" "$out/replay/nginx_all_access.log" "$out/replay/nginx_error.log" "$out/replay/ssh_auth.log" "$out/replay/netfilter.log"
chown antiddos:antiddos "$out/replay"/*.log
chmod 0640 "$out/replay"/*.log
jq --arg a "$out/replay/nginx_bgt_access.log" \
   --arg all "$out/replay/nginx_all_access.log" \
   --arg e "$out/replay/nginx_error.log" \
   --arg s "$out/replay/ssh_auth.log" \
   --arg n "$out/replay/netfilter.log" \
  '.block_mode="dry_run" |
   .log_sources.nginx_bgt_access.path=$a |
   .log_sources.nginx_all_access.path=$all |
   .log_sources.nginx_error={path:$e,format:"nginx_error"} |
   .log_sources.ssh_auth={path:$s,format:"syslog_sshd"} |
   .log_sources.netfilter={path:$n,format:"netfilter_log"}' \
  "$config" >"$out/config.json"
jq -e . "$out/config.json" >/dev/null
install -o root -g root -m 0644 "$out/config.json" "$config"
soak_hash=$(sha256sum "$config" | awk '{print $1}')
systemctl restart antiddos.service
systemctl is-active --quiet antiddos.service
started=$(date --iso-8601=seconds)
for source in nginx_bgt_access nginx_all_access nginx_error ssh_auth netfilter; do
  for _ in $(seq 1 50); do
    journalctl -u antiddos --since "$started" --no-pager 2>/dev/null | grep -q "log file opened.*source=$source " && break
    sleep 0.1
  done
  journalctl -u antiddos --since "$started" --no-pager 2>/dev/null | grep -q "log file opened.*source=$source " || { echo "source did not open: $source" >&2; exit 1; }
done
{
  echo "Replay speed=$speed duration=${duration}s; detection-only mode"
  echo "Sources: $src/nginx/bgtweb_access.log.1, $src/nginx/bgtweb_all_access.log.1, $src/nginx/error.log.1, $src/system/auth.log.1, $src/system/kern.log.1"
} | tee "$out/README.txt"

(
  while :; do
    printf '\n[%s]\n' "$(date --iso-8601=seconds)"
    /usr/local/bin/antiddos monitor --once --limit 1000 2>&1 || true
    sleep 30
  done
) >"$out/monitor.log" 2>&1 &
sampler=$!

python3 scripts/log-study-replay.py --speed "$speed" --duration "$duration" --output "$out/replay" \
  --source nginx_bgt_access access "$src/nginx/bgtweb_access.log.1" \
  --source nginx_all_access access "$src/nginx/bgtweb_all_access.log.1" \
  --source nginx_error error "$src/nginx/error.log.1" \
  --source ssh_auth syslog "$src/system/auth.log.1" \
  --source netfilter syslog "$src/system/kern.log.1"
"/usr/local/bin/antiddos" monitor --once --limit 1000 >"$out/final-monitor.txt" 2>&1 || true
