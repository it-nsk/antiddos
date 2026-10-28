#!/usr/bin/env bash
set -Eeuo pipefail

duration=${1:-14400}
speed=${2:-1.0}
[[ "$duration" =~ ^[0-9]+$ && "$duration" -gt 0 ]] || { echo 'duration must be positive seconds' >&2; exit 2; }
awk -v speed="$speed" 'BEGIN { exit !(speed > 0) }' || { echo 'speed must be positive' >&2; exit 2; }

repo=$(cd "$(dirname "$0")/.." && pwd)
src=/home/semyon/Downloads/bgtweb_logs/bgtweb_logs
for file in nginx/bgtweb_access.log.1 nginx/bgtweb_all_access.log.1 nginx/error.log.1 system/auth.log system/kern.log.1; do
  [[ -r "$src/$file" ]] || { echo "missing real source: $src/$file" >&2; exit 1; }
done

out=$(mktemp -d /tmp/antiddos-log-study-XXXXXX)
mkdir -p "$out/replay"
chmod 0700 "$out" "$out/replay"
config="$out/config.json"
touch "$out/replay/web_access.log" "$out/replay/nginx_all_access.log" "$out/replay/nginx_error.log" "$out/replay/ssh_auth.log" "$out/replay/netfilter.log"
jq --arg db "$out/antiddos.sqlite" \
   --arg a "$out/replay/web_access.log" \
   --arg all "$out/replay/nginx_all_access.log" \
   --arg e "$out/replay/nginx_error.log" \
   --arg s "$out/replay/ssh_auth.log" \
   --arg n "$out/replay/netfilter.log" \
  '.database_path=$db | .start_position="end" | .block_mode="dry_run" |
   .log_sources.web_access.path=$a |
   .log_sources.nginx_all_access={path:$all,format:"nginx_combined"} |
   .engine.rules=(.engine.rules + [.engine.rules[] | select(.log_source=="web_access") | . as $r | $r + {"id":($r.id+"-all"),"log_source":"nginx_all_access"}]) |
   .engine.rules |= map(.enabled=true) |
   .log_sources.nginx_error.path=$e |
   .log_sources.ssh_auth.path=$s |
   .log_sources.netfilter.path=$n' \
  "$repo/deploy/config.security.example.json" >"$config"
jq -e . "$config" >/dev/null

daemon_pid=''
sampler_pid=''
cleanup() {
  status=$?
  trap - EXIT INT TERM
  [[ -z "$sampler_pid" ]] || { kill "$sampler_pid" 2>/dev/null || true; wait "$sampler_pid" 2>/dev/null || true; }
  [[ -z "$daemon_pid" ]] || { kill -TERM "$daemon_pid" 2>/dev/null || true; wait "$daemon_pid" 2>/dev/null || true; }
  {
    echo "exit=$status"
    echo "requested_duration_seconds=$duration"
    echo "speed=$speed"
    echo "output=$out"
    echo
    echo 'replayed_lines:'
    for f in "$out"/replay/*.log; do [[ -e "$f" ]] && printf '%s=%s\n' "$(basename "$f")" "$(wc -l <"$f")"; done
    echo
    echo 'detections_by_rule:'
    grep -o 'rule=[^ ]*' "$out/daemon.log" 2>/dev/null | sort | uniq -c || true
    echo
    echo 'daemon_shutdown:'
    grep 'service stopped' "$out/daemon.log" 2>/dev/null | tail -1 || true
  } >"$out/summary.txt"
  echo "Isolated replay finished (exit=$status). Report: $out/summary.txt"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "Starting isolated detection-only replay for ${duration}s at ${speed}x. Output: $out"
echo "System config, firewall, Nginx and running AntiDDoS services are untouched."
"$repo/antiddos" run --config "$config" >"$out/daemon.log" 2>&1 &
daemon_pid=$!
for _ in $(seq 1 100); do
  grep -q 'service started' "$out/daemon.log" && break
  kill -0 "$daemon_pid" 2>/dev/null || { cat "$out/daemon.log"; exit 1; }
  sleep 0.1
done
grep -q 'service started' "$out/daemon.log" || { echo 'daemon failed to start; see daemon.log' >&2; exit 1; }
for source in web_access nginx_all_access nginx_error ssh_auth netfilter; do
  for _ in $(seq 1 50); do
    grep -q "log file opened.*source=$source " "$out/daemon.log" && break
    kill -0 "$daemon_pid" 2>/dev/null || { cat "$out/daemon.log"; exit 1; }
    sleep 0.1
  done
  grep -q "log file opened.*source=$source " "$out/daemon.log" || { echo "source did not open: $source" >&2; exit 1; }
done

(
  while kill -0 "$daemon_pid" 2>/dev/null; do
    printf '\n[%s]\n' "$(date --iso-8601=seconds)"
    "$repo/antiddos" monitor --once --config "$config" --limit 1000 2>&1 || true
    sleep 30
  done
) >"$out/monitor.log" 2>&1 &
sampler_pid=$!

echo "Sources: access/error rotated logs, current SSH auth and rotated kernel log; timeline speed=${speed}x."
python3 "$repo/scripts/log-study-replay.py" --speed "$speed" --duration "$duration" --output "$out/replay" \
  --source web_access access "$src/nginx/bgtweb_access.log.1" \
  --source nginx_all_access access "$src/nginx/bgtweb_all_access.log.1" \
  --source nginx_error error "$src/nginx/error.log.1" \
  --source ssh_auth syslog "$src/system/auth.log" \
  --source netfilter syslog "$src/system/kern.log.1"
"$repo/antiddos" monitor --once --config "$config" --limit 1000 >"$out/final-monitor.txt" 2>&1 || true
echo "$out" >"$repo/.log-study-replay-current"
