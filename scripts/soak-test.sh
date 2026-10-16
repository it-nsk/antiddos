#!/usr/bin/env bash
set -Eeuo pipefail

# Six-hour nftables soak test against the local Nginx vhost. The test requests
# use 127.0.0.1, so the generated block affects loopback traffic only.

duration_seconds="${1:-21600}"
config_file=/etc/antiddos/config.json
binary=/usr/local/bin/antiddos
service=antiddos
test_ip=127.0.0.1
burst_interval=70
request_count=8
request_gap=0.2
connect_timeout=3

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[[ "$EUID" -eq 0 ]] || fail "run with sudo: sudo bash scripts/soak-test.sh"
[[ "$duration_seconds" =~ ^[0-9]+$ ]] && (( duration_seconds > 0 )) || fail "duration must be a positive number of seconds"
command -v jq >/dev/null || fail "jq is required"
command -v curl >/dev/null || fail "curl is required"
command -v nft >/dev/null || fail "nft is required"
command -v journalctl >/dev/null || fail "journalctl is required"
[[ -x "$binary" ]] || fail "binary not found: $binary"
[[ -r "$config_file" ]] || fail "cannot read $config_file"
systemctl is-active --quiet "$service" || fail "antiddos service is not active"

jq -e '
  .block_mode == "nftables" and
  .block_duration == "1m" and
  (.block_tcp_ports | index(443) != null) and
  (.engine.ignore_ips == []) and
  any(.engine.rules[]; .id == "homepage" and .path_regex == "^/$" and .window == "5s" and .threshold == 5 and .group_by == "ip")
' "$config_file" >/dev/null || fail "expected nftables mode, 1m duration, port 443, empty whitelist, and homepage ip rule (5 requests / 5s)"

nft list table inet antiddos >/dev/null 2>&1 || fail "AntiDDoS nftables table is missing"
systemctl show "$service" -p MainPID --value | grep -Eq '^[1-9][0-9]*$' || fail "antiddos has no MainPID"

effective_log=$(jq -r '.log_file' "$config_file")
if [[ -r /etc/default/antiddos ]]; then
  log_override=$(sed -n 's/^[[:space:]]*ANTIDDOS_LOG_FILE[[:space:]]*=[[:space:]]*//p' /etc/default/antiddos | tail -n 1)
  log_override=${log_override#\"}
  log_override=${log_override%\"}
  [[ -z "$log_override" ]] || effective_log=$log_override
fi
[[ -r "$effective_log" ]] || fail "effective Nginx log is not readable: $effective_log"

started_epoch=$(date +%s)
started_iso=$(date --iso-8601=seconds)
ended_epoch=$((started_epoch + duration_seconds))
out_dir="/var/log/antiddos/soak-$(date +%Y%m%d-%H%M%S)"
install -d -m 0750 "$out_dir"
printf 'timestamp,pid,rss_kb,hwm_kb,cpu_percent\n' >"$out_dir/resources.csv"
printf 'timestamp,request,http_code\n' >"$out_dir/requests.csv"
jq '{log_file, block_mode, block_duration, block_tcp_ports, engine}' "$config_file" >"$out_dir/config-snapshot.json"

# Clear only a leftover localhost test lease so the first burst is observable.
"$binary" unblock "$test_ip" >"$out_dir/preflight-unblock.log" 2>&1 || fail "could not clear a previous localhost test block"
started_epoch=$(date +%s)
started_iso=$(date --iso-8601=seconds)
ended_epoch=$((started_epoch + duration_seconds))

journal_pid=
metrics_pid=
cleanup() {
  [[ -z "$journal_pid" ]] || kill "$journal_pid" 2>/dev/null || true
  [[ -z "$metrics_pid" ]] || kill "$metrics_pid" 2>/dev/null || true
  "$binary" unblock "$test_ip" >>"$out_dir/cleanup.log" 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

journalctl -u "$service" --since "$started_iso" --follow -o short-iso-precise >>"$out_dir/service.log" 2>&1 &
journal_pid=$!

(
  ticks_per_second=$(getconf CLK_TCK)
  previous_pid=
  previous_ticks=0
  previous_ns=0
  while (( $(date +%s) < ended_epoch )); do
    timestamp=$(date --iso-8601=seconds)
    now_ns=$(date +%s%N)
    pid=$(systemctl show "$service" -p MainPID --value 2>/dev/null || true)
    rss=0
    hwm=0
    cpu=0
    if [[ "$pid" =~ ^[1-9][0-9]*$ && -r "/proc/$pid/status" && -r "/proc/$pid/stat" ]]; then
      rss=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status")
      hwm=$(awk '/^VmHWM:/ {print $2}' "/proc/$pid/status")
      ticks=$(awk '{sub(/^.*\) /, ""); print $12 + $13}' "/proc/$pid/stat")
      if [[ "$pid" == "$previous_pid" && "$previous_ns" -gt 0 ]]; then
        cpu=$(awk -v now="$ticks" -v prev="$previous_ticks" -v hz="$ticks_per_second" -v dns="$((now_ns - previous_ns))" 'BEGIN { if (dns > 0) printf "%.2f", (now-prev)*100000000000/dns/hz; else print "0.00" }')
      fi
      previous_pid=$pid
      previous_ticks=$ticks
      previous_ns=$now_ns
    else
      previous_pid=
      previous_ticks=0
      previous_ns=0
    fi
    printf '%s,%s,%s,%s,%s\n' "$timestamp" "${pid:-0}" "${rss:-0}" "${hwm:-0}" "$cpu" >>"$out_dir/resources.csv"
    sleep 1
  done
) &
metrics_pid=$!

printf 'Test started: %s\nDuration: %s seconds\nLog: %s\nOutput: %s\n' "$started_iso" "$duration_seconds" "$effective_log" "$out_dir"
next_burst=$started_epoch
while (( $(date +%s) < ended_epoch )); do
  now=$(date +%s)
  if (( now >= next_burst )); then
    if (( now + request_count * connect_timeout + 5 > ended_epoch )); then
      break
    fi
    for ((i = 1; i <= request_count; i++)); do
      timestamp=$(date --iso-8601=seconds)
      code=$(curl --noproxy '*' -k -sS -o /dev/null -w '%{http_code}' \
        --connect-timeout "$connect_timeout" --max-time "$connect_timeout" \
        --resolve bgt.my:443:127.0.0.1 https://bgt.my/ 2>>"$out_dir/curl-errors.log" || true)
      printf '%s,%d,%s\n' "$timestamp" "$i" "${code:-000}" >>"$out_dir/requests.csv"
      sleep "$request_gap"
    done
    next_burst=$(($(date +%s) + burst_interval))
    printf 'Burst completed at %s\n' "$(date --iso-8601=seconds)"
  else
    sleep 1
  fi
done

wait "$metrics_pid" || true
metrics_pid=
sleep 2
"$binary" monitor --once --limit 1000 >"$out_dir/final-monitor.txt" 2>&1 || true

{
  printf 'AntiDDoS six-hour soak summary\nStarted: %s\nFinished: %s\nDuration seconds: %s\nNginx log: %s\n' "$started_iso" "$(date --iso-8601=seconds)" "$duration_seconds" "$effective_log"
  printf '\nResource samples (RSS and per-second process CPU):\n'
  awk -F, 'NR > 1 {n++; rss += $3; if ($3 > maxrss) maxrss = $3; if ($4 > maxhwm) maxhwm = $4; cpu += $5; if ($5 > maxcpu) maxcpu = $5} END {if (n) printf "samples=%d avg_rss_kb=%.0f peak_rss_kb=%d peak_hwm_kb=%d avg_cpu_percent=%.2f peak_cpu_percent=%.2f\n", n, rss/n, maxrss, maxhwm, cpu/n, maxcpu; else print "no resource samples"}' "$out_dir/resources.csv"
  printf '\nTest request results (HTTP code counts):\n'
  awk -F, 'NR > 1 {count[$3]++} END {for (code in count) printf "%s=%d\n", code, count[code]}' "$out_dir/requests.csv" | sort
  printf '\nDetection/block action counts from service journal:\n'
  awk '/request pattern detected/ {detections++} /block action result/ {actions++; for (i=1;i<=NF;i++) if ($i ~ /^status=/) {split($i,a,"="); status[a[2]]++}} END {printf "detections=%d action_results=%d\n", detections, actions; for (s in status) printf "%s=%d\n", s, status[s]}' "$out_dir/service.log" | sort
  printf '\nFiles: %s\n' "$out_dir"
} | tee "$out_dir/summary.txt"
