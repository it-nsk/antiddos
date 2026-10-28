#!/usr/bin/env bash
set -Eeuo pipefail

duration_seconds="${1:-3600}"
repo_root=$(cd "$(dirname "$0")/.." && pwd)
config_file=/etc/antiddos/config.json
binary=/usr/local/bin/antiddos
service=antiddos.service
checker_service=antiddos-challenge.service
web_service=antiddos-web.service
feed_socket=/run/antiddos-soft-feed/feed.sock
check_socket=/run/antiddos-challenge-check/check.sock
run_lock=/run/antiddos-hybrid-soak.lock

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[[ "$EUID" -eq 0 ]] || fail "run as root"
[[ "$duration_seconds" =~ ^[0-9]+$ ]] && ((duration_seconds > 0)) || fail "duration must be a positive number of seconds"
for command in jq curl systemctl flock sha256sum awk sed; do
    command -v "$command" >/dev/null || fail "$command is required"
done
[[ -x "$repo_root/scripts/install.sh" || -f "$repo_root/scripts/install.sh" ]] || fail "installer is missing"

exec 9>"$run_lock"
flock -n 9 || fail "another hybrid soak is already running"

started_stamp=$(date +%Y%m%d-%H%M%S)
started_iso=$(date --iso-8601=seconds)
out_dir="/var/log/antiddos/hybrid-soak-${started_stamp}"
install -d -o root -g antiddos -m 0750 "$out_dir"
access_log="$out_dir/access.log"
touch "$access_log"
chown antiddos:antiddos "$access_log"
chmod 0640 "$access_log"
printf '%s\n' "$out_dir" >/run/antiddos-hybrid-soak.current

config_backup="$out_dir/config.before.json"
cp -a "$config_file" "$config_backup"
test_ips="$out_dir/test-ips.txt"
resources="$out_dir/resources.csv"
events="$out_dir/events.csv"
printf 'timestamp,pid,rss_kb,hwm_kb,cpu_percent\n' >"$resources"
printf 'timestamp,type,ip,count\n' >"$events"

child_pids=()
configured=0
cleanup_started=0

stop_children() {
    local pid
    for pid in "${child_pids[@]:-}"; do
        [[ -n "$pid" ]] || continue
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${child_pids[@]:-}"; do
        [[ -n "$pid" ]] || continue
        wait "$pid" 2>/dev/null || true
    done
    child_pids=()
}

write_report() {
    "$binary" monitor --once --limit 1000 >"$out_dir/final-monitor.txt" 2>&1 || true
    systemctl show "$service" "$checker_service" "$web_service" -p ActiveState -p MainPID -p NRestarts >"$out_dir/final-services.txt" 2>&1 || true
    {
        printf 'Hybrid log soak\n'
        printf 'Started: %s\n' "$started_iso"
        printf 'Finished: %s\n' "$(date --iso-8601=seconds)"
        printf 'Requested duration seconds: %s\n' "$duration_seconds"
        printf 'Output: %s\n' "$out_dir"
        printf '\nGenerated events:\n'
        awk -F, 'NR>1 {events[$2]+=$4; bursts[$2]++} END {for (kind in events) printf "%s_events=%d %s_batches=%d\n",kind,events[kind],kind,bursts[kind]}' "$events" | sort
        printf '\nDaemon resources:\n'
        awk -F, 'NR>1 {n++;rss+=$3;cpu+=$5;if($3>maxrss)maxrss=$3;if($4>maxhwm)maxhwm=$4;if($5>maxcpu)maxcpu=$5} END {if(n)printf "samples=%d avg_rss_kb=%.0f peak_rss_kb=%d peak_hwm_kb=%d avg_cpu_percent=%.2f peak_cpu_percent=%.2f\n",n,rss/n,maxrss,maxhwm,cpu/n,maxcpu;else print "no samples"}' "$resources"
        printf '\nInstalled binary SHA256:\n'
        sha256sum "$binary"
    } >"$out_dir/summary.txt"
}

restore_config() {
    ((configured)) || return 0
    local current_hash
    current_hash=$(sha256sum "$config_file" | awk '{print $1}')
    if [[ "$current_hash" != "$soak_config_hash" ]]; then
        printf 'Config changed during soak; automatic restore skipped. Backup: %s\n' "$config_backup" | tee -a "$out_dir/cleanup.log"
        return 0
    fi
    install -o root -g antiddos -m 0640 "$config_backup" "$config_file"
    systemctl restart "$service"
    printf 'Original config restored and antiddos restarted.\n' >>"$out_dir/cleanup.log"
}

cleanup() {
    local status=$?
    ((cleanup_started == 0)) || return
    cleanup_started=1
    trap - EXIT INT TERM
    stop_children
    if ((configured)); then
        if [[ -s "$test_ips" ]]; then
            sort -u "$test_ips" | while read -r ip; do
                [[ -n "$ip" ]] || continue
                "$binary" unblock "$ip" >>"$out_dir/unblock.log" 2>&1 || true
            done
        fi
        write_report
        restore_config
    fi
    rm -f /run/antiddos-hybrid-soak.current
    printf 'exit=%d\n' "$status" >>"$out_dir/cleanup.log"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Install the current checkout first. The installer preserves config, keys and users.
bash "$repo_root/scripts/install.sh" --local --soft-block >"$out_dir/install.log" 2>&1

site_id=$(jq -r '.soft_block.sites | keys | if length == 1 then .[0] else empty end' "$config_file")
[[ -n "$site_id" ]] || fail "the soak requires exactly one configured soft_block site"
site_host=$(jq -r --arg site "$site_id" '.soft_block.sites[$site].hosts | if length > 0 then .[0] else empty end' "$config_file")
[[ -n "$site_host" ]] || fail "the configured soft_block site has no host"
jq -e '.engine.rules | length > 0 and all(.[]; .group_by == "ip")' "$config_file" >/dev/null || fail "all existing rules must use group_by ip before temporary hybrid conversion"
jq -e --arg id hybrid_soak '(.log_sources[$id] == null) and (all(.engine.rules[]; .id != "soak-captcha" and .id != "soak-firewall"))' "$config_file" >/dev/null || fail "temporary hybrid soak IDs already exist"

config_tmp="$out_dir/config.hybrid.json"
jq --arg source hybrid_soak --arg path "$access_log" --arg site "$site_id" '
    .block_mode = "hybrid"
    | .log_sources[$source] = {
        "path": $path,
        "format": "nginx_custom",
        "log_format": "$remote_addr - - [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\" \"$antiddos_response_origin\""
      }
    | .soft_block.sites[$site].log_sources = ((.soft_block.sites[$site].log_sources + [$source]) | unique)
    | .engine.rules = (
        [.engine.rules[] | if .action == null then . + {"action":"soft_block"} else . end]
        + [
            {"id":"soak-captcha","action":"soft_block","log_source":$source,"path_regex":"^/__hybrid_soak$","window":"10s","threshold":8,"group_by":"ip","ignore_ips":[]},
            {"id":"soak-firewall","action":"nftables","log_source":$source,"path_regex":"^/__hybrid_soak$","window":"1s","threshold":10,"group_by":"ip","ignore_ips":[]}
          ]
      )
' "$config_file" >"$config_tmp"

install -o root -g antiddos -m 0640 "$config_tmp" "$config_file"
soak_config_hash=$(sha256sum "$config_file" | awk '{print $1}')
configured=1
systemctl restart "$service" "$checker_service" "$web_service"
systemctl is-active --quiet "$service" "$checker_service" "$web_service"
for _ in $(seq 1 50); do
    [[ -S "$feed_socket" && -S "$check_socket" ]] && break
    sleep 0.1
done
[[ -S "$feed_socket" && -S "$check_socket" ]] || fail "feed/check sockets are unavailable after hybrid restart"
jq '{block_mode,block_duration,block_tcp_ports,log_sources,engine,soft_block}' "$config_file" >"$out_dir/config.hybrid.snapshot.json"

started_epoch=$(date +%s)
started_iso=$(date --iso-8601=seconds)
ended_epoch=$((started_epoch + duration_seconds))

append_line() {
    local ip=$1 path=$2 timestamp
    timestamp=$(date '+%d/%b/%Y:%H:%M:%S %z')
    printf '%s - - [%s] "GET %s HTTP/1.1" 200 12 "-" "hybrid-log-soak" "application"\n' "$ip" "$timestamp" "$path" >>"$access_log"
}

issue_challenge() {
    local ip=$1 code challenge_code attempt
    for attempt in $(seq 1 20); do
        code=$(curl --silent --output /dev/null --write-out '%{http_code}' --unix-socket "$check_socket" \
            http://localhost/__antiddos_check \
            -H "X-AntiDDoS-Site: $site_id" -H "X-AntiDDoS-IP: $ip" \
            -H "X-AntiDDoS-Host: $site_host" -H "X-AntiDDoS-Authority: $site_host" \
            -H 'X-AntiDDoS-URI: /__hybrid_soak' -H 'X-AntiDDoS-Method: GET' -H 'X-AntiDDoS-Scheme: https' || true)
        if [[ "$code" == 403 ]]; then
            challenge_code=$(curl --silent --output /dev/null --write-out '%{http_code}' --unix-socket "$check_socket" \
                'http://localhost/__antiddos/challenge' \
                -H "X-AntiDDoS-Site: $site_id" -H "X-AntiDDoS-IP: $ip" \
                -H "X-AntiDDoS-Host: $site_host" -H "X-AntiDDoS-Authority: $site_host" \
                -H 'X-AntiDDoS-URI: /' -H 'X-AntiDDoS-Method: GET' -H 'X-AntiDDoS-Scheme: https' || true)
            printf '%s ip=%s check=%s challenge=%s\n' "$(date --iso-8601=seconds)" "$ip" "$code" "${challenge_code:-000}"
            [[ "$challenge_code" == 200 ]]
            return
        fi
        sleep 0.05
    done
    printf '%s ip=%s check=%s challenge=not-issued\n' "$(date --iso-8601=seconds)" "$ip" "${code:-000}"
    return 1
}

# Baseline: five ordinary log events per second for traffic charts.
(
    sequence=1
    while (( $(date +%s) < ended_epoch )); do
        for _ in 1 2 3 4 5; do
            octet=$((sequence % 250 + 1))
            append_line "192.0.2.$octet" "/__hybrid_baseline/$sequence"
            sequence=$((sequence + 1))
        done
        printf '%s,baseline,192.0.2.0/24,5\n' "$(date --iso-8601=seconds)" >>"$events"
        sleep 1
    done
) & child_pids+=("$!")

# Slow bursts: eight requests spread across seven seconds, so only CAPTCHA fires.
(
    sequence=1
    while (( $(date +%s) < ended_epoch )); do
        octet=$((sequence % 250 + 1))
        ip="198.51.100.$octet"
        printf '%s\n' "$ip" >>"$test_ips"
        for _ in $(seq 1 8); do
            append_line "$ip" /__hybrid_soak
            sleep 1
        done
        printf '%s,soft,%s,8\n' "$(date --iso-8601=seconds)" "$ip" >>"$events"
        issue_challenge "$ip" >>"$out_dir/challenge.log" 2>&1 || true
        sequence=$((sequence + 1))
        sleep 12
    done
) & child_pids+=("$!")

# Hard bursts: ten requests inside one second, satisfying both rules; nftables wins.
(
    sequence=1
    while (( $(date +%s) < ended_epoch )); do
        octet=$((sequence % 250 + 1))
        ip="203.0.113.$octet"
        printf '%s\n' "$ip" >>"$test_ips"
        for _ in $(seq 1 10); do append_line "$ip" /__hybrid_soak; done
        printf '%s,hard,%s,10\n' "$(date --iso-8601=seconds)" "$ip" >>"$events"
        issue_challenge "$ip" >>"$out_dir/challenge.log" 2>&1 || true
        sequence=$((sequence + 1))
        sleep 60
    done
) & child_pids+=("$!")

# Per-second daemon resource samples.
(
    ticks_per_second=$(getconf CLK_TCK)
    previous_pid= previous_ticks=0 previous_ns=0
    while (( $(date +%s) < ended_epoch )); do
        timestamp=$(date --iso-8601=seconds)
        now_ns=$(date +%s%N)
        pid=$(systemctl show "$service" -p MainPID --value 2>/dev/null || true)
        rss=0 hwm=0 cpu=0
        if [[ "$pid" =~ ^[1-9][0-9]*$ && -r "/proc/$pid/status" && -r "/proc/$pid/stat" ]]; then
            rss=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status")
            hwm=$(awk '/^VmHWM:/ {print $2}' "/proc/$pid/status")
            ticks=$(awk '{sub(/^.*\) /, ""); print $12 + $13}' "/proc/$pid/stat")
            if [[ "$pid" == "$previous_pid" && "$previous_ns" -gt 0 ]]; then
                cpu=$(awk -v now="$ticks" -v prev="$previous_ticks" -v hz="$ticks_per_second" -v dns="$((now_ns-previous_ns))" 'BEGIN{if(dns>0)printf "%.2f",(now-prev)*100000000000/dns/hz;else print "0.00"}')
            fi
            previous_pid=$pid previous_ticks=$ticks previous_ns=$now_ns
        fi
        printf '%s,%s,%s,%s,%s\n' "$timestamp" "${pid:-0}" "${rss:-0}" "${hwm:-0}" "$cpu" >>"$resources"
        sleep 1
    done
) & child_pids+=("$!")

printf 'Hybrid soak started at %s for %s seconds.\n' "$started_iso" "$duration_seconds"
printf 'Open http://127.0.0.1:8080/ and keep Live mode enabled.\n'
printf 'Artifacts: %s\n' "$out_dir"

if ((duration_seconds >= 20)); then
    sleep 15
    systemctl is-active --quiet "$service" "$checker_service" "$web_service" || fail "a service stopped during the first 15 seconds"
    "$binary" monitor --once --limit 100 >"$out_dir/preflight-monitor.txt" 2>&1 || fail "monitor failed during preflight"
    grep -q 'soak-captcha' "$out_dir/preflight-monitor.txt" || fail "soft-level detection did not appear during preflight"
    grep -q 'soak-firewall' "$out_dir/preflight-monitor.txt" || fail "firewall-level detection did not appear during preflight"
    printf 'Preflight passed: both hybrid levels are visible.\n'
fi

while (( $(date +%s) < ended_epoch )); do
    systemctl is-active --quiet "$service" "$checker_service" "$web_service" || fail "a service stopped during soak"
    sleep 5
done
