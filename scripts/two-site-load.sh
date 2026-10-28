#!/usr/bin/env bash
# A soak is a long-running observer: one failed request or optional probe
# must not terminate the whole load. Explicit preflight checks still call
# fail(), while per-cycle operations are best-effort and recorded.
set -Euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
command_name="${1:-help}"
argument="${2:-}"
config=/etc/antiddos/config.json
binary=/usr/local/bin/antiddos
hosts=(bgt.my bgt2.test)
# Use a fresh benchmark subnet on every invocation. Soft decisions are
# intentionally persisted in SQLite, so reusing a source IP would make a
# subsequent hard-burst start in an already-challenged state.
run_octet=$((($$ % 100) + 10))
hard_octet=$((run_octet + 100))
soft_ips=("198.18.${run_octet}.10" "198.18.${run_octet}.20")
hard_ips=("198.18.${hard_octet}.10" "198.18.${hard_octet}.20")
all_ips=()
out_dir=

fail(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }
require_root(){ ((EUID == 0)) || fail "run through sudo (test source addresses require it)"; }
require_commands(){
    local name
    for name in curl jq ip nginx systemctl awk node nft; do command -v "$name" >/dev/null || fail "$name is required"; done
}
add_ip(){ local ip=$1; ip address add "$ip/32" dev lo 2>/dev/null || true; all_ips+=("$ip"); }
cleanup(){
    local ip
    for ip in "${all_ips[@]:-}"; do
        "$binary" unblock "$ip" >/dev/null 2>&1 || true
        ip address del "$ip/32" dev lo 2>/dev/null || true
    done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
request(){
    local host=$1 source=$2 path=${3:-/captcha-demo}
    curl --noproxy '*' -ksS --connect-timeout 2 --max-time 5 --interface "$source" \
        --resolve "$host:443:127.0.0.1" -o /dev/null -w '%{http_code}' "https://$host$path" 2>/dev/null || printf 000
}
validate(){
    local expected=${1:-}
    require_commands
    [[ -x "$binary" && -r "$config" ]] || fail "AntiDDoS binary/config is unavailable"
    jq -e '
      .log_sources.bgt_access.path == "/var/log/nginx/bgtweb_antiddos.log" and
      .log_sources.bgt2_access.path == "/var/log/nginx/bgt2_antiddos.log" and
      .soft_block.sites.bgt.hosts == ["bgt.my"] and
      .soft_block.sites.bgt.log_sources == ["bgt_access"] and
      .soft_block.sites.bgt2.hosts == ["bgt2.test"] and
      .soft_block.sites.bgt2.log_sources == ["bgt2_access"]
    ' "$config" >/dev/null || fail "config does not have isolated bgt/bgt2 sources and sites"
    if [[ -n "$expected" ]]; then
        [[ "$(jq -r .block_mode "$config")" == "$expected" ]] || fail "expected block_mode=$expected"
    fi
    systemctl is-active --quiet antiddos.service || fail "antiddos.service is not active"
    if jq -e '.block_mode == "soft_block" or (.block_mode == "hybrid" and any(.engine.rules[]; .action == "soft_block"))' "$config" >/dev/null; then
        systemctl is-active --quiet antiddos-challenge.service || fail "challenge checker is not active"
    fi
    nginx -t >/dev/null
    for host in "${hosts[@]}"; do
        [[ "$(curl --noproxy '*' -ksS --max-time 5 --resolve "$host:443:127.0.0.1" -o /dev/null -w '%{http_code}' "https://$host/")" =~ ^(200|301|302|404)$ ]] || fail "$host baseline request failed"
    done
}
validate_independent(){
    require_commands
    [[ -x "$binary" && -r "$config" ]] || fail "AntiDDoS binary/config is unavailable"
    jq -e '
      .block_mode == "hybrid" and
      .log_sources.bgt_access.path == "/var/log/nginx/bgtweb_antiddos.log" and
      .log_sources.bgt2_access.path == "/var/log/nginx/bgt2_access.log" and
      .soft_block.sites.bgt.hosts == ["bgt.my"] and
      .soft_block.sites.bgt.log_sources == ["bgt_access"] and
      (.soft_block.sites | has("bgt2") | not) and
      any(.engine.rules[]; .log_source == "bgt_access" and .action == "soft_block") and
      any(.engine.rules[]; .log_source == "bgt_access" and .action == "nftables") and
      any(.engine.rules[]; .log_source == "bgt2_access" and .action == "dry_run") and
      (all(.engine.rules[] | select(.log_source == "bgt2_access"); .action == "dry_run"))
    ' "$config" >/dev/null || fail "config does not match the independent hybrid profile"
    systemctl is-active --quiet antiddos.service || fail "antiddos.service is not active"
    systemctl is-active --quiet antiddos-challenge.service || fail "challenge checker is not active"
    nginx -t >/dev/null
    for host in "${hosts[@]}"; do
        [[ "$(curl --noproxy '*' -ksS --max-time 5 --resolve "$host:443:127.0.0.1" -o /dev/null -w '%{http_code}' "https://$host/")" =~ ^(200|301|302|404)$ ]] || fail "$host baseline request failed"
    done
}
soft_probe(){
    local index=$1 host=${hosts[$1]} source=${soft_ips[$1]} status= attempt
    add_ip "$source"
    for _ in $(seq 1 8); do status=$(request "$host" "$source"); sleep 1.05; done
    for attempt in $(seq 1 30); do
        status=$(request "$host" "$source")
        [[ "$status" == 429 ]] && break
        sleep 0.1
    done
    printf '%s soft source=%s final_http=%s\n' "$host" "$source" "$status"
    [[ "$status" == 429 ]] || { printf 'ERROR: %s did not issue a challenge after the soft threshold\n' "$host" >&2; return 1; }
}
hard_probe(){
    local index=$1 host=${hosts[$1]} source=${hard_ips[$1]} status= pid_list=()
    add_ip "$source"
    for _ in $(seq 1 10); do request "$host" "$source" >/dev/null & pid_list+=("$!"); done
    for pid in "${pid_list[@]}"; do wait "$pid" || true; done
    sleep 0.3
    status=$(request "$host" "$source")
    printf '%s hard source=%s post_burst_http=%s (000 means nftables dropped it)\n' "$host" "$source" "$status"
    "$binary" monitor --once --limit 200 | grep -qE "${host%%.*}-hard|bgt2-hard|bgt-hard" || { printf 'ERROR: hard detection is absent from monitor for %s\n' "$host" >&2; return 1; }
}
nft_contains(){
    local source=$1
    nft list set inet antiddos blocked_ipv4 2>/dev/null | grep -Eq "(^|[[:space:],{])${source}([[:space:],}]|$)"
}
rapid_expect(){
    local index=$1 expected=$2 host=${hosts[$1]} source=${hard_ips[$1]} status= pid_list=()
    add_ip "$source"
    for _ in $(seq 1 10); do request "$host" "$source" >/dev/null & pid_list+=("$!"); done
    for pid in "${pid_list[@]}"; do wait "$pid" || true; done
    for _ in $(seq 1 30); do
        status=$(request "$host" "$source")
        case "$expected" in
          application) [[ "$status" != 429 && "$status" != 000* ]] && break ;;
          challenge) [[ "$status" == 429 ]] && break ;;
          firewall) nft_contains "$source" && break ;;
        esac
        sleep 0.1
    done
    printf '%s rapid expected=%s http=%s nft=%s\n' "$host" "$expected" "$status" "$(nft_contains "$source" && printf yes || printf no)"
    case "$expected" in
      application) [[ "$status" != 429 && "$status" != 000* ]] || fail "$host unexpectedly enforced rapid traffic" ;;
      challenge) [[ "$status" == 429 ]] || fail "$host did not challenge rapid traffic in soft_block" ;;
      firewall) nft_contains "$source" || fail "$host source is absent from the nftables set" ;;
    esac
}
case "$command_name" in
  preflight)
    require_root; validate "$argument"
    printf 'Preflight OK: two HTTPS sites, two isolated logs, services and Nginx are ready.\n'
    ;;
  soft)
    require_root; validate "${argument:-hybrid}"
    soft_probe 0; soft_probe 1
    ;;
  hard)
    require_root; validate "${argument:-hybrid}"
    hard_probe 0; hard_probe 1
    ;;
  mode-probe)
    require_root; mode=${argument:-}; [[ -n "$mode" ]] || fail "mode-probe requires dry_run|soft_block|hybrid|nftables"
    validate "$mode"
    case "$mode" in
      dry_run) for i in 0 1; do rapid_expect "$i" application; done ;;
      soft_block) for i in 0 1; do rapid_expect "$i" challenge; done ;;
      hybrid) soft_probe 0; soft_probe 1; for i in 0 1; do rapid_expect "$i" firewall; done ;;
      nftables) for i in 0 1; do rapid_expect "$i" firewall; done ;;
      *) fail "unknown mode $mode" ;;
    esac
    ;;
  independent)
    require_root; validate_independent
    soft_probe 0 || fail 'independent soft probe failed'
    rapid_expect 0 firewall || fail 'independent firewall probe failed'
    rapid_expect 1 application || fail 'independent dry-run probe failed'
    printf 'Independent profile OK: bgt.my uses CAPTCHA+nftables; bgt2.test is detection-only.\n'
    ;;
  browser)
    validate "${argument:-hybrid}"
    for host in "${hosts[@]}"; do
      SITE_HOST="$host" node "$repo_root/tests/integration/two-site/browser_acceptance.mjs"
    done
    ;;
  fault-checker)
    require_root; validate "${argument:-hybrid}"
    systemctl stop antiddos-challenge.service
    trap 'systemctl start antiddos-challenge.service; cleanup' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    for host in "${hosts[@]}"; do
      code=$(curl --noproxy '*' -ksS --max-time 5 --resolve "$host:443:127.0.0.1" -o /dev/null -w '%{http_code}' "https://$host/")
      printf '%s with checker stopped: HTTP %s (fail-open application response expected)\n' "$host" "$code"
      [[ "$code" != 429 && "$code" != 500 && "$code" != 502 && "$code" != 503 && "$code" != 504 ]] || fail "$host did not fail open"
    done
    systemctl start antiddos-challenge.service
    trap cleanup EXIT
    ;;
  soak)
    require_root; duration=${argument:-3600}; [[ "$duration" =~ ^[0-9]+$ ]] || fail "duration must be seconds"
    validate hybrid
    stamp=$(date +%Y%m%d-%H%M%S); out_dir="/var/log/antiddos/two-site-soak-$stamp"; install -d -m 0750 "$out_dir"
    printf 'timestamp,host,kind,requests,last_http\n' >"$out_dir/events.csv"
    printf 'timestamp,service,pid,rss_kb,restarts\n' >"$out_dir/resources.csv"
    end=$((SECONDS+duration)); cycle=0; background_rps=10
    for ip in "${soft_ips[@]}" "${hard_ips[@]}"; do add_ip "$ip"; done
    while ((SECONDS < end)); do
      cycle=$((cycle+1)); now=$(date --iso-8601=seconds)
      for i in 0 1; do
        request_pids=()
        for _ in $(seq 1 "$background_rps"); do
          request "${hosts[$i]}" "${soft_ips[$i]}" "/soak-baseline?cycle=$cycle" >/dev/null & request_pids+=("$!")
        done
        status=000
        for pid in "${request_pids[@]}"; do wait "$pid" || true; done
        status=$(request "${hosts[$i]}" "${soft_ips[$i]}" "/soak-baseline?cycle=$cycle")
        printf '%s,%s,baseline,%s,%s\n' "$now" "${hosts[$i]}" "$((background_rps+1))" "$status" >>"$out_dir/events.csv"
      done
      if ((cycle % 30 == 1)); then
        for i in 0 1; do soft_probe "$i" >>"$out_dir/probes.log" 2>&1 || true; done
      fi
      if ((cycle % 120 == 1)); then
        for i in 0 1; do hard_probe "$i" >>"$out_dir/probes.log" 2>&1 || true; done
      fi
      for service in antiddos antiddos-challenge antiddos-web; do
        pid=$(systemctl show "$service.service" -p MainPID --value 2>/dev/null || printf 0)
        restarts=$(systemctl show "$service.service" -p NRestarts --value 2>/dev/null || printf 0)
        rss=0
        if [[ "$pid" =~ ^[1-9][0-9]*$ && -r /proc/$pid/status ]]; then
          rss=$(awk '/^VmRSS:/{print $2}' "/proc/$pid/status")
        fi
        printf '%s,%s,%s,%s,%s\n' "$now" "$service" "$pid" "${rss:-0}" "${restarts:-0}" >>"$out_dir/resources.csv"
      done
      ((cycle % 2 == 0)) && "$binary" monitor --once --limit 500 >"$out_dir/monitor-latest.txt" 2>&1 || true
      sleep 1
    done
    "$binary" monitor --once --limit 2000 >"$out_dir/monitor-final.txt" 2>&1 || true
    systemctl show antiddos.service antiddos-challenge.service antiddos-web.service -p ActiveState -p MainPID -p NRestarts >"$out_dir/services-final.txt"
    jq '{block_mode,block_duration,log_sources,engine,soft_block}' "$config" >"$out_dir/config.json"
    printf 'Soak finished. Artifacts: %s\n' "$out_dir"
    ;;
  *)
    printf 'Usage: sudo %s preflight [MODE] | mode-probe MODE | independent | soft [MODE] | hard [MODE] | browser [MODE] | fault-checker [MODE] | soak [SECONDS]\n' "$0"
    ;;
esac
