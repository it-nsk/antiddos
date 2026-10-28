#!/usr/bin/env bash
set -Eeuo pipefail

duration=${1:-3600}
(( EUID == 0 )) || { echo 'run through sudo'; exit 1; }
[[ "$duration" =~ ^[0-9]+$ && "$duration" -gt 0 ]] || { echo 'duration must be positive seconds'; exit 1; }
command -v jq >/dev/null || { echo 'jq is required'; exit 1; }

config=/etc/antiddos/config.json
stamp=$(date +%Y%m%d-%H%M%S)
root=/var/log/antiddos/log-study-soak-$stamp
mkdir -p "$root"/nginx "$root"/system
chown -R antiddos:antiddos "$root"
chmod 0750 "$root" "$root"/nginx "$root"/system
for f in bgtweb_access.log bgtweb_all_access.log error.log; do touch "$root/nginx/$f"; done
for f in auth.log kern.log; do touch "$root/system/$f"; done
chown -R antiddos:antiddos "$root"; chmod 0640 "$root"/nginx/* "$root"/system/*

backup="$root/config.before.json"
cp -a "$config" "$backup"
cleanup(){
  status=$?
  trap - EXIT INT TERM
  [[ -n "${sampler:-}" ]] && kill "$sampler" 2>/dev/null || true
  install -o root -g root -m 0644 "$backup" "$config" 2>/dev/null || true
  systemctl restart antiddos.service >/dev/null 2>&1 || true
  {
    echo "started=$started"; echo "finished=$(date --iso-8601=seconds)"; echo "duration=$duration"; echo "output=$root"
    echo; echo 'event_lines:'
    for f in "$root"/nginx/* "$root"/system/*; do printf '%s=%s\n' "$(basename "$f")" "$(wc -l <"$f")"; done
    echo; echo 'detections:'
    journalctl -u antiddos --since "$started" --no-pager 2>/dev/null | grep 'request pattern detected' | sed -E 's/.*rule=([^ ]+).*group_value=([^ ]+).*count=([^ ]+).*/rule=\1 ip=\2 count=\3/' | sort | uniq -c || true
    echo; echo 'service:'; systemctl is-active antiddos.service || true
  } | tee "$root/summary.txt"
  echo "Soak finished (exit=$status). Output: $root"
  exit "$status"
}
trap cleanup EXIT INT TERM

tmp="$root/config.json"
jq --arg a "$root/nginx/bgtweb_access.log" --arg all "$root/nginx/bgtweb_all_access.log" --arg e "$root/nginx/error.log" --arg s "$root/system/auth.log" --arg n "$root/system/kern.log" '
  .block_mode="dry_run" |
  .log_sources.nginx_bgt_access.path=$a |
  .log_sources.nginx_all_access.path=$all |
  .log_sources.nginx_error={path:$e,format:"nginx_error"} |
  .log_sources.ssh_auth={path:$s,format:"syslog_sshd"} |
  .log_sources.netfilter={path:$n,format:"netfilter_log"}
' "$config" >"$tmp"
install -o root -g root -m 0644 "$tmp" "$config"
systemctl restart antiddos.service
systemctl is-active --quiet antiddos.service
started=$(date --iso-8601=seconds)
sampler=''
(
  while :; do
    printf '\n[%s]\n' "$(date --iso-8601=seconds)"
    /usr/local/bin/antiddos monitor --once --limit 1000 2>&1 || true
    sleep 30
  done
) >>"$root/monitor.log" 2>&1 &
sampler=$!
end=$((SECONDS+duration))
cycle=0
while (( SECONDS < end )); do
  cycle=$((cycle+1)); now_access=$(date '+%d/%b/%Y:%H:%M:%S %z'); now_sys=$(date '+%b %e %H:%M:%S')
  # Representative URLs copied from the supplied bgtweb access logs.
  for path in '/.env' '/.git/config' '/.aws/credentials' '/admin' '/login'; do
    printf '198.18.250.10 - - [%s] "GET %s HTTP/1.1" 403 146 "-" "Mozilla/5.0 scanner"\n' "$now_access" "$path" >>"$root/nginx/bgtweb_access.log"
  done
  printf '198.18.250.11 - - [%s] "GET /phpmyadmin HTTP/1.1" 401 172 "-" "Mozilla/5.0 scanner"\n' "$now_access" >>"$root/nginx/bgtweb_all_access.log"
  printf '%s [error] 1#1: *1 limiting requests, excess: 3.1 by zone "main", client: 198.18.250.12, server: bankturov.ru, request: "GET / HTTP/1.1", host: "bankturov.ru"\n' "$(date '+%Y/%m/%d %H:%M:%S')" >>"$root/nginx/error.log"
  printf '%s host sshd[1]: Failed password for root from 198.18.250.20 port 42022 ssh2\n' "$now_sys" >>"$root/system/auth.log"
  printf '%s host sshd[1]: Failed password for invalid user admin from 198.18.250.21 port 42023 ssh2\n' "$now_sys" >>"$root/system/auth.log"
  for port in 22 80 443 8080 8443 3306 6379 9200; do printf '%s host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.18.250.30 DST=192.0.2.10 PROTO=TCP SPT=42%02d DPT=%s\n' "$now_sys" "$((cycle%90+10))" "$port" >>"$root/system/kern.log"; done
  sleep 1
done
