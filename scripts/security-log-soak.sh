#!/usr/bin/env bash
set -Eeuo pipefail

# Safe replay soak: generates representative security log lines locally; it
# never opens SSH connections, probes ports, or sends traffic to other hosts.
repo_root=$(cd "$(dirname "$0")/.." && pwd)
duration=${1:-3600}
config=/etc/antiddos/config.json
backup=/etc/antiddos/config.json.security-soak-backup
log_dir=/var/log/antiddos/security-soak
error_log=$log_dir/nginx-error.log
ssh_log=$log_dir/ssh-auth.log
netfilter_log=$log_dir/netfilter.log
fail(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }
((EUID==0)) || fail 'run through sudo'
[[ "$duration" =~ ^[0-9]+$ && "$duration" -gt 0 ]] || fail 'duration must be positive seconds'
command -v jq >/dev/null || fail 'jq is required'
command -v systemctl >/dev/null || fail 'systemctl is required'

install -d -m 0755 "$log_dir"
touch "$error_log" "$ssh_log" "$netfilter_log"
chmod 0644 "$error_log" "$ssh_log" "$netfilter_log"
cp -a "$config" "$backup"
cleanup(){
  local status=$?
  trap - EXIT INT TERM
  if [[ -f "$backup" ]]; then
    install -o root -g root -m 0644 "$backup" "$config"
    systemctl restart antiddos.service >/dev/null 2>&1 || true
    rm -f "$backup"
  fi
  printf 'Security log soak finished (exit=%s). Logs remain in %s\n' "$status" "$log_dir"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

config_tmp="${config}.security-soak.$$"
jq --arg error "$error_log" --arg ssh "$ssh_log" --arg net "$netfilter_log" '
  .log_sources.bgt_error={path:$error,format:"nginx_error"}
  | .log_sources.ssh_auth={path:$ssh,format:"syslog_sshd"}
  | .log_sources.netfilter={path:$net,format:"netfilter_log"}
  | .engine.rules=(
      [.engine.rules[] | select((.id|IN("soak-nginx-basic-auth","soak-ssh-failed","soak-ssh-invalid","soak-port-burst"))|not)]
      + [
        {id:"soak-nginx-basic-auth",action:"dry_run",log_source:"bgt_error",path_regex:"^/auth/basic/failure$",window:"60s",threshold:5,group_by:"ip",ignore_ips:[]},
        {id:"soak-ssh-failed",action:"dry_run",log_source:"ssh_auth",path_regex:"^/ssh/failed$",window:"60s",threshold:8,group_by:"ip",ignore_ips:[]},
        {id:"soak-ssh-invalid",action:"dry_run",log_source:"ssh_auth",path_regex:"^/ssh/invalid-user$",window:"60s",threshold:4,group_by:"ip",ignore_ips:[]},
        {id:"soak-port-burst",action:"dry_run",log_source:"netfilter",path_regex:"^/port/",window:"30s",threshold:12,group_by:"ip",ignore_ips:[]}
      ])
' "$config" >"$config_tmp"
install -o root -g root -m 0644 "$config_tmp" "$config"
rm -f "$config_tmp"
systemctl restart antiddos.service

printf 'Security log soak running for %ss; generated sources: bgt_error, ssh_auth, netfilter\n' "$duration"
end=$((SECONDS+duration)); tick=0
while ((SECONDS < end)); do
  tick=$((tick+1)); stamp=$(date '+%b %e %H:%M:%S')
  printf '%s [error] 1#1: *1 user "admin": password mismatch, client: 198.18.250.10, server: bgt.my, request: "GET /admin HTTP/1.1"\n' "$(date '+%Y/%m/%d %H:%M:%S')" >>"$error_log"
  printf '%s host sshd[1]: Failed password for root from 198.18.250.20 port 42022 ssh2\n' "$stamp" >>"$ssh_log"
  printf '%s host sshd[1]: Failed password for invalid user admin from 198.18.250.21 port 42023 ssh2\n' "$stamp" >>"$ssh_log"
  for port in 22 80 443 8080; do
    printf '%s host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.18.250.30 DST=192.0.2.10 PROTO=TCP SPT=42%02d DPT=%s\n' "$stamp" "$((tick%90+10))" "$port" >>"$netfilter_log"
  done
  sleep 1
done
