#!/usr/bin/env bash
# Exercises the installed daemon and its actual managed firewall objects.
# It refuses to run without --live and cleans its TEST-NET lease on exit.
set -Eeuo pipefail

[[ ${1:-} == --live && $# -eq 1 ]] || { echo "usage: sudo $0 --live" >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 2; }

bin=/usr/local/bin/antiddos
config=/etc/antiddos/config.json
ip=198.18.0.254
require() { command -v "$1" >/dev/null || { echo "missing $1" >&2; exit 1; }; }
for command in "$bin" python3 systemctl; do [[ "$command" == /* ]] && [[ -x "$command" ]] || require "$command"; done
systemctl is-active --quiet antiddos || { echo "antiddos is not active" >&2; exit 1; }
[[ -r $config ]] || { echo "missing $config" >&2; exit 1; }

read -r database mode rule action < <(python3 - "$config" <<'PY'
import json, sys
c=json.load(open(sys.argv[1]))
mode=c.get("block_mode", "dry_run")
for r in c.get("engine", {}).get("rules", []):
    if r.get("enabled", True) is False: continue
    a=r.get("action", mode) if mode == "hybrid" else mode
    if a in ("nftables", "iptables"):
        print(c["database_path"], mode, r["id"], a)
        break
else: raise SystemExit("no enabled firewall rule")
PY
)
[[ -f $database ]] || { echo "database does not exist: $database" >&2; exit 1; }

nft=false; ipset=false
case "$mode" in
  nftables) nft=true ;;
  iptables) ipset=true ;;
  hybrid) [[ $action == nftables ]] && nft=true || ipset=true ;;
  *) echo "configured mode is not a firewall mode: $mode" >&2; exit 1 ;;
esac

has_nft() { nft list set inet antiddos blocked_ipv4 2>/dev/null | grep -q "$ip"; }
has_ipset() { ipset test antiddos_blocked_ipv4 "$ip" >/dev/null 2>&1; }
has_block() { if $nft; then has_nft; else has_ipset; fi; }
ready() {
  [[ -S /run/antiddos/control.sock ]] || return 1
  if $nft; then
    nft list set inet antiddos blocked_ipv4 >/dev/null 2>&1
  else
    ipset list antiddos_blocked_ipv4 >/dev/null 2>&1
  fi
}
for ((attempt=0; attempt<100; attempt++)); do
  ready && break
  sleep 0.2
done
ready || { journalctl -u antiddos -n 25 --no-pager; echo 'daemon/firewall not ready' >&2; exit 1; }
db_count() { python3 - "$database" "$ip" <<'PY'
import sqlite3,sys
with sqlite3.connect(sys.argv[1]) as db: print(db.execute('select count(*) from active_blocks where ip=?',(sys.argv[2],)).fetchone()[0])
PY
}
cleanup() {
  $nft && nft delete element inet antiddos blocked_ipv4 "{ $ip }" 2>/dev/null || true
  $ipset && ipset del antiddos_blocked_ipv4 "$ip" 2>/dev/null || true
  python3 - "$database" "$ip" <<'PY' 2>/dev/null || true
import sqlite3,sys
with sqlite3.connect(sys.argv[1]) as db: db.execute('delete from active_blocks where ip=?',(sys.argv[2],))
PY
}
[[ $(db_count) == 0 ]] || { echo "refusing: $ip already exists in SQLite" >&2; exit 1; }
if has_block; then echo "refusing: $ip already exists in firewall" >&2; exit 1; fi
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Firewall -> SQLite -> remove external lease.
$nft && nft add element inet antiddos blocked_ipv4 "{ $ip timeout 120s }"
$ipset && ipset add antiddos_blocked_ipv4 "$ip" timeout 120
"$bin" blocks reconcile
[[ $(db_count) == 1 ]] || { echo "firewall import failed" >&2; exit 1; }
$nft && nft delete element inet antiddos blocked_ipv4 "{ $ip }"
$ipset && ipset del antiddos_blocked_ipv4 "$ip"
"$bin" blocks reconcile
[[ $(db_count) == 0 ]] || { echo "external lease was unexpectedly restored" >&2; exit 1; }

# Detected SQLite -> managed firewall -> explicit unblock.
python3 - "$database" "$ip" "$rule" <<'PY'
import sqlite3,sys,time
now=int(time.time()*1000); expires=now+120000
with sqlite3.connect(sys.argv[1]) as db:
 db.execute("insert into active_blocks(ip,rule_id,started_at_unix_ms,expires_at_unix_ms,origin) values(?,?,?,?, 'detected')",(sys.argv[2],sys.argv[3],now,expires))
PY
"$bin" blocks reconcile
has_block || { echo "SQLite export failed" >&2; exit 1; }
"$bin" unblock "$ip"
[[ $(db_count) == 0 ]] || { echo "unblock left SQLite lease" >&2; exit 1; }
if has_block; then echo "unblock left firewall element" >&2; exit 1; fi
echo "PASS: live managed firewall and SQLite synchronization"
