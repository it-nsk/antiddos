#!/usr/bin/env bash
# Temporarily exercise the installed daemon on the host's managed nft sets.
set -Eeuo pipefail
[[ $EUID == 0 ]] || { echo 'Run with sudo' >&2; exit 2; }
root=$(cd "$(dirname "$0")/../../.." && pwd)
work=$(mktemp -d /tmp/antiddos-live-nft.XXXXXX)
cp -p /etc/antiddos/config.json "$work/config.json"
echo "Original configuration saved in $work/config.json"
restore() {
  result=$?
  trap - EXIT
  cp -p "$work/config.json" /etc/antiddos/config.json || { echo "RESTORE FAILED: $work/config.json" >&2; exit 1; }
  systemctl restart antiddos || { echo 'Service restart failed during restore' >&2; exit 1; }
  echo 'Original configuration restored; backup retained.'
  exit "$result"
}
trap restore EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
systemctl stop antiddos
python3 - <<'PY'
import json
p='/etc/antiddos/config.json'
with open(p) as f: c=json.load(f)
c['block_mode']='nftables'
c['block_tcp_ports']=[65530]
with open(p,'w') as f:
    json.dump(c,f,ensure_ascii=False,indent=2)
    f.write('\n')
PY
systemctl start antiddos
# Type=simple reports started before the launcher has initialized nftables.
bash "$root/tests/integration/firewall-reconcile/live-host.sh" --live
python3 "$root/tests/integration/firewall-reconcile/live-whitelist.py"
