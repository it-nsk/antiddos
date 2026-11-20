#!/usr/bin/env bash
# Real-firewall reconciliation test.  The outer invocation must be root; it
# immediately enters a fresh network and mount namespace, so no host firewall,
# /run socket, Nginx instance, or configured site is changed.
set -Eeuo pipefail

inside=0
output=""
go_binary="${GO_BINARY:-}"
while (($#)); do
    case "$1" in
        --inside) inside=1; shift ;;
        --output) output=${2:?missing output directory}; shift 2 ;;
        *) printf 'usage: sudo %s --output <new-directory>\n' "$0" >&2; exit 2 ;;
    esac
done

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
require() { command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"; }

# sudo commonly uses secure_path and omits /usr/local/go/bin.  Prefer an
# explicit override, then the standard Go installation path.
if [[ -z "$go_binary" ]]; then
    if command -v go >/dev/null 2>&1; then go_binary=$(command -v go)
    elif [[ -x /usr/local/go/bin/go ]]; then go_binary=/usr/local/go/bin/go
    else fail 'Go is required; pass GO_BINARY=/absolute/path/to/go before sudo'; fi
fi
[[ -x "$go_binary" ]] || fail "Go executable is not executable: $go_binary"

if (( ! inside )); then
    (( EUID == 0 )) || fail 'run through sudo; the test needs a private network namespace'
    [[ -n "$output" ]] || fail '--output is required'
    [[ ! -e "$output" || -z "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]] || fail "output is not empty: $output"
    mkdir -p "$output"
	root=$(cd "$(dirname "$0")/../../.." && pwd)
	case_dir="$output/case"
	mkdir -p "$case_dir/nginx"
	# Module downloads, when needed, must happen before the network namespace
	# deliberately removes outbound DNS/network access.
	(cd "$root" && GOCACHE="$case_dir/go-cache" "$go_binary" build -o "$output/antiddos" ./cmd/antiddos)
    exec unshare --net --mount --fork -- bash "$0" --inside --output "$output"
fi

[[ -n "$output" ]] || fail '--output is required'
for command in ip nft iptables ip6tables ipset nginx curl python3 mount; do require "$command"; done

# Do not propagate the private /run mount back to the host.
mount --make-rprivate /
mount -t tmpfs -o mode=0755 tmpfs /run
mkdir -p /run/antiddos
ip link set lo up

root=$(cd "$(dirname "$0")/../../.." && pwd)
case_dir="$output/case"
mkdir -p "$case_dir/nginx"
binary="$output/antiddos"
[[ -x "$binary" ]] || fail "prebuilt test binary is missing: $binary"

daemon_pid=""
nginx_pid=""
cleanup() {
    [[ -z "$daemon_pid" ]] || kill "$daemon_pid" 2>/dev/null || true
    [[ -z "$nginx_pid" ]] || kill "$nginx_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

cat >"$case_dir/nginx.conf" <<EOF
pid $case_dir/nginx/nginx.pid;
error_log $case_dir/nginx/error.log notice;
events {}
http {
  access_log $case_dir/access.log combined;
  server { listen 127.0.0.1:18080; server_name bgt.my; location / { return 200 "bgt.my firewall reconcile test\\n"; } }
}
EOF
nginx -p "$case_dir/nginx" -c "$case_dir/nginx.conf"
nginx_pid=$(cat "$case_dir/nginx/nginx.pid")

wait_for() {
    local tries=$1; shift
    for ((i=0; i<tries; i++)); do "$@" && return 0; sleep 0.1; done
    return 1
}
nft_has() { nft list set inet antiddos blocked_ipv4 | grep -q "$1"; }
ipset_has() { ipset test antiddos_blocked_ipv4 "$1"; }
query_count() {
    python3 - "$case_dir/state.sqlite" "$1" <<'PY'
import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as db:
    print(db.execute("select count(*) from active_blocks where ip=?", (sys.argv[2],)).fetchone()[0])
PY
}
query_origin() {
    python3 - "$case_dir/state.sqlite" "$1" <<'PY'
import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as db:
    row=db.execute("select rule_id,origin from active_blocks where ip=?", (sys.argv[2],)).fetchone()
    print("" if row is None else "|".join(row))
PY
}

run_backend() {
    local backend=$1 external=198.51.100.77 client=127.0.0.2
    cat >"$case_dir/config.json" <<EOF
{"log_sources":{"bgt":{"path":"$case_dir/access.log","format":"nginx_combined"}},"database_path":"$case_dir/state.sqlite","start_position":"end","block_mode":"$backend","block_duration":"1m","block_tcp_ports":[18080],"engine":{"rules":[{"id":"bgt-request","log_source":"bgt","path_regex":"^/$","window":"1s","threshold":1,"group_by":"ip"}]}}
EOF
    "$binary" launch --config "$case_dir/config.json" >"$case_dir/$backend-daemon.log" 2>&1 &
    daemon_pid=$!
    wait_for 100 test -S /run/antiddos/control.sock || fail "$backend daemon control socket was not created"

    # bgt.my is resolved only for this request. The non-primary loopback source
    # lets the test later prove the real input-chain ban without losing access
    # to the test server itself.
    curl --noproxy '*' --interface "$client" --resolve bgt.my:18080:127.0.0.1 -fsS http://bgt.my:18080/ >/dev/null
    if [[ "$backend" == nftables ]]; then
        wait_for 100 nft_has "$client" || fail 'nftables detection did not create a managed block'
        nft add table inet firewall_reconcile_foreign
        nft add set inet firewall_reconcile_foreign keep '{ type ipv4_addr; }'
        nft add element inet firewall_reconcile_foreign keep '{ 203.0.113.200 }'
        nft add element inet antiddos blocked_ipv4 "{ $external timeout 5s }"
		nft -j list set inet antiddos blocked_ipv4 >"$case_dir/nft-before-reconcile.json"
    else
        wait_for 100 ipset_has "$client" || fail 'ipset detection did not create a managed block'
        ipset create firewall_reconcile_foreign hash:ip family inet timeout 60
        ipset add firewall_reconcile_foreign 203.0.113.200 timeout 60
        ipset add antiddos_blocked_ipv4 "$external" timeout 5
    fi

    "$binary" blocks reconcile
    [[ "$(query_origin "$external")" == 'external-firewall|external' ]] || fail "$backend did not import firewall-only address"

    # Explicit sync restores a detected SQLite-only lease to the firewall.
    if [[ "$backend" == nftables ]]; then
        nft delete element inet antiddos blocked_ipv4 "{ $client }"
        ! nft_has "$client" || fail 'nftables did not remove the managed element'
    else
        ipset del antiddos_blocked_ipv4 "$client"
        ! ipset_has "$client" || fail 'ipset did not remove the managed element'
    fi
    "$binary" blocks reconcile
    if [[ "$backend" == nftables ]]; then
        nft_has "$client" || fail 'nftables did not restore SQLite-only address'
    else
        ipset_has "$client" || fail 'ipset did not restore SQLite-only address'
    fi
    [[ "$(query_count "$client")" == 1 ]] || fail "$backend lost detected SQLite lease"

    # An explicit unblock removes the address from both places.
    "$binary" unblock "$client"
    [[ "$(query_count "$client")" == 0 ]] || fail "$backend retained unblocked SQLite address"
    if [[ "$backend" == nftables ]]; then
        ! nft_has "$client" || fail 'nftables retained unblocked address'
    else
        ! ipset_has "$client" || fail 'ipset retained unblocked address'
    fi

    # Timeout expiration also removes the SQLite row after the next reconcile.
    sleep 6
	if [[ "$backend" == nftables ]]; then nft -j list set inet antiddos blocked_ipv4 >"$case_dir/nft-after-expiry.json"; fi
    "$binary" blocks reconcile
    [[ "$(query_count "$external")" == 0 ]] || fail "$backend retained expired firewall address"
    if [[ "$backend" == nftables ]]; then
        nft list set inet firewall_reconcile_foreign keep | grep -q 203.0.113.200 || fail 'nftables touched foreign set'
    else
        ipset test firewall_reconcile_foreign 203.0.113.200 || fail 'ipset touched foreign set'
    fi
    printf '%s: PASS\n' "$backend" | tee -a "$output/result.log"
    kill "$daemon_pid"; wait "$daemon_pid" 2>/dev/null || true; daemon_pid=""
    rm -f /run/antiddos/control.sock /run/antiddos/web.sock "$case_dir/state.sqlite" "$case_dir/state.sqlite-wal" "$case_dir/state.sqlite-shm"
}

run_backend nftables
run_backend iptables
printf 'PASS: isolated real nftables and iptables+ipset reconciliation test completed.\n'
