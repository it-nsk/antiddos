#!/bin/sh
# Create an isolated Nginx access log and AntiDDoS config for local smoke tests.
# It never reads or writes /var/log/nginx or /etc/antiddos.
set -eu

test_dir=${1:-"$(mktemp -d /tmp/antiddos-logban-smoke.XXXXXX)"}
case "$test_dir" in
  /tmp/*) ;;
  *) echo "Refusing output outside /tmp: $test_dir" >&2; exit 2 ;;
esac
mkdir -p "$test_dir"
log_file="$test_dir/access.log"
config_file="$test_dir/config.json"
database_file="$test_dir/state.sqlite"
test_ip=${2:-198.51.100.77}
test_uri=${3:-/load-test}
request_count=${4:-2}
case "$test_ip" in *[!0-9A-Fa-f.:]*) echo "Invalid test IP" >&2; exit 2;; esac
case "$test_uri" in /*) ;; *) echo "Test URI must start with /" >&2; exit 2;; esac
case "$test_uri" in *' '*|*'"'*|*"'"*|*'\\'*|*'`'*) echo "Invalid test URI" >&2; exit 2;; esac
case "$request_count" in ''|*[!0-9]*) echo "Request count must be a positive integer" >&2; exit 2;; esac
[ "$request_count" -gt 0 ] || { echo "Request count must be positive" >&2; exit 2; }
timestamp=$(LC_ALL=C date -u '+%d/%b/%Y:%H:%M:%S +0000')

: > "$log_file"
i=0
while [ "$i" -lt "$request_count" ]; do
  printf '%s - - [%s] "GET %s HTTP/1.1" 200 123 "-" "antiddos-test"\n' "$test_ip" "$timestamp" "$test_uri" >> "$log_file"
  i=$((i + 1))
done

cat > "$config_file" <<EOF
{
  "log_sources": {"test": {"path": "$log_file", "format": "nginx_combined"}},
  "database_path": "$database_file",
  "start_position": "beginning",
  "block_mode": "dry_run",
  "block_duration": "1m",
  "engine": {"rules": [{"id": "load-test", "action": "dry_run", "log_source": "test", "path_regex": "^${test_uri}$", "window": "10s", "threshold": 2, "group_by": "ip"}]}
}
EOF

printf 'Test log: %s\nTest config: %s\n' "$log_file" "$config_file"
printf 'Safe dry-run: antiddos run --config %s --from-start\n' "$config_file"
