#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
OUTPUT=${1:-}
if [[ -z "$OUTPUT" || ( -e "$OUTPUT" && -n "$(find "$OUTPUT" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ) ]]; then
  echo "usage: $0 NEW_OUTPUT_DIRECTORY" >&2
  exit 2
fi
mkdir -p "$OUTPUT"
OUTPUT=$(cd "$OUTPUT" && pwd)
IMAGE=${SYSTEMD_IMAGE:-antiddos-stage-f-systemd:20261021}
NAME="antiddos-stage-f-$PPID-$$"
CONTAINER_ID=
cleanup() {
  status=$?
  if [[ -n "$CONTAINER_ID" ]]; then
    docker inspect "$CONTAINER_ID" >"$OUTPUT/container-inspect.json" 2>/dev/null || true
    docker logs "$CONTAINER_ID" >"$OUTPUT/container.log" 2>&1 || true
    docker exec "$CONTAINER_ID" systemctl status antiddos.service antiddos-challenge.service --no-pager >"$OUTPUT/failure-unit-status.txt" 2>&1 || true
    docker exec "$CONTAINER_ID" journalctl -u antiddos.service -u antiddos-challenge.service --no-pager >"$OUTPUT/failure-journal.log" 2>&1 || true
    docker rm -f "$CONTAINER_ID" >"$OUTPUT/container-remove.log" 2>&1 || true
  fi
  printf 'exit=%s\n' "$status" >>"$OUTPUT/commands.log"
}
trap cleanup EXIT INT TERM

run() {
  printf '%q ' "$@" >>"$OUTPUT/commands.log"
  printf '\n' >>"$OUTPUT/commands.log"
  "$@"
}

run env GOCACHE=/tmp/antiddos-go-cache-20261021 CGO_ENABLED=1 GOOS=linux go build -o "$OUTPUT/antiddos" ./cmd/antiddos
run docker image inspect "$IMAGE" >"$OUTPUT/image-inspect.json"
CONTAINER_ID=$(run docker run -d --privileged --cgroupns=private --name "$NAME" --tmpfs /run --tmpfs /run/lock --tmpfs /tmp "$IMAGE" /sbin/init)
printf '%s\n' "$CONTAINER_ID" >"$OUTPUT/container-id.txt"

for _ in $(seq 1 30); do
  state=$(docker inspect --format '{{.State.Status}}' "$CONTAINER_ID")
  if [[ "$state" != running ]]; then
    echo "systemd container stopped: $state" >&2
    exit 1
  fi
  if docker exec "$CONTAINER_ID" systemctl is-system-running --quiet; then break; fi
  sleep 1
done
run docker exec "$CONTAINER_ID" systemctl is-system-running >"$OUTPUT/systemd-state.txt"
run docker exec "$CONTAINER_ID" systemd --version >"$OUTPUT/systemd-version.txt"
printf '%q ' docker exec "$CONTAINER_ID" systemd-run --wait --pipe -p User=nobody -p LoadCredential=probe:/etc/hostname /bin/sh -c 'printf "CREDENTIALS_DIRECTORY=%s\n" "$CREDENTIALS_DIRECTORY"; ls -la "$CREDENTIALS_DIRECTORY"; cat "$CREDENTIALS_DIRECTORY/probe"' >>"$OUTPUT/commands.log"
printf '\n' >>"$OUTPUT/commands.log"
if ! docker exec "$CONTAINER_ID" systemd-run --wait --pipe \
  -p User=nobody \
  -p LoadCredential=probe:/etc/hostname \
  /bin/sh -c 'printf "CREDENTIALS_DIRECTORY=%s\n" "$CREDENTIALS_DIRECTORY"; ls -la "$CREDENTIALS_DIRECTORY"; cat "$CREDENTIALS_DIRECTORY/probe"' \
  >"$OUTPUT/credential-probe.log" 2>&1; then
  echo "systemd LoadCredential is unavailable; see credential-probe.log" >&2
  exit 1
fi
run docker cp "$OUTPUT/antiddos" "$CONTAINER_ID:/usr/local/bin/antiddos"
run docker cp "$ROOT/deploy/antiddos.service" "$CONTAINER_ID:/etc/systemd/system/antiddos.service"
run docker cp "$ROOT/deploy/antiddos-challenge.service" "$CONTAINER_ID:/etc/systemd/system/antiddos-challenge.service"
run docker exec "$CONTAINER_ID" mkdir -p /etc/systemd/system/antiddos.service.d
run docker cp "$ROOT/deploy/antiddos-soft-block.conf" "$CONTAINER_ID:/etc/systemd/system/antiddos.service.d/soft-block.conf"

run docker exec "$CONTAINER_ID" bash -lc '
set -Eeuo pipefail
groupadd --system antiddos
groupadd --system antiddos-soft-feed
groupadd --system antiddos-check
useradd --system --gid antiddos antiddos
useradd --system --gid antiddos-check --groups antiddos-soft-feed antiddos-challenge
useradd --system --gid antiddos-check nginx-probe
install -d -o root -g root -m 0755 /etc/antiddos /etc/antiddos-challenge
install -d -o root -g root -m 0755 /run/credentials
install -d -o antiddos -g antiddos -m 0750 /var/log/nginx
touch /var/log/nginx/access.log
chown antiddos:antiddos /var/log/nginx/access.log
cat >/etc/antiddos/config.json <<JSON
{
  "log_sources":{"web":{"path":"/var/log/nginx/access.log","format":"nginx_custom","log_format":"\$remote_addr [\$time_local] \"\$request\" \$status \$body_bytes_sent \"\$http_referer\" \"\$http_user_agent\" \$antiddos_response_origin"}},
  "database_path":"/var/lib/antiddos/antiddos.sqlite",
  "start_position":"end",
  "block_mode":"soft_block",
  "block_duration":"1m",
  "soft_block":{"cookie_ttl":"30m","sites":{"test":{"hosts":["example.test"],"log_sources":["web"]}}},
  "engine":{"rules":[{"id":"probe","log_source":"web","path_regex":"^/$","window":"5s","threshold":2,"group_by":"ip"}]}
}
JSON
chmod 0644 /etc/antiddos/config.json
printf "%s\n" "{\"provider_secret\":\"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=\",\"current\":{\"id\":\"test\",\"secret\":\"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=\"},\"previous\":[]}" >/etc/antiddos-challenge/keys.json
chmod 0600 /etc/antiddos-challenge/keys.json
systemctl daemon-reload
systemctl start antiddos.service
systemctl start antiddos-challenge.service
systemctl is-active --quiet antiddos.service antiddos-challenge.service
for _ in $(seq 1 50); do
  if test -S /run/antiddos-soft-feed/feed.sock && test -S /run/antiddos-challenge-check/check.sock; then break; fi
  systemctl is-active --quiet antiddos.service antiddos-challenge.service
  sleep 0.1
done
test -S /run/antiddos-soft-feed/feed.sock
test -S /run/antiddos-challenge-check/check.sock
test "$(stat -c %a /run/antiddos-soft-feed/feed.sock)" = 660
test "$(stat -c %a /run/antiddos-challenge-check/check.sock)" = 660
runuser -u nginx-probe -- curl --fail --silent --show-error --unix-socket /run/antiddos-challenge-check/check.sock http://localhost/__antiddos_check \
  -H "X-AntiDDoS-Host: example.test" -H "X-AntiDDoS-Authority: example.test" -H "X-AntiDDoS-Scheme: https" \
  -H "X-AntiDDoS-IP: 192.0.2.10" -H "X-AntiDDoS-Method: GET" -H "X-AntiDDoS-URI: /" -o /tmp/check-body -w "%{http_code}" | grep -q 204
if runuser -u nobody -- curl --silent --show-error --unix-socket /run/antiddos-challenge-check/check.sock http://localhost/__antiddos_check -o /tmp/denied 2>/tmp/denied.err; then
  echo "unexpected checker socket access for nobody" >&2
  exit 1
fi
grep -qi "Permission denied" /tmp/denied.err
main_pid=$(systemctl show -p MainPID --value antiddos.service)
checker_pid=$(systemctl show -p MainPID --value antiddos-challenge.service)
grep -q "^CapEff:[[:space:]]*0000000000000000$" "/proc/$main_pid/status"
grep -q "^CapEff:[[:space:]]*0000000000000000$" "/proc/$checker_pid/status"
if runuser -u antiddos-challenge -- sh -c "echo x >>/etc/antiddos/config.json" 2>/tmp/config-write.err; then exit 1; fi
if runuser -u antiddos-challenge -- sh -c "echo x >>/var/lib/antiddos/antiddos.sqlite" 2>/tmp/db-write.err; then exit 1; fi
systemctl restart antiddos.service antiddos-challenge.service
systemctl is-active --quiet antiddos.service antiddos-challenge.service
test -S /run/antiddos-soft-feed/feed.sock
test -S /run/antiddos-challenge-check/check.sock
systemctl show antiddos.service antiddos-challenge.service > /tmp/unit-show.txt
systemctl stop antiddos-challenge.service antiddos.service
test ! -e /run/antiddos-soft-feed/feed.sock
test ! -e /run/antiddos-challenge-check/check.sock
'

run docker cp "$CONTAINER_ID:/tmp/unit-show.txt" "$OUTPUT/unit-show.txt"
run docker exec "$CONTAINER_ID" journalctl -u antiddos.service -u antiddos-challenge.service --no-pager >"$OUTPUT/journal.log"
run docker exec "$CONTAINER_ID" systemctl is-active antiddos.service antiddos-challenge.service >"$OUTPUT/final-unit-state.txt" || true
printf 'PASS\n' >"$OUTPUT/result.txt"
