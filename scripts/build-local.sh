#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

for command_name in go npm sha256sum; do
    command -v "$command_name" >/dev/null || { printf 'ERROR: %s is required\n' "$command_name" >&2; exit 1; }
done
[[ -d web/node_modules ]] || { printf 'ERROR: web/node_modules is missing; run (cd web && npm ci) first\n' >&2; exit 1; }

printf '[1/4] Go tests\n'
go test ./cmd/... ./internal/... -count=1
printf '[2/4] Go vet\n'
go vet ./cmd/... ./internal/...
printf '[3/4] Web production assets\n'
(cd web && npm run build)
printf '[4/4] Linux binary\n'
temporary="${repo_root}/.antiddos.build.$$"
trap 'rm -f -- "$temporary"' EXIT
go build -trimpath -o "$temporary" ./cmd/antiddos
chmod 0755 "$temporary"
mv -f -- "$temporary" "$repo_root/antiddos"
trap - EXIT

printf 'Built: %s\n' "$repo_root/antiddos"
sha256sum "$repo_root/antiddos"
"$repo_root/antiddos" --help | sed -n '1,14p'
