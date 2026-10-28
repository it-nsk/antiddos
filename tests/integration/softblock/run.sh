#!/usr/bin/env bash
set -euo pipefail

scenario=""
output=""
while (($#)); do
  case "$1" in
    --scenario) scenario="${2:?missing scenario value}"; shift 2 ;;
    --output) output="${2:?missing output value}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ ( "$scenario" != nginx-contract && "$scenario" != nginx-uds ) || -z "$output" ]]; then
  echo "usage: $0 --scenario nginx-contract|nginx-uds --output <new-run-directory>" >&2
  exit 2
fi
if [[ -e "$output" ]] && [[ -n "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]]; then
  echo "output directory is not empty: $output" >&2
  exit 2
fi
for dependency in nginx openssl python3; do
  if ! command -v "$dependency" >/dev/null 2>&1; then
    echo "BLOCKED: missing dependency: $dependency" >&2
    exit 2
  fi
done
mkdir -p "$output"
runner=nginx_contract.py
if [[ "$scenario" == nginx-uds ]]; then runner=nginx_uds.py; fi
if python3 "$(dirname "$0")/$runner" --output "$output"; then
  status=0
else
  status=$?
fi
printf 'bash %s --scenario %s --output %s exit=%s\n' "$0" "$scenario" "$output" "$status" >>"$output/commands.log"
exit "$status"
