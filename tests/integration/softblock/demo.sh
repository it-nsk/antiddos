#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
run_dir="${SOFTBLOCK_RUN_DIR:-${root_dir}/runtime/softblock/demo-local}"

usage() {
    echo "Usage: $0 local|vm [--output DIR]"
    echo "  local  open a visible local HTTPS ALTCHA page in Chrome"
    echo "  vm     run the full real Nginx → checker UDS acceptance scenario"
}

mode="${1:-}"
if [[ "$mode" == "" || "$mode" == "-h" || "$mode" == "--help" ]]; then usage; exit 0; fi
shift
while (($#)); do
    case "$1" in
        --output) run_dir="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

mkdir -p "$run_dir"
case "$mode" in
    local)
        command -v openssl >/dev/null || { echo "missing dependency: openssl" >&2; exit 2; }
        [[ -x /usr/bin/google-chrome || -n "${CHROME_PATH:-}" ]] || { echo "missing dependency: Google Chrome" >&2; exit 2; }
        command -v node >/dev/null || { echo "missing dependency: node" >&2; exit 2; }
        (cd "$root_dir" && SOFTBLOCK_RUN_DIR="$run_dir" node tests/integration/softblock/challenge_demo.mjs)
        ;;
    vm)
        (cd "$root_dir" && bash tests/integration/softblock/run.sh --scenario nginx-uds --output "$run_dir")
        echo "VM/UDS demo report: $run_dir/progress.md and $run_dir/results.json"
        ;;
    *) echo "unknown mode: $mode" >&2; usage >&2; exit 2 ;;
esac
