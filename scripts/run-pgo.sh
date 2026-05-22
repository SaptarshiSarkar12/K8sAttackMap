#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(dirname "$0")"
JSON="$(realpath "$SCRIPT_DIR/../testdata/cluster-state.json")"
BINARY="$(realpath "${1:-./target/K8sAttackMap}")"

echo ">> Binary resolved to: $BINARY"
echo ">> JSON resolved to: $JSON"

if [[ ! -f "$BINARY" ]]; then
  echo "Usage: $0 <path-to-instrumented-binary>"
  exit 1
fi

# Helper function to print formatted timestamps
log_info() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

run() {
  "$BINARY" "$@" --no-color > /dev/null 2>&1 || true
}

log_info ">> Phase 1: Feature Coverage (Error paths, Formats, Help) started."
run --help
run --version
run -k /dev/null
run -k "$JSON" -s "Pod:default:nonexistent" -t "Secret:default:nonexistent"
run -k "$JSON" --max-hops abc
run -k "$JSON" -o html,pdf --verbose
log_info ">> Phase 1 completed."

log_info ">> Phase 2: Graph Algorithm Warmup (PGO Hot Paths) started."
TOTAL_ITERATIONS=20

for i in $(seq 1 $TOTAL_ITERATIONS); do
  log_info "   -> Running traversal iteration $i of $TOTAL_ITERATIONS..."
  
  run -k "$JSON" -s "Pod:default:web" -t "Secret:default:db-credentials" -m 5 -o html
  
  run -k "$JSON" -s "Pod:default:privileged-worker" -t "Node:cluster-scoped:worker-node-1" -m 10
  
  run -k "$JSON" \
    -s "Pod:default:web,ServiceAccount:default:web-sa" \
    -t "Secret:default:tls-cert,ClusterRole:cluster-scoped:cluster-admin-wildcard" \
    --show-all-paths -a
done

log_info ">> Phase 2 completed."

log_info ">> PGO run complete. default.iprof should be generated."
