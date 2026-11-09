#!/usr/bin/env bash
# Runs the full feedback loop locally: vulnerable agent (gate FAILS) -> hardened agent (gate PASSES).
set -u
cd "$(dirname "$0")/.."
export AGENTSEC_CLIENT_SECRET=${AGENTSEC_CLIENT_SECRET:-demo-secret}
PY=${PYTHON:-python3}

for MODE in vulnerable hardened; do
  echo; echo "################ Deploying test agent: $MODE ################"
  $PY demo/stack.py --mode "$MODE" > "/tmp/agentsec-stack-$MODE.log" 2>&1 &
  PID=$!
  for _ in $(seq 1 30); do curl -sf -o /dev/null http://127.0.0.1:8003/openapi.json && break; sleep 0.2; done
  agentsec scan examples/target.yaml --output "report-$MODE.json" --markdown "summary-$MODE.md"
  echo "exit code: $?"
  kill "$PID"; wait "$PID" 2>/dev/null
done
