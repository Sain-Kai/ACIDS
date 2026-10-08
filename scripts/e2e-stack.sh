#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ROOT}/deploy/.env"
if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: deploy/.env missing. Run deploy/bootstrap.sh first." >&2
  exit 1
fi
command -v docker >/dev/null 2>&1 || { echo "ERROR: Docker is required for stack E2E." >&2; exit 1; }
set -a
# shellcheck disable=SC1091
. "$ENV_FILE"
set +a
# E2E is destructive only to the disposable Compose stack; the detector remains deterministic.
export RESPONSE_MODE=dry-run
COMPOSE=(docker compose --env-file "$ENV_FILE" -f "$ROOT/deploy/docker-compose.prod.yml")
cleanup(){ "${COMPOSE[@]}" down --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
"${COMPOSE[@]}" config >/dev/null
"${COMPOSE[@]}" up -d --build
for url in \
  http://127.0.0.1:8080/actuator/health \
  http://127.0.0.1:8090/healthz \
  http://127.0.0.1:9090/healthz \
  http://127.0.0.1:2112/healthz \
  http://127.0.0.1:9091/-/healthy; do
  echo "checking $url"
  for i in $(seq 1 60); do
    if curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then break; fi
    [[ "$i" == 60 ]] && { echo "ERROR: endpoint did not become healthy: $url" >&2; "${COMPOSE[@]}" ps; "${COMPOSE[@]}" logs --tail=120; exit 1; }
    sleep 2
  done
done
# Exercise the maintained Falco-shaped HTTP ingest contract end-to-end.
# This synthetic event matches the deterministic reverse-shell rule but uses dry-run response mode.
curl -fsS --max-time 5 -X POST 'http://127.0.0.1:8766/falco/events' \
  -H 'Content-Type: application/json' \
  -d '{"time":"2026-10-08T00:00:00Z","rule":"Synthetic Reverse Shell","priority":"Critical","output":"bash -c /dev/tcp/10.0.0.8/443","output_fields":{"proc.pid":"424242","proc.name":"bash","proc.pname":"sshd","user.name":"root","fd.typechar":"4","fd.rip":"10.0.0.8","fd.rport":"443"}}' >/dev/null
for i in $(seq 1 30); do
  if curl -fsS --max-time 2 http://127.0.0.1:2112/metrics | grep -Eq 'sentinelmesh_detections_total[^0-9]*[1-9]'; then break; fi
  [[ "$i" == 30 ]] && { echo 'ERROR: synthetic event was not detected' >&2; exit 1; }
  sleep 1
done

# Prove asynchronous incident delivery reached the persistent control-plane store.
for i in $(seq 1 30); do
  incidents="$(curl -fsS --max-time 2 -H "X-SentinelMesh-Api-Key: ${DETECTION_ENGINE_KEY}" 'http://127.0.0.1:8080/incidents?limit=100' 2>/dev/null || true)"
  if INCIDENTS_JSON="$incidents" python3 -c '
import json, os, sys
items=json.loads(os.environ.get("INCIDENTS_JSON", "[]"))
if any(i.get("actionTaken") == "escalate_to_reclaim" for i in items if isinstance(i, dict)):
    raise SystemExit(0)
raise SystemExit(1)
'; then break; fi
  [[ "$i" == 30 ]] && { echo 'ERROR: incident was not persisted by control-plane' >&2; exit 1; }
  sleep 1
done
printf 'STACK E2E PASS: Falco HTTP contract -> normalization -> deterministic detection -> incident transport -> persistent control-plane.\n' 
