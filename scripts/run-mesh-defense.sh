#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ROOT}/deploy/.env"
LOG_DIR="${ROOT}/logs"
STATE_DIR="/tmp/sentinelmesh"

mkdir -p "$LOG_DIR"
mkdir -p "$STATE_DIR"/{audit,outbox,quarantine,policy,snapshots,sandbox-staging}

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "$ENV_FILE"
  set +a
fi

echo "=================================================="
echo "    SENTINELMESH BLUE TEAM DEFENSE PLATFORM       "
echo "=================================================="

# Export standard keys if not defined
export SENTINELMESH_API_KEY="${CONTROL_PLANE_TO_HOST_AGENT_KEY:-860ecb248dd49ff6672079e8cb38165140e5915390c8c7a0e53e473ac90cc31c}"
export POLICY_SIGNING_KEY="${SENTINELMESH_POLICY_SIGNING_KEY:-797282ea9e056a2df511f1a7d1adcbd7671894b1db8c38540c04b74e637b31cc}"
export CONTROL_PLANE_API_KEY="${DETECTION_ENGINE_KEY:-f6a834823e964cc7924b127783de1a8374e907da90fcc10e3801f93657d22cd1}"
export LLM_API_KEY="${LLM_ORCHESTRATION_KEY:-27b1392d6a26234435b4e0c36179ff59604c4b04d9a3ced5d79a89179b6e68a8}"

# Ensure PATH includes java, go, pip, python binaries
export PATH="/home/sohan-vm/.config/Antigravity/bin:/snap/bin:$PATH"

# 1. Start Control Plane (Spring Boot)
echo "[1/4] Starting Control Plane (port 8080)..."
if ! pgrep -f "control-plane-0.1.0-SNAPSHOT.jar" >/dev/null; then
  SENTINELMESH_AUDIT_LOG_PATH="${STATE_DIR}/audit/control-plane-audit.log" \
  SENTINELMESH_HOST_REGISTRY="sentinelmesh-host=http://127.0.0.1:9090" \
  SENTINELMESH_LLM_URL="http://127.0.0.1:8090" \
  SENTINELMESH_LLM_API_KEY="$LLM_API_KEY" \
  SENTINELMESH_POLICY_SIGNING_KEY="$POLICY_SIGNING_KEY" \
  SENTINELMESH_API_KEYS="detection-engine:${CONTROL_PLANE_API_KEY},llm-orchestration:${LLM_API_KEY},security-automation:${SECURITY_AUTOMATION_KEY:-sec-key}" \
  nohup java -jar "${ROOT}/control-plane/target/control-plane-0.1.0-SNAPSHOT.jar" \
    > "${LOG_DIR}/control-plane.log" 2>&1 &
fi

# 2. Start Host Agent (Go)
echo "[2/4] Starting Host Agent (port 9090)..."
if ! pgrep -f "sentinelmesh-host-agent" >/dev/null; then
  LISTEN_ADDR="0.0.0.0:9090" \
  SENTINELMESH_API_KEY="$SENTINELMESH_API_KEY" \
  SENTINELMESH_POLICY_SIGNING_KEY="$POLICY_SIGNING_KEY" \
  QUARANTINE_DIR="${STATE_DIR}/quarantine" \
  SANDBOX_STAGING_DIR="${STATE_DIR}/sandbox-staging" \
  SNAPSHOT_DIR="${STATE_DIR}/snapshots" \
  POLICY_PATH="${STATE_DIR}/policy/current.json" \
  nohup "${ROOT}/host-agent/bin/sentinelmesh-host-agent" \
    > "${LOG_DIR}/host-agent.log" 2>&1 &
fi

# 3. Start LLM Orchestration (Python Flask)
echo "[3/4] Starting LLM Orchestration (port 8090)..."
if ! pgrep -f "llm-orchestration/app.py" >/dev/null; then
  CONTROL_PLANE_URL="http://127.0.0.1:8080" \
  CONTROL_PLANE_API_KEY="$LLM_API_KEY" \
  SENTINELMESH_API_KEY="${CONTROL_PLANE_TO_LLM_KEY:-a6492b57ceb4824f4d8387ca009ffff0a8b72e116cbdef3fc3fcbe4307d46790}" \
  OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-http://192.168.122.1:11434}" \
  NVIDIA_API_KEY="${NVIDIA_API_KEY:-}" \
  nohup python3 "${ROOT}/llm-orchestration/app.py" \
    > "${LOG_DIR}/llm-orchestration.log" 2>&1 &
fi

# 4. Start Detection Engine (Go Hot-Path Detector)
echo "[4/4] Starting Detection Engine (port 8766 ingress, 2112 metrics)..."
if ! pgrep -f "sentinelmesh-detector" >/dev/null; then
  (
    cd "${ROOT}/detection-engine"
    LOCAL_AUDIT_LOG_PATH="${STATE_DIR}/audit/audit.log" \
    INCIDENT_SPOOL_DIR="${STATE_DIR}/outbox" \
    QUARANTINE_DIR="${STATE_DIR}/quarantine" \
    POLICY_PATH="${STATE_DIR}/policy/current.json" \
    CONTROL_PLANE_URL="http://127.0.0.1:8080" \
    CONTROL_PLANE_API_KEY="$CONTROL_PLANE_API_KEY" \
    POLICY_SIGNING_KEY="$POLICY_SIGNING_KEY" \
    FALCO_HTTP_ADDR="0.0.0.0:8766" \
    FALCO_HTTP_PATH="/falco/events" \
    METRICS_ADDR="0.0.0.0:2112" \
    RESPONSE_MODE="${RESPONSE_MODE:-enforce}" \
    nohup ./bin/sentinelmesh-detector \
      > "${LOG_DIR}/detector.log" 2>&1 &
  )
fi

echo ""
echo "Waiting for services to become healthy..."

for i in $(seq 1 30); do
  cp_ok=0
  ha_ok=0
  llm_ok=0
  det_ok=0

  curl -fsS http://127.0.0.1:8080/actuator/health >/dev/null 2>&1 && cp_ok=1 || true
  curl -fsS http://127.0.0.1:9090/healthz >/dev/null 2>&1 && ha_ok=1 || true
  curl -fsS http://127.0.0.1:8090/healthz >/dev/null 2>&1 && llm_ok=1 || true
  curl -fsS http://127.0.0.1:2112/healthz >/dev/null 2>&1 && det_ok=1 || true

  if [[ $cp_ok -eq 1 && $ha_ok -eq 1 && $llm_ok -eq 1 && $det_ok -eq 1 ]]; then
    echo "All SentinelMesh services are ONLINE and HEALTHY!"
    echo ""
    echo "=================================================="
    echo "Service Status:"
    echo " - Control Plane:       http://0.0.0.0:8080  (Health: /actuator/health)"
    echo " - Host Agent:          http://0.0.0.0:9090  (Health: /healthz)"
    echo " - LLM Orchestrator:    http://0.0.0.0:8090  (Health: /healthz)"
    echo " - Detection Engine:    http://0.0.0.0:8766  (Events: /falco/events, Metrics: :2112/metrics)"
    echo "=================================================="
    echo "Virtual Machine IP:     192.168.122.120"
    echo "Logs directory:         ${LOG_DIR}/"
    echo "=================================================="
    echo "SentinelMesh defense is running in the background..."
    wait
  fi
  sleep 1
done

echo "Warning: Some services may still be initializing. Check logs in ${LOG_DIR}/"
