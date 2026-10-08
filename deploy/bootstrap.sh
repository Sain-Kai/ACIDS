#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ROOT}/deploy/.env"
STACK_FILE="${STACK_FILE:-${ROOT}/deploy/docker-compose.prod.yml}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "ERROR: SentinelMesh protected-host deployment requires Linux." >&2
  exit 1
fi
for cmd in openssl docker python3 go clang bpftool ip; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: missing required command: $cmd" >&2; exit 1; }
done

if [[ ! -f "$ENV_FILE" ]]; then
  cp "$ROOT/deploy/.env.example" "$ENV_FILE"
fi

python3 - "$ENV_FILE" <<'PY'
from pathlib import Path
import secrets, sys
p=Path(sys.argv[1])
s=p.read_text()
keys=[
"POSTGRES_PASSWORD","CONTROL_PLANE_DB_PASSWORD","DETECTION_ENGINE_KEY",
"LLM_ORCHESTRATION_KEY","SECURITY_AUTOMATION_KEY","CONTROL_PLANE_TO_LLM_KEY",
"CONTROL_PLANE_TO_HOST_AGENT_KEY","SENTINELMESH_POLICY_SIGNING_KEY"
]
values={}
for line in s.splitlines():
    if line and not line.lstrip().startswith('#') and '=' in line:
        k,v=line.split('=',1)
        if k in keys:
            values[k]=v
for k in keys:
    if values.get(k) in ('REPLACE_ME','CHANGE_ME','CHANGE-ME',''):
        values[k]=secrets.token_hex(32)
lines=[]
for line in s.splitlines():
    if line and not line.lstrip().startswith('#') and '=' in line:
        k,v=line.split('=',1)
        if k in values:
            line=f"{k}={values[k]}"
    if line.startswith('SENTINELMESH_API_KEYS='):
        line='SENTINELMESH_API_KEYS=' + ','.join([
            'detection-engine:'+values['DETECTION_ENGINE_KEY'],
            'llm-orchestration:'+values['LLM_ORCHESTRATION_KEY'],
            'security-automation:'+values['SECURITY_AUTOMATION_KEY'],
        ])
    lines.append(line)
p.write_text('\n'.join(lines)+'\n')
PY
chmod 600 "$ENV_FILE"

# Bind the deployment to one deterministic host identity. Multi-NIC hosts should
# override SENTINELMESH_HOST_IP in deploy/.env with the intended management/data IP.
set -a
source "$ENV_FILE"
set +a
if [[ -z "${SENTINELMESH_HOST_IP:-}" ]]; then
  detected_ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="src"){print $(i+1); exit}}')" || detected_ip=""
  if [[ -z "$detected_ip" ]]; then
    detected_ip="$(hostname -I 2>/dev/null | tr ' ' '\n' | awk 'NF{print; exit}')" || detected_ip=""
  fi
  [[ -n "$detected_ip" ]] || { echo "ERROR: cannot determine SENTINELMESH_HOST_IP; set it explicitly in deploy/.env" >&2; exit 1; }
  python3 - "$ENV_FILE" "$detected_ip" <<'PYIP'
from pathlib import Path
import sys
p=Path(sys.argv[1]); ip=sys.argv[2]
lines=p.read_text().splitlines()
out=[]; found=False
for line in lines:
    if line.startswith("SENTINELMESH_HOST_IP="):
        out.append("SENTINELMESH_HOST_IP="+ip); found=True
    else: out.append(line)
if not found: out.append("SENTINELMESH_HOST_IP="+ip)
p.write_text("\n".join(out)+"\n")
PYIP
  chmod 600 "$ENV_FILE"
  export SENTINELMESH_HOST_IP="$detected_ip"
fi

# Run the full host preflight after secrets exist so configured sandbox/runtime checks are authoritative.
"$ROOT/deploy/doctor.sh"

# Generate native eBPF bindings against the target kernel before compose builds detection-engine.
"$ROOT/scripts/build-native.sh"

# Render first so errors surface before any service is started.
set -a
source "$ENV_FILE"
set +a
docker compose --env-file "$ENV_FILE" -f "$STACK_FILE" config >/dev/null

echo "Bootstrap prerequisites and compose configuration validated."
echo "Start with: docker compose --env-file \"$ENV_FILE\" -f \"$STACK_FILE\" up -d --build"
