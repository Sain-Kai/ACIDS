#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
python3 scripts/validate-config.py
python3 -m py_compile scripts/verify-audit.py scripts/verify-detector-audit.py
python3 - <<'PYVAL'
import yaml
from pathlib import Path
for f in [Path("deploy/falco/falco.yaml"), Path("deploy/prometheus.yml")]:
    yaml.safe_load(f.read_text())
print("YAML validation passed")
PYVAL

go_major=0
go_minor=0
if command -v go >/dev/null 2>&1; then
  gov="$(go env GOVERSION | sed -E 's/^go([0-9]+)\.([0-9]+).*/\1 \2/')"
  read -r go_major go_minor <<<"$gov"
fi
if (( go_major > 1 || (go_major == 1 && go_minor >= 25) )); then
  cd detection-engine
  go test ./...
  go vet ./...
  go build ./...
  cd "$ROOT"
else
  echo "WARNING: Go 1.25+ is required for the native probe dependency; running source-level/non-native detector checks with Go ${go_major}.${go_minor}." >&2
  if [[ "${CI:-}" == "true" ]]; then
    echo "ERROR: CI requires Go 1.25+; refusing a release with an unsupported toolchain." >&2
    exit 1
  fi
  TMP_DETECTOR_DIR="$(mktemp -d)"
  trap 'rm -rf "${TMP_DETECTOR_DIR:-}"' EXIT
  cp -a detection-engine/. "$TMP_DETECTOR_DIR/"
  printf 'module sentinelmesh/detection-engine\n\ngo 1.23\n' > "$TMP_DETECTOR_DIR/go.mod"
  (cd "$TMP_DETECTOR_DIR" && go test ./... && go vet ./... && go build ./... && go build -o "$TMP_DETECTOR_DIR/sentinelmesh-detector" ./cmd/detector)
  DETECTOR_BIN="$TMP_DETECTOR_DIR/sentinelmesh-detector" bash scripts/e2e-local.sh
fi

(cd host-agent && go test ./... && go vet ./... && go build ./...)

cd "$ROOT"
if command -v mvn >/dev/null 2>&1; then
  (cd control-plane && mvn -B verify)
else
  echo "WARNING: Maven not installed; control-plane compile/test skipped locally." >&2
fi

python3 -m py_compile llm-orchestration/app.py llm-orchestration/orchestrator.py llm-orchestration/ollama_client.py llm-orchestration/agents/*.py

if command -v docker >/dev/null 2>&1; then
  docker compose -f deploy/docker-compose.prod.yml config >/dev/null
  docker compose -f deploy/docker-compose.protected-host.yml config >/dev/null
else
  echo "WARNING: Docker not installed; Compose rendering skipped locally." >&2
fi

echo "Release local verification completed. Native eBPF build remains a target-Linux prerequisite; run scripts/build-native.sh on the deployment/build host."
