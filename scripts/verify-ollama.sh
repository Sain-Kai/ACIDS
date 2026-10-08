#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ROOT}/deploy/.env"
if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "$ENV_FILE"
  set +a
fi
BASE="${OLLAMA_BASE_URL:-http://127.0.0.1:11434}"
RCA="${SENTINELMESH_RCA_MODEL:-qwen2.5:14b}"
PATCH="${SENTINELMESH_PATCH_MODEL:-qwen2.5-coder:14b}"
JUDGE="${SENTINELMESH_JUDGE_MODEL:-qwen2.5:14b}"
command -v curl >/dev/null 2>&1 || { echo "ERROR: curl is required." >&2; exit 1; }
json="$(curl -fsS --max-time 5 "${BASE%/}/api/tags")" || { echo "ERROR: Ollama is unreachable at $BASE" >&2; exit 1; }
python3 -c '
import json, sys
wanted=set(sys.argv[1:])
data=json.loads(sys.stdin.read())
have={m.get("name") for m in data.get("models", []) if isinstance(m, dict)}
missing=sorted(wanted-have)
if missing:
    print("ERROR: missing Ollama model(s): " + ", ".join(missing), file=sys.stderr)
    sys.exit(1)
print("Ollama model prerequisites present: " + ", ".join(sorted(wanted)))
' "$RCA" "$PATCH" "$JUDGE" <<<"$json"
