"""HTTP wrapper around orchestrator.handle_incident.

control-plane's LlmOrchestrationClient POSTs the incident context here
once containment is done; this is the only entrypoint into the LLM layer.
Auth is a shared-secret header (matches control-plane's ApiKeyAuthFilter
pattern) -- proportionate for a service-to-service API that's meant to
sit on a private network alongside control-plane, not be internet-facing.
"""
import hmac
import os
import sys
from typing import Any

from flask import Flask, request, jsonify

from orchestrator import handle_incident

API_KEY_HEADER = "X-SentinelMesh-Api-Key"
API_KEY = os.environ.get("SENTINELMESH_API_KEY")

if not API_KEY:
    # Fail closed, not open: refuse to start rather than silently accept
    # unauthenticated requests to an endpoint that can trigger patch
    # deployment. DEV-ONLY note: set this to a real generated secret
    # (e.g. `openssl rand -hex 32`), matching control-plane's
    # sentinelmesh.security.llm-orchestration-api-key -- never hardcode
    # a real value here or commit one.
    sys.exit("SENTINELMESH_API_KEY must be set -- refusing to start without auth configured")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 << 20


@app.before_request
def check_api_key():
    if request.path == "/healthz":
        return None
    if not hmac.compare_digest(request.headers.get(API_KEY_HEADER, ""), API_KEY):
        return jsonify({"error": f"missing or invalid {API_KEY_HEADER}"}), 401
    return None


@app.post("/handle-incident")
def handle_incident_route():
    try:
        incident_context: Any = request.get_json(force=False, silent=False)
    except Exception:
        return jsonify({"error": "invalid JSON"}), 400
    if not isinstance(incident_context, dict):
        return jsonify({"error": "incident context must be a JSON object"}), 400
    required = ("incident_id", "status")
    missing = [key for key in required if not str(incident_context.get(key, "")).strip()]
    if missing:
        return jsonify({"error": "missing required fields: " + ",".join(missing)}), 400
    if incident_context.get("status") not in {"CONTAINED", "RECLAIM_COMPLETE", "RESOLVED"}:
        # The LLM service may inspect a reclaiming incident only when it is
        # explicitly requested for analysis, but it must never be allowed to
        # turn an unresolved incident into a deployable result. The Python
        # orchestrator enforces the same deployment gate independently.
        incident_context["deployment_gate"] = "blocked_until_post_containment"
    try:
        result = handle_incident(incident_context)
    except Exception as exc:
        app.logger.exception("LLM incident processing failed")
        return jsonify({"error": "LLM processing failed", "detail": str(exc)[:500]}), 503
    return jsonify(result)


@app.get("/healthz")
def healthz():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8090)
