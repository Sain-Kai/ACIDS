"""Ties RCA -> Patch -> Judge together for a single contained incident.

Called by control-plane after containment (or the full reclaim protocol)
has already completed for an incident -- never from the hot path.
"""
import os

import requests

from agents.rca_agent import RCAAgent
from agents.patch_agent import PatchAgent
from agents.security_judge import SecurityJudge

CONTROL_PLANE_URL = os.environ.get("CONTROL_PLANE_URL", "http://localhost:8080")
API_KEY_HEADER = "X-SentinelMesh-Api-Key"
# DEV-ONLY placeholder default -- must match one of the keys in
# control-plane's sentinelmesh.security.api-keys config. Set a real
# generated secret via env var for anything beyond local dev.
CONTROL_PLANE_API_KEY = os.environ.get("CONTROL_PLANE_API_KEY", "").strip()


def handle_incident(incident_context: dict) -> dict:
    status = str(incident_context.get("status", "")).strip()
    if status not in {"CONTAINED", "RECLAIM_COMPLETE", "RESOLVED"}:
        # Analysis may be useful during reclaim, but no result from an
        # unresolved incident can ever be deployed. The caller still gets
        # an RCA so operators can review it.
        incident_context = dict(incident_context)
        incident_context["deployment_gate"] = "blocked_until_post_containment"
    rca = RCAAgent().analyze(incident_context)
    patch = PatchAgent().propose(rca)
    verdict = SecurityJudge().review(rca, patch)

    result = {
        "incident_id": incident_context.get("incident_id"),
        # Threaded through so control-plane's GuardedDeployment can record
        # which rule(s) this patch targets -- CanaryPromotionScheduler
        # uses it to check whether the incident rate for those specific
        # rules actually improved during the canary window, rather than
        # promoting on elapsed time alone.
        "matched_rules": incident_context.get("matched_rules", ""),
        "rca_summary": rca.summary,
        "proposed_change": patch.proposed_change,
        "patch_manifest": patch.manifest,
        "approved": verdict.approved,
        "judge_rationale": verdict.rationale,
    }

    if verdict.approved:
        # LLM analysis can continue while reclaim is isolated/in progress, but
        # autonomous policy deployment is fail-closed until the protected host
        # has reached a post-containment/recovery state. This prevents a model
        # proposal from mutating a host whose reclaim protocol is still blocked
        # on verification or human review.
        safe_to_deploy = incident_context.get("status") in {"CONTAINED", "RECLAIM_COMPLETE", "RESOLVED"}
        if not safe_to_deploy:
            result["deploy_error"] = "guarded deployment blocked until incident reaches CONTAINED, RECLAIM_COMPLETE, or RESOLVED"
            return result
        if not CONTROL_PLANE_API_KEY:
            result["deploy_error"] = "CONTROL_PLANE_API_KEY is required for guarded deployment"
            return result
        try:
            response = requests.post(
                f"{CONTROL_PLANE_URL}/deploy/guarded",
                json=result,
                timeout=5,
                headers={API_KEY_HEADER: CONTROL_PLANE_API_KEY},
            )
            if response.status_code >= 300:
                result["deploy_error"] = f"control-plane /deploy/guarded returned HTTP {response.status_code}: {response.text[:500]}"
        except requests.RequestException as e:
            result["deploy_error"] = str(e)

    return result
