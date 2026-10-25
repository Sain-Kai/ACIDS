"""Strict post-containment judge for the constrained patch manifest."""
import json
import os
from dataclasses import dataclass
from ollama_client import OllamaClient
from agents.rca_agent import RCAReport
from agents.patch_agent import PatchProposal, validate_manifest

DEFAULT_MODEL = os.environ.get("SENTINELMESH_JUDGE_MODEL", "qwen2.5:14b")
SYSTEM_PROMPT = (
    "You are a strict security reviewer. Approve only if the proposed JSON patch "
    "is narrowly scoped, defensive, and does not weaken detection/containment. "
    "Respond APPROVE or REJECT on the first line, then rationale."
)

@dataclass
class JudgeVerdict:
    approved: bool
    rationale: str


class SecurityJudge:
    def __init__(self, client: OllamaClient | None = None, model: str = DEFAULT_MODEL):
        self.client = client or OllamaClient()
        self.model = model

    def review(self, rca: RCAReport, patch: PatchProposal) -> JudgeVerdict:
        try:
            manifest = validate_manifest(patch.manifest)
            serialized = json.dumps(manifest, separators=(",", ":"), sort_keys=True)
        except Exception as exc:
            return JudgeVerdict(False, f"REJECT: deterministic manifest validation failed: {exc}")

        # Threshold/shape validation is deterministic; the LLM is asked only
        # for a security-context judgement over an already-safe schema.
        output = self.client.generate(
            self.model,
            f"Root-cause report:\n{rca.summary}\n\nProposed patch manifest:\n{serialized}\n\nReview it.",
            system=SYSTEM_PROMPT,
        ).strip()
        first = output.splitlines()[0].strip().upper() if output else ""
        approved = first == "APPROVE"
        return JudgeVerdict(approved, output or "REJECT: empty judge response")
