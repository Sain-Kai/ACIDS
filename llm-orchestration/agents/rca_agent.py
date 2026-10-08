"""Root-cause-analysis agent.

Runs after an incident has already been contained. Never called from the
detection-engine hot path -- only from control-plane, once containment (or
the full reclaim protocol) has already run.
"""
import json
import os
from dataclasses import dataclass

from ollama_client import OllamaClient

DEFAULT_MODEL = os.environ.get("SENTINELMESH_RCA_MODEL", "qwen2.5:14b")

SYSTEM_PROMPT = """You are a security root-cause-analysis assistant for an \
already-contained incident. You are given a normalized event, the \
detection rule(s) that matched, and the containment action already taken. \
Produce a concise root-cause report: what happened, how the attacker \
likely got in or what triggered the rule, what was affected, and how \
confident you are. Do not propose a fix -- that's a separate step. Do not \
speculate beyond what the evidence supports."""


@dataclass
class RCAReport:
    summary: str
    raw_model_output: str


class RCAAgent:
    def __init__(self, client: OllamaClient | None = None, model: str = DEFAULT_MODEL):
        self.client = client or OllamaClient()
        self.model = model

    def analyze(self, incident_context: dict) -> RCAReport:
        prompt = (
            "Incident context (JSON):\n"
            f"{json.dumps(incident_context, sort_keys=True, default=str)}\n\n"
            "Produce the root-cause report described in your instructions."
        )
        output = self.client.generate(self.model, prompt, system=SYSTEM_PROMPT)
        return RCAReport(summary=output.strip(), raw_model_output=output)
