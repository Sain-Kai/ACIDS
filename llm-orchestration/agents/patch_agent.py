"""Produces a machine-validated defensive patch manifest. The model may
propose text, but deployment only accepts the constrained JSON schema below."""
import ipaddress
import json
import os
from dataclasses import dataclass
from ollama_client import OllamaClient
from agents.rca_agent import RCAReport

DEFAULT_MODEL = os.environ.get("SENTINELMESH_PATCH_MODEL", "qwen2.5-coder:14b")
ALLOWED_KINDS = {"BLOCK_IP", "COMMAND_PATTERN"}
MAX_PATCHES = 8
MAX_VALUE_LENGTH = 200

SYSTEM_PROMPT = (
    "You are a defensive patch designer. Return ONLY JSON with this schema:\n"
    '{"patches":[{"kind":"BLOCK_IP|COMMAND_PATTERN","value":"..."}]} '
    "\nUse the smallest narrowly-scoped safe change. Never disable security controls. "
    "Prefer BLOCK_IP for a confirmed malicious remote IPv4 or COMMAND_PATTERN for a "
    "confirmed malicious command substring. Threshold changes are not permitted."
)

@dataclass
class PatchProposal:
    proposed_change: str
    justification: str
    raw_model_output: str
    manifest: dict


def validate_manifest(manifest: object) -> dict:
    if not isinstance(manifest, dict):
        raise ValueError("patch manifest must be a JSON object")
    patches = manifest.get("patches")
    if not isinstance(patches, list) or not patches:
        raise ValueError("patch manifest has no patches")
    if len(patches) > MAX_PATCHES:
        raise ValueError(f"patch manifest contains too many patches (max {MAX_PATCHES})")

    normalized = []
    seen = set()
    for index, patch in enumerate(patches):
        if not isinstance(patch, dict):
            raise ValueError(f"patch {index} must be an object")
        if set(patch.keys()) != {"kind", "value"}:
            raise ValueError(f"patch {index} must contain only kind and value")
        kind = str(patch.get("kind", "")).strip().upper()
        value = patch.get("value")
        if kind not in ALLOWED_KINDS:
            raise ValueError(f"unsupported patch kind: {kind or '<empty>'}")
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"patch {index} value must be a non-empty string")
        value = value.strip()
        if len(value) > MAX_VALUE_LENGTH or "\x00" in value or "\r" in value or "\n" in value:
            raise ValueError(f"patch {index} value contains unsafe characters or is too long")
        if kind == "BLOCK_IP":
            try:
                ip = ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValueError(f"patch {index} BLOCK_IP is not a valid IP") from exc
            if ip.version != 4 or ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_reserved:
                raise ValueError(f"patch {index} BLOCK_IP is not an acceptable routable IPv4 address")
        elif kind == "COMMAND_PATTERN":
            # This field is a literal substring, not executable shell text.
            # Reject control/meta separators that would turn it into a
            # surprising command-level instruction later if the policy format
            # is ever reused by a different actuator.
            if any(ch in value for ch in ["\x00", "\n", "\r"]):
                raise ValueError(f"patch {index} COMMAND_PATTERN contains control characters")
        item = {"kind": kind, "value": value}
        key = (kind, value)
        if key not in seen:
            normalized.append(item)
            seen.add(key)

    return {"patches": normalized}


class PatchAgent:
    def __init__(self, client: OllamaClient | None = None, model: str = DEFAULT_MODEL):
        self.client = client or OllamaClient()
        self.model = model

    def propose(self, rca: RCAReport) -> PatchProposal:
        output = self.client.generate(
            self.model,
            f"Root-cause report:\n{rca.summary}\nReturn the defensive patch manifest JSON.",
            system=SYSTEM_PROMPT,
        )
        start, end = output.find("{"), output.rfind("}")
        if start < 0 or end <= start:
            raise ValueError("patch model did not return JSON")
        manifest = validate_manifest(json.loads(output[start:end + 1]))
        return PatchProposal(
            proposed_change=json.dumps(manifest, separators=(",", ":"), sort_keys=True),
            justification="structured defensive manifest",
            raw_model_output=output,
            manifest=manifest,
        )
