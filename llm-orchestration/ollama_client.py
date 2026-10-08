"""Bounded local Ollama client. This layer is downstream-only and may fail
without affecting P0 containment."""
import os
import time
import requests

class OllamaClient:
    def __init__(self, base_url: str | None = None):
        self.base_url = (base_url or os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")).rstrip("/")
        self.connect_timeout = float(os.environ.get("OLLAMA_CONNECT_TIMEOUT", "2"))
        self.read_timeout = float(os.environ.get("OLLAMA_READ_TIMEOUT", "120"))
        self.retries = max(0, int(os.environ.get("OLLAMA_RETRIES", "2")))

    def generate(self, model: str, prompt: str, system: str | None = None, timeout: int | None = None) -> str:
        payload = {"model": model, "prompt": prompt, "stream": False}
        if system: payload["system"] = system
        total = timeout or int(self.read_timeout)
        last = None
        for attempt in range(self.retries + 1):
            try:
                resp = requests.post(f"{self.base_url}/api/generate", json=payload,
                                     timeout=(self.connect_timeout, total))
                resp.raise_for_status()
                data = resp.json()
                result = data.get("response", "")
                if not isinstance(result, str) or not result.strip():
                    raise RuntimeError("Ollama returned an empty response")
                return result
            except (requests.RequestException, ValueError, RuntimeError) as exc:
                last = exc
                if attempt < self.retries:
                    time.sleep(0.25 * (2 ** attempt))
        raise RuntimeError(f"ollama generation failed after {self.retries + 1} attempt(s): {last}")
