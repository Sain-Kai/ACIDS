"""Bounded local Ollama client. This layer is downstream-only and may fail
without affecting P0 containment."""
import os
import time
import requests

class OllamaClient:
    def __init__(self, base_url: str | None = None):
        self.base_url = (base_url or os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")).rstrip("/")
        self.nvidia_api_key = os.environ.get("NVIDIA_API_KEY", "").strip()
        self.nvidia_base_url = os.environ.get("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1").rstrip("/")
        self.connect_timeout = float(os.environ.get("OLLAMA_CONNECT_TIMEOUT", "2"))
        self.read_timeout = float(os.environ.get("OLLAMA_READ_TIMEOUT", "120"))
        self.retries = max(0, int(os.environ.get("OLLAMA_RETRIES", "2")))

    def generate(self, model: str, prompt: str, system: str | None = None, timeout: int | None = None) -> str:
        total = timeout or int(self.read_timeout)
        last = None
        for attempt in range(self.retries + 1):
            try:
                if self.nvidia_api_key:
                    nv_model = os.environ.get("NVIDIA_MODEL", model if "/" in model else "meta/llama-3.1-8b-instruct")
                    messages = []
                    if system:
                        messages.append({"role": "system", "content": system})
                    messages.append({"role": "user", "content": prompt})
                    headers = {
                        "Authorization": f"Bearer {self.nvidia_api_key}",
                        "Content-Type": "application/json",
                    }
                    payload = {
                        "model": nv_model,
                        "messages": messages,
                        "temperature": 0.2,
                        "max_tokens": 1024,
                    }
                    resp = requests.post(
                        f"{self.nvidia_base_url}/chat/completions",
                        json=payload,
                        headers=headers,
                        timeout=(self.connect_timeout, total),
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    choices = data.get("choices", [])
                    if not choices:
                        raise RuntimeError("NVIDIA API returned no choices")
                    result = choices[0].get("message", {}).get("content", "")
                    if not isinstance(result, str) or not result.strip():
                        raise RuntimeError("NVIDIA API returned an empty response")
                    return result
                else:
                    payload = {"model": model, "prompt": prompt, "stream": False}
                    if system:
                        payload["system"] = system
                    resp = requests.post(
                        f"{self.base_url}/api/generate",
                        json=payload,
                        timeout=(self.connect_timeout, total),
                    )
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
        raise RuntimeError(f"LLM generation failed after {self.retries + 1} attempt(s): {last}")
