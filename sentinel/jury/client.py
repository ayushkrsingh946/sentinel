"""OpenAI-compatible inference client with disk caching and retry loops."""

from __future__ import annotations
import hashlib
import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple
import urllib.error
import urllib.request

from sentinel.jury.repair import JSONRepairHarness
from sentinel.jury.schema import Finding


class ModelClient:
    """Client for OpenAI-compatible local or remote LLM endpoints."""

    def __init__(
        self,
        base_url: str = "http://localhost:11434/v1",
        api_key: str = "ollama",
        cache_dir: Path | str = ".sentinel_cache",
        cache_enabled: bool = True,
        timeout: int = 45,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.cache_dir = Path(cache_dir)
        self.cache_enabled = cache_enabled
        self.timeout = timeout
        if self.cache_enabled:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_key(self, model: str, messages: List[Dict[str, str]], temperature: float) -> str:
        payload = json.dumps({"model": model, "messages": messages, "temperature": temperature}, sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _read_cache(self, key: str) -> Optional[str]:
        if not self.cache_enabled:
            return None
        cache_file = self.cache_dir / f"{key}.json"
        if cache_file.exists():
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("response")
            except Exception:
                return None
        return None

    def _write_cache(self, key: str, response: str, model: str) -> None:
        if not self.cache_enabled:
            return
        cache_file = self.cache_dir / f"{key}.json"
        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump({"model": model, "response": response, "timestamp": time.time()}, f)
        except Exception:
            pass

    def chat_completion(
        self,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float = 0.1,
        max_tokens: int = 1500,
    ) -> Tuple[str, float]:
        """Calls /chat/completions endpoint, returning (content, latency_ms)."""
        cache_key = self._get_cache_key(model, messages, temperature)
        cached = self._read_cache(cache_key)
        if cached is not None:
            return cached, 1.0  # Instant cached response

        url = f"{self.base_url}/chat/completions"
        req_data = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
        }
        json_body = json.dumps(req_data).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=json_body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )

        start_time = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                latency_ms = (time.perf_counter() - start_time) * 1000
                res_body = response.read().decode("utf-8")
                parsed = json.loads(res_body)
                content = parsed["choices"][0]["message"]["content"]
                self._write_cache(cache_key, content, model)
                return content, latency_ms
        except urllib.error.URLError as e:
            # Fallback retry without response_format if endpoint doesn't support json_object mode
            req_data.pop("response_format", None)
            json_body = json.dumps(req_data).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=json_body,
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    latency_ms = (time.perf_counter() - start_time) * 1000
                    res_body = response.read().decode("utf-8")
                    parsed = json.loads(res_body)
                    content = parsed["choices"][0]["message"]["content"]
                    self._write_cache(cache_key, content, model)
                    return content, latency_ms
            except Exception as final_err:
                raise ConnectionError(f"Failed to communicate with LLM endpoint at {url}: {final_err}") from final_err
