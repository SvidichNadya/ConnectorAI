"""LocalLLMClient: the ONLY way any DCPM component talks to a language model.

Trust direction is the opposite of SafeFetcher: SafeFetcher fetches untrusted public sources and
refuses private/internal destinations. This client calls an inference sidecar that is supposed to
run ON THE SAME MACHINE (Ollama / llama.cpp server / LM Studio / vLLM, all OpenAI-chat-compatible)
and refuses to connect anywhere that is not loopback, so a misconfigured base_url can never ship
tenant content to a remote host.

Protocol: POST {base_url}/chat/completions, body {"model", "messages", "temperature", "max_tokens"},
response {"choices":[{"message":{"content": "..."}}]} - the de facto standard every local runtime speaks.
"""
from __future__ import annotations

import http.client
import json
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from ..errors import DCPMError
from ..llmjson import extract_json
from ..security.netguard import is_loopback, system_resolver
from ..security.redact import redact
from .gateway_protocol import ChatGateway

MAX_ANSWER_BYTES = 1_000_000
_DEFAULT_BASE_URL = "http://127.0.0.1:11434/v1"


@dataclass(frozen=True)
class LocalLLMConfig:
    base_url: str = _DEFAULT_BASE_URL
    model: str = ""
    connect_timeout_s: float = 5.0
    read_timeout_s: float = 120.0
    max_retries: int = 1
    retry_base_delay_s: float = 0.5
    temperature: float = 0.0
    max_context_chars: int = 24_000       # caps the *prompt*; keeps a small model's context safe

    def __post_init__(self) -> None:
        if not self.model:
            raise ValueError("LocalLLMConfig.model is required (the model name your local server has loaded)")
        parts = urlsplit(self.base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("LocalLLMConfig.base_url must be an http(s) URL")


class LocalModelUnavailable(DCPMError):
    def __init__(self, message: str, *, retryable: bool = True):
        super().__init__("MODEL_UNAVAILABLE", message)
        self._retryable = retryable

    @property
    def retryable(self) -> bool:  # overrides the catalogue lookup: availability here is call-specific
        return self._retryable


class LocalLLMClient(ChatGateway):
    """Real HTTP client. No weights ship with DCPM; point base_url at your own running server."""

    def __init__(self, config: LocalLLMConfig, *, resolver=system_resolver, clock=time.monotonic):
        self.config, self._resolver, self._clock = config, resolver, clock
        self._lock = threading.Lock()   # local servers are usually single-request; serialise calls

    # ------------------------------------------------------------------ public (ChatGateway)
    def complete_json(self, *, system: str, user: str, max_tokens: int) -> str:
        user = self._truncate(user)
        body = {"model": self.config.model, "temperature": self.config.temperature, "max_tokens": int(max_tokens),
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        return self._post_with_retry(body)

    def complete_json_validated(self, *, system: str, user: str, max_tokens: int, limit: int) -> Any:
        """Call the model and parse its answer as JSON. Raises LocalModelUnavailable on any failure;
        callers decide what "unavailable" means for them (retry, fall back to rules, ask again)."""
        try:
            text = self.complete_json(system=system, user=user, max_tokens=max_tokens)
            return extract_json(text, limit)
        except LocalModelUnavailable:
            raise
        except ValueError as e:
            raise LocalModelUnavailable(f"model answer was not usable JSON: {e}", retryable=False) from None

    def ping(self) -> bool:
        try:
            self._post_with_retry({"model": self.config.model, "max_tokens": 1,
                                   "messages": [{"role": "user", "content": "ping"}]}, retries=0)
            return True
        except DCPMError:
            return False

    # ------------------------------------------------------------------ internals
    def _truncate(self, text: str) -> str:
        limit = self.config.max_context_chars
        return text if len(text) <= limit else text[: limit - 20] + "\n…(truncated)…"

    def _post_with_retry(self, body: dict[str, Any], retries: int | None = None) -> str:
        attempt, limit = 0, self.config.max_retries if retries is None else retries
        last: DCPMError | None = None
        while True:
            with self._lock:
                try:
                    return self._post_once(body)
                except LocalModelUnavailable as e:
                    last = e
            if not last.retryable or attempt >= limit:
                raise last
            attempt += 1
            time.sleep(self.config.retry_base_delay_s * attempt)

    def _post_once(self, body: dict[str, Any]) -> str:
        cfg = self.config
        parts = urlsplit(cfg.base_url)
        host, port = parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)
        try:
            ips = list(dict.fromkeys(self._resolver(host, port)))
        except DCPMError as e:
            raise LocalModelUnavailable(f"local model host did not resolve: {e.message}") from None
        if not ips or not all(is_loopback(a) for a in ips):
            # fails closed: refuses even if only SOME resolved addresses are non-loopback
            raise LocalModelUnavailable(
                "refusing to call a local-model endpoint that does not resolve to loopback "
                "(base_url must point at a server on this machine)", retryable=False)
        payload = json.dumps(body).encode()
        path = parts.path.rstrip("/") + "/chat/completions"
        conn_cls = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
        conn = None
        try:
            conn = conn_cls(ips[0], port, timeout=cfg.connect_timeout_s)
            conn.connect()
            conn.sock.settimeout(cfg.read_timeout_s)
            conn.request("POST", path, body=payload, headers={"Content-Type": "application/json",
                                                               "Content-Length": str(len(payload)), "Connection": "close"})
            resp = conn.getresponse()
            raw = self._read_bounded(resp)
        except LocalModelUnavailable:
            raise
        except (socket.timeout, TimeoutError):
            raise LocalModelUnavailable("local model did not answer in time") from None
        except (http.client.HTTPException, OSError) as e:
            raise LocalModelUnavailable(f"could not reach the local model server ({type(e).__name__}): "
                                        f"is it running at {redact(cfg.base_url)}?") from None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:  # pragma: no cover
                    pass
        if resp.status != 200:
            raise LocalModelUnavailable(f"local model server returned HTTP {resp.status}: {redact(raw[:200].decode('utf-8', 'replace'))}",
                                        retryable=resp.status >= 500 or resp.status == 429)
        try:
            data = json.loads(raw)
            return data["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError):
            raise LocalModelUnavailable("local model server returned an unexpected response shape", retryable=False) from None

    def _read_bounded(self, resp: http.client.HTTPResponse) -> bytes:
        out = bytearray()
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            out += chunk
            if len(out) > MAX_ANSWER_BYTES:
                raise LocalModelUnavailable("local model answer exceeded the size limit", retryable=False)
        return bytes(out)
