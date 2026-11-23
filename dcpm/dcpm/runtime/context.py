"""Execution context: budgets, throttling, robots.txt, cancellation (ТЗ §7.2)."""
from __future__ import annotations

import random
import threading
import time
import urllib.robotparser
from collections import Counter
from typing import Callable

from ..config import Policy
from ..errors import DCPMError
from ..security.netguard import SafeFetcher
from ..security.urls import NormalizedUrl, Scope, origin_of
from ..storage.blobs import BlobStore
from ..semantic.gateway_protocol import ChatGateway
from ..storage.db import Store

ROBOTS_MAX_BYTES = 512 * 1024


class Stats:
    def __init__(self) -> None:
        self._c: Counter[str] = Counter()
        self._lock = threading.Lock()

    def inc(self, key: str, n: int = 1) -> None:
        with self._lock:
            self._c[key] += n

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._c)


class Budget:
    def __init__(self, max_bytes: int, max_resources: int):
        self.max_bytes, self.max_resources = max_bytes, max_resources
        self.bytes = 0
        self.requests = 0
        self._lock = threading.Lock()

    def consume_request(self) -> None:
        with self._lock:
            if self.requests >= self.max_resources:
                raise DCPMError("BUDGET_EXCEEDED", "resource budget for this run is exhausted")
            self.requests += 1

    def consume_bytes(self, n: int) -> None:
        with self._lock:
            if self.bytes + n > self.max_bytes:
                raise DCPMError("BUDGET_EXCEEDED", "download budget for this run is exhausted")
            self.bytes += n

    def snapshot(self) -> dict[str, int]:
        return {"max_total_bytes": self.max_bytes, "max_resources": self.max_resources,
                "bytes_used": self.bytes, "resources_used": self.requests}


class DomainThrottle:
    """Minimum interval between requests per host (politeness + rate-limit protection)."""

    def __init__(self, sleep: Callable[[float], None], clock: Callable[[], float] = time.monotonic):
        self._sleep, self._clock = sleep, clock
        self._next: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, host: str, interval: float) -> None:
        with self._lock:
            now = self._clock()
            t = max(now, self._next.get(host, 0.0))
            self._next[host] = t + interval
            delay = t - now
        if delay > 0:
            self._sleep(delay)


class RobotsCache:
    """RFC 9309: 2xx -> parse; 4xx -> unavailable => allow all; 5xx/unreachable => disallow all."""

    def __init__(self, safe: SafeFetcher, policy: Policy, scope: Scope, throttle: DomainThrottle):
        self._safe, self._policy, self._scope, self._throttle = safe, policy, scope, throttle
        self._cache: dict[str, tuple[str, urllib.robotparser.RobotFileParser | None]] = {}
        self._lock = threading.Lock()

    def check(self, nu: NormalizedUrl) -> tuple[bool, float]:
        origin = origin_of(nu)
        with self._lock:
            entry = self._cache.get(origin)
        if entry is None:
            entry = self._load(origin, nu)
            with self._lock:
                self._cache[origin] = entry
        mode, rp = entry
        if mode == "allow_all":
            return True, 0.0
        if mode == "disallow_all" or rp is None:
            return False, 0.0
        token = self._policy.robots_token
        delay = rp.crawl_delay(token)
        return rp.can_fetch(token, nu.url), min(float(delay or 0.0), self._policy.max_crawl_delay_s)

    def _load(self, origin: str, nu: NormalizedUrl):
        try:
            self._throttle.wait(nu.host, self._policy.min_request_interval_s)
            raw = self._safe.fetch(origin + "/robots.txt", scope=self._scope, max_bytes=ROBOTS_MAX_BYTES)
        except DCPMError as e:
            if e.code == "CANCELLED":
                raise
            return "disallow_all", None
        if 200 <= raw.status < 300:
            rp = urllib.robotparser.RobotFileParser()
            rp.parse(raw.body.decode("utf-8", "replace").splitlines())
            rp.modified()  # without this, can_fetch() refuses everything
            return "rules", rp
        if 400 <= raw.status < 500:
            return "allow_all", None
        return "disallow_all", None


class RunContext:
    def __init__(self, *, tenant_id: str, source_id: str, run_id: str, store: Store, blobs: BlobStore, policy: Policy,
                 scope: Scope, safe: SafeFetcher, cancel: threading.Event, deadline: float, budget: Budget,
                 clock: Callable[[], float] = time.monotonic, respect_robots: bool = True,
                 llm: "ChatGateway | None" = None, ai_allowed: bool = False):
        self.tenant_id, self.source_id, self.run_id = tenant_id, source_id, run_id
        self.store, self.blobs, self.policy, self.scope, self.safe = store, blobs, policy, scope, safe
        self.cancel, self.deadline, self.budget, self.clock = cancel, deadline, budget, clock
        self.respect_robots = respect_robots and policy.respect_robots
        self.llm, self.ai_allowed = llm, ai_allowed
        self.stats = Stats()
        self.rng = random.Random()
        self.throttle = DomainThrottle(self.sleep, clock)
        self.robots = RobotsCache(safe, policy, scope, self.throttle)
        from .fetcher import RunFetcher  # local import: fetcher needs the context type
        self.fetcher = RunFetcher(self)

    def sleep(self, seconds: float) -> None:
        if self.cancel.wait(max(0.0, seconds)):
            raise DCPMError("CANCELLED", "run was cancelled")

    def check_cancel(self) -> None:
        if self.cancel.is_set():
            raise DCPMError("CANCELLED", "run was cancelled")

    def check_deadline(self) -> None:
        if self.clock() > self.deadline:
            raise DCPMError("BUDGET_EXCEEDED", "run time budget exhausted")

    def read_body(self, resp: dict) -> bytes:
        return self.blobs.get(self.tenant_id, resp["sha256"])
