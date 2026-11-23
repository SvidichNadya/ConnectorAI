"""Policy: every limit lives here, never hard-coded inside an operation (ТЗ §7.4).

Values are *starting defaults* to be tuned after profiling (ТЗ §8.7).
"""
from __future__ import annotations

from dataclasses import dataclass, fields


@dataclass(frozen=True)
class Policy:
    user_agent: str = "DCPMBot/0.1"
    robots_token: str = "DCPMBot"
    allowed_schemes: tuple[str, ...] = ("http", "https")
    allowed_ports: frozenset[int] | None = frozenset({80, 443})   # None = any port
    # Trusted-network mode for in-house sources. Cloud-metadata / link-local / multicast
    # ranges stay blocked even when this is True.
    allow_private_networks: bool = False
    ca_bundle: str | None = None
    connect_timeout_s: float = 10.0
    read_timeout_s: float = 20.0
    request_deadline_s: float = 60.0
    max_redirects: int = 5
    max_response_bytes: int = 20 * 1024 * 1024
    max_total_bytes: int = 256 * 1024 * 1024
    max_retries: int = 2
    retry_base_delay_s: float = 1.0
    retry_max_delay_s: float = 30.0
    min_request_interval_s: float = 1.0
    max_crawl_delay_s: float = 30.0
    respect_robots: bool = True
    max_operations: int = 50
    max_depth: int = 4
    max_resources: int = 1000
    max_runtime_seconds: int = 3600
    max_links_per_page: int = 500
    max_frontier: int = 20000
    max_out_of_scope_records: int = 1000
    max_plan_bytes: int = 262144
    max_rest_pages: int = 1000
    max_sitemap_urls: int = 50000
    max_extraction_bytes: int = 2 * 1024 * 1024
    pdf_max_pages: int = 500
    pdf_timeout_s: float = 60.0
    pdf_memory_bytes: int = 2 * 1024**3
    max_probes: int = 20

    def __post_init__(self) -> None:
        for f in fields(self):
            v = getattr(self, f.name)
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                continue
            if v < 0 or (v == 0 and f.name not in ("min_request_interval_s", "max_retries", "retry_base_delay_s")):
                raise ValueError(f"Policy.{f.name} must be positive, got {v!r}")
