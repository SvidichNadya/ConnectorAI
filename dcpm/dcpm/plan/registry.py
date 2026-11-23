"""Operation Registry (ТЗ §6.5). The only things a plan may ask the runtime to do.

All MVP operations are read-only (effects == ("read",)). Anything with side effects is
rejected by the validator until a policy for it exists.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

PATH_PATTERN = r"[A-Za-z0-9_.\-]{0,128}"
PARAM_PATTERN = r"[A-Za-z_][A-Za-z0-9_.\-\[\]]{0,63}"

LITERAL_TYPES = ("url", "url_list", "int", "bool", "string")
REF_ONLY_TYPES = ("response", "response_list", "document", "extraction_list", "semantic_summary")


@dataclass(frozen=True)
class Param:
    name: str
    type: str
    required: bool = False
    default: Any = None
    min: int | None = None
    max: int | None = None
    policy_max: str | None = None          # Policy attribute that caps this value
    choices: tuple[str, ...] | None = None
    pattern: str | None = None
    max_len: int = 256


@dataclass(frozen=True)
class Output:
    name: str
    type: str


@dataclass(frozen=True)
class OperationSpec:
    type: str
    version: str
    description: str
    inputs: tuple[Param, ...]
    outputs: tuple[Output, ...]
    effects: tuple[str, ...] = ("read",)
    security_class: str = "network_read"

    def param(self, name: str) -> Param | None:
        return next((p for p in self.inputs if p.name == name), None)

    def output(self, name: str) -> Output | None:
        return next((o for o in self.outputs if o.name == name), None)


def _ops() -> dict[str, OperationSpec]:
    ops = [
        OperationSpec("http.fetch", "1.0", "GET one URL (in scope, SSRF-checked, robots-aware).",
                      (Param("url", "url", required=True),), (Output("response", "response"),)),
        OperationSpec("http.fetch_many", "1.0", "GET many URLs sequentially with per-domain throttling.",
                      (Param("urls", "url_list", required=True),
                       Param("max_items", "int", default=100, min=1, policy_max="max_resources")),
                      (Output("responses", "response_list"),)),
        OperationSpec("html.parse", "1.0", "Parse a fetched HTML response into a document model.",
                      (Param("response", "response", required=True),), (Output("document", "document"),),
                      security_class="local_parse"),
        OperationSpec("html.extract_links", "1.0", "In-scope absolute links of a parsed document.",
                      (Param("document", "document", required=True),), (Output("urls", "url_list"),),
                      security_class="local_parse"),
        OperationSpec("sitemap.collect", "1.0", "Collect page URLs from a sitemap (follows sitemap indexes, bounded).",
                      (Param("url", "url", required=True),
                       Param("max_urls", "int", default=1000, min=1, policy_max="max_sitemap_urls")),
                      (Output("urls", "url_list"),)),
        OperationSpec("feed.collect", "1.0", "Collect item URLs from an RSS/Atom feed.",
                      (Param("url", "url", required=True),
                       Param("max_urls", "int", default=200, min=1, policy_max="max_resources")),
                      (Output("urls", "url_list"),)),
        OperationSpec("crawl.recursive", "1.0", "Budgeted breadth-first resource discovery with dedup and cycle protection.",
                      (Param("seeds", "url_list", required=True),
                       Param("max_depth", "int", default=2, min=0, policy_max="max_depth"),
                       Param("max_resources", "int", default=100, min=1, policy_max="max_resources"),
                       Param("follow_attachments", "bool", default=True)),
                      (Output("responses", "response_list"),)),
        OperationSpec("rest.paginate", "1.0", "Walk a paginated JSON API (GET only).",
                      (Param("url", "url", required=True),
                       Param("pagination", "string", default="auto", choices=("auto", "none", "link_header", "next_link", "cursor", "page")),
                       Param("items_path", "string", default="", pattern=PATH_PATTERN),
                       Param("next_path", "string", default="", pattern=PATH_PATTERN),
                       Param("cursor_param", "string", default="cursor", pattern=PARAM_PATTERN),
                       Param("page_param", "string", default="page", pattern=PARAM_PATTERN),
                       Param("max_pages", "int", default=10, min=1, policy_max="max_rest_pages")),
                      (Output("responses", "response_list"),)),
        OperationSpec("content.extract", "1.0", "Detect real format and extract text/structure (HTML, JSON, CSV, text, PDF).",
                      (Param("responses", "response_list", required=True),),
                      (Output("extractions", "extraction_list"),), security_class="local_parse"),
        OperationSpec("semantic.process", "1.0",
                      "Identify the subject domain, extract domain-relevant facts/entities/relationships with "
                      "verified evidence, resolve entities against existing ones, and reconcile conflicting assertions.",
                      (Param("extractions", "extraction_list", required=True),),
                      (Output("summary", "semantic_summary"),), security_class="local_model"),
    ]
    return {o.type: o for o in ops}


REGISTRY: dict[str, OperationSpec] = _ops()


def catalogue() -> list[dict[str, Any]]:
    """Machine-readable description handed to the planner (no secrets, no source data)."""
    out = []
    for o in REGISTRY.values():
        out.append({
            "type": o.type, "description": o.description,
            "inputs": [{"name": p.name, "type": p.type, "required": p.required, "default": p.default,
                        "choices": list(p.choices) if p.choices else None, "min": p.min} for p in o.inputs],
            "outputs": [{"name": x.name, "type": x.type} for x in o.outputs],
        })
    return out
