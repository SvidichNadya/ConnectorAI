"""URL normalisation and scope. All URL handling in DCPM goes through normalize_url()."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import quote, unquote, urljoin, urlsplit

from ..errors import DCPMError

_PATH_SAFE = "/%:@!$&'()*+,;=-._~"
_QUERY_SAFE = "/?:@!$&'()*+,;=-._~%"
_TRACKING_EXACT = frozenset({"fbclid", "gclid", "dclid", "msclkid", "mc_cid", "mc_eid", "yclid", "_hsenc", "_hsmi", "igshid"})
_BAD_CHARS = re.compile(r"[\x00-\x20\x7f\\]")
_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
MAX_URL_LENGTH = 4096
DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class NormalizedUrl:
    url: str       # what we request (tracking params stripped, canonical form)
    key: str       # dedup identity (query params sorted)
    scheme: str
    host: str
    port: int
    target: str    # request-target: path[?query]


def _invalid(msg: str) -> DCPMError:
    return DCPMError("INVALID_URL", msg)


def _remove_dot_segments(path: str) -> str:
    out: list[str] = []
    segs = path.split("/")
    last = len(segs) - 1
    for i, s in enumerate(segs):
        if s == ".":
            if i == last:
                out.append("")
            continue
        if s == "..":
            if len(out) > 1:
                out.pop()
            if i == last:
                out.append("")
            continue
        out.append(s)
    res = "/".join(out)
    return res if res.startswith("/") else "/" + res


def normalize_url(url: str, base: str | None = None, *, strip_tracking: bool = True) -> NormalizedUrl:
    if not isinstance(url, str):
        raise _invalid("URL must be a string")
    url = url.strip()
    if base:
        try:
            url = urljoin(base, url)
        except ValueError:
            raise _invalid("cannot resolve URL") from None
    if not url or len(url) > MAX_URL_LENGTH:
        raise _invalid("URL is empty or too long")
    if _BAD_CHARS.search(url):
        raise _invalid("URL contains control characters, whitespace or backslash")
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in DEFAULT_PORTS:
            raise _invalid("only http and https URLs are supported")
        if "@" in parts.netloc:
            raise _invalid("credentials inside URLs are not allowed")
        host = parts.hostname
        port = parts.port
    except ValueError:
        raise _invalid("malformed URL") from None
    if not host:
        raise _invalid("URL has no host")
    host = host.rstrip(".")
    if not host or "%" in host:
        raise _invalid("invalid host")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise _invalid("invalid host name") from None
    if port is not None and not (1 <= port <= 65535):
        raise _invalid("invalid port")
    eff_port = port or DEFAULT_PORTS[scheme]
    host_part = f"[{host}]" if ":" in host else host
    netloc = host_part if eff_port == DEFAULT_PORTS[scheme] else f"{host_part}:{eff_port}"

    path = quote(_remove_dot_segments(parts.path or "/"), safe=_PATH_SAFE)

    kept: list[str] = []
    for pair in parts.query.split("&"):
        if not pair:
            continue
        name = unquote(pair.split("=", 1)[0]).lower()
        if strip_tracking and (name.startswith("utm_") or name in _TRACKING_EXACT):
            continue
        kept.append(quote(pair, safe=_QUERY_SAFE))
    fetch_q = "&".join(kept)
    key_q = "&".join(sorted(kept))
    target = path + (f"?{fetch_q}" if fetch_q else "")
    return NormalizedUrl(
        url=f"{scheme}://{netloc}{target}",
        key=f"{scheme}://{netloc}{path}" + (f"?{key_q}" if key_q else ""),
        scheme=scheme, host=host, port=eff_port, target=target,
    )


def normalize_domain(value: str) -> str:
    if not isinstance(value, str):
        raise DCPMError("VALIDATION_ERROR", "domain must be a string")
    d = value.strip().lower().rstrip(".")
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError:
        raise DCPMError("VALIDATION_ERROR", f"invalid domain {value!r}") from None
    try:
        return str(ipaddress.ip_address(d.strip("[]")))   # an IP literal is a valid (exact-match) scope entry
    except ValueError:
        pass
    if not _DOMAIN_RE.match(d):
        raise DCPMError("VALIDATION_ERROR", f"invalid or too broad domain {value!r} (need at least two labels)")
    return d


@dataclass(frozen=True)
class Scope:
    """Domains a source may touch. A host is in scope if it equals or is a subdomain of an entry."""
    allowed_domains: tuple[str, ...]

    def allows(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        return any(host == d or host.endswith("." + d) for d in self.allowed_domains)

    @classmethod
    def parse(cls, domains: list[str]) -> "Scope":
        if not isinstance(domains, list) or not domains or len(domains) > 20:
            raise DCPMError("VALIDATION_ERROR", "scope.allowed_domains must be a list of 1..20 domains")
        seen: list[str] = []
        for d in domains:
            nd = normalize_domain(d)
            if nd not in seen:
                seen.append(nd)
        return cls(tuple(seen))


def origin_of(nu: NormalizedUrl) -> str:
    host = f"[{nu.host}]" if ":" in nu.host else nu.host
    return f"{nu.scheme}://{host}" + ("" if nu.port == DEFAULT_PORTS[nu.scheme] else f":{nu.port}")
