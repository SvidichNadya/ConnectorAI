"""Network Egress Security Gateway (ТЗ §14.2, research §4).

Every outbound request in DCPM goes through SafeFetcher. Guarantees:

* the destination host is resolved ONCE per hop; every resolved address must be allowed
  (mixed public/private answers are rejected);
* the TCP connection is made to that already-validated IP (no second DNS lookup -> no DNS
  rebinding window); TLS still verifies the certificate against the original host name (SNI);
* every redirect hop is re-validated (scheme, port, scope, DNS/IP); https->http is refused;
* only GET/HEAD, fixed header allow-list, never any credentials/cookies;
* response size, decompressed size and wall-clock time are bounded.
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
import zlib
from dataclasses import dataclass, field
from typing import Callable

from ..config import Policy
from ..errors import DCPMError
from .urls import NormalizedUrl, Scope, normalize_url

Resolver = Callable[[str, int], list[str]]

_ALWAYS_BLOCKED = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "100.100.100.200/32",
    "::/128", "fe80::/10", "ff00::/8", "fd00:ec2::/32", "2002::/16", "2001::/32",
    "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
)]
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


def is_loopback(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return bool(ip.is_loopback)


def ip_block_reason(addr: str, allow_private: bool) -> str | None:
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return "unparseable address"
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    for net in _ALWAYS_BLOCKED:
        if ip in net:
            return "reserved, link-local, multicast or cloud-metadata range"
    if ip.is_loopback:
        return None if allow_private else "non-public address"
    if ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_reserved:
        return "reserved address"
    if not allow_private and not ip.is_global:
        return "non-public address"
    return None


def system_resolver(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise DCPMError("NETWORK_ERROR", "DNS resolution failed", details={"host": host}) from None
    except UnicodeError:
        raise DCPMError("INVALID_URL", "invalid host name") from None
    return [i[4][0] for i in infos]


def resolve_and_check(host: str, port: int, policy: Policy, resolver: Resolver) -> list[str]:
    """Return the ordered list of validated IPs for host, or raise SSRF_BLOCKED."""
    try:
        ipaddress.ip_address(host)
        addrs = [host]
    except ValueError:
        addrs = resolver(host, port)
    addrs = list(dict.fromkeys(addrs))
    if not addrs:
        raise DCPMError("NETWORK_ERROR", "host did not resolve", details={"host": host})
    for a in addrs:
        reason = ip_block_reason(a, policy.allow_private_networks)
        if reason:
            raise DCPMError("SSRF_BLOCKED", f"destination not allowed ({reason})", details={"host": host})
    return addrs


@dataclass
class RawResponse:
    url: str
    final_url: str
    status: int
    headers: dict[str, str]
    body: bytes
    redirect_chain: list[str] = field(default_factory=list)
    elapsed_s: float = 0.0

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


def _connect_pinned(ips: list[str], port: int, connect_timeout: float, read_timeout: float) -> socket.socket:
    last: OSError | None = None
    for ip in ips:
        try:
            s = socket.create_connection((ip, port), timeout=connect_timeout)
            s.settimeout(read_timeout)
            return s
        except OSError as e:
            last = e
    raise last or OSError("no usable address")


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, ips, connect_timeout, read_timeout):
        super().__init__(host, port, timeout=connect_timeout)
        self._ips, self._ct, self._rt = ips, connect_timeout, read_timeout

    def connect(self):
        self.sock = _connect_pinned(self._ips, self.port, self._ct, self._rt)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, ips, ctx, connect_timeout, read_timeout):
        super().__init__(host, port, timeout=connect_timeout, context=ctx)
        self._ips, self._ct, self._rt = ips, connect_timeout, read_timeout

    def connect(self):
        raw = _connect_pinned(self._ips, self.port, self._ct, self._rt)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class SafeFetcher:
    _ALLOWED_REQ_HEADERS = frozenset({"accept", "accept-language", "if-none-match", "if-modified-since"})

    def __init__(self, policy: Policy, *, resolver: Resolver | None = None,
                 ssl_context: ssl.SSLContext | None = None, clock: Callable[[], float] = time.monotonic):
        self.policy = policy
        self._resolver = resolver or system_resolver
        self._clock = clock
        if ssl_context is None:
            ssl_context = ssl.create_default_context(cafile=policy.ca_bundle)
            ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._ssl = ssl_context

    # ---------------------------------------------------------------- public
    def check_destination(self, url: str, scope: Scope) -> NormalizedUrl:
        """Static + DNS validation without sending anything (used when registering sources)."""
        nu = normalize_url(url)
        self._check_target(nu, scope)
        resolve_and_check(nu.host, nu.port, self.policy, self._resolver)
        return nu

    def fetch(self, url: str, *, scope: Scope, method: str = "GET", headers: dict[str, str] | None = None,
              max_bytes: int | None = None, deadline_s: float | None = None) -> RawResponse:
        if method not in ("GET", "HEAD"):
            raise DCPMError("POLICY_BLOCKED", "only GET and HEAD are permitted")
        started = self._clock()
        deadline = started + (deadline_s or self.policy.request_deadline_s)
        max_bytes = min(max_bytes or self.policy.max_response_bytes, self.policy.max_response_bytes)
        current = normalize_url(url)
        chain = [current.url]
        seen = {current.key}
        for _ in range(self.policy.max_redirects + 1):
            self._check_target(current, scope)
            ips = resolve_and_check(current.host, current.port, self.policy, self._resolver)
            status, hdrs, body = self._single_request(current, ips, method, headers or {}, max_bytes, deadline)
            location = hdrs.get("location")
            if status in _REDIRECT_STATUSES and location:
                try:
                    nxt = normalize_url(location, base=current.url, strip_tracking=False)
                except DCPMError:
                    raise DCPMError("HTTP_ERROR", "redirect to an invalid URL") from None
                if current.scheme == "https" and nxt.scheme == "http":
                    raise DCPMError("POLICY_BLOCKED", "redirect from https to http refused")
                if nxt.key in seen:
                    raise DCPMError("HTTP_ERROR", "redirect loop")
                seen.add(nxt.key)
                chain.append(nxt.url)
                current = nxt
                continue
            return RawResponse(url=chain[0], final_url=current.url, status=status, headers=hdrs, body=body,
                               redirect_chain=chain, elapsed_s=self._clock() - started)
        raise DCPMError("HTTP_ERROR", "too many redirects")

    # --------------------------------------------------------------- internal
    def _check_target(self, nu: NormalizedUrl, scope: Scope) -> None:
        if nu.scheme not in self.policy.allowed_schemes:
            raise DCPMError("UNSUPPORTED_PROTOCOL", f"scheme {nu.scheme!r} not allowed")
        if self.policy.allowed_ports is not None and nu.port not in self.policy.allowed_ports:
            raise DCPMError("POLICY_BLOCKED", f"port {nu.port} not allowed")
        if not scope.allows(nu.host):
            raise DCPMError("OUT_OF_SCOPE", "host is outside the source scope", details={"host": nu.host})

    def _single_request(self, nu: NormalizedUrl, ips: list[str], method: str, extra: dict[str, str],
                        max_bytes: int, deadline: float) -> tuple[int, dict[str, str], bytes]:
        p = self.policy
        req_headers = {"User-Agent": p.user_agent, "Accept-Encoding": "gzip", "Connection": "close"}
        for k, v in extra.items():
            if k.lower() in self._ALLOWED_REQ_HEADERS and isinstance(v, str) and "\r" not in v and "\n" not in v:
                req_headers[k] = v
        conn: http.client.HTTPConnection | None = None
        try:
            if nu.scheme == "https":
                conn = _PinnedHTTPS(nu.host, nu.port, ips, self._ssl, p.connect_timeout_s, p.read_timeout_s)
            else:
                conn = _PinnedHTTP(nu.host, nu.port, ips, p.connect_timeout_s, p.read_timeout_s)
            conn.request(method, nu.target, headers=req_headers)
            resp = conn.getresponse()
            hdrs = {k.lower(): v for k, v in resp.getheaders()}
            if resp.status in _REDIRECT_STATUSES or method == "HEAD":
                return resp.status, hdrs, b""
            return resp.status, hdrs, self._read_body(resp, hdrs, max_bytes, deadline)
        except DCPMError:
            raise
        except (socket.timeout, TimeoutError):
            raise DCPMError("TIMEOUT", "request timed out") from None
        except ssl.SSLError as e:
            raise DCPMError("TLS_ERROR", f"TLS failure: {getattr(e, 'reason', None) or 'handshake/verification failed'}") from None
        except (http.client.HTTPException, OSError) as e:
            raise DCPMError("NETWORK_ERROR", f"connection failed ({type(e).__name__})") from None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:  # pragma: no cover
                    pass

    def _read_body(self, resp: http.client.HTTPResponse, hdrs: dict[str, str], max_bytes: int, deadline: float) -> bytes:
        enc = (hdrs.get("content-encoding") or "identity").strip().lower()
        if enc not in ("identity", "gzip", "x-gzip"):
            raise DCPMError("UNSUPPORTED_ENCODING", f"content-encoding {enc!r} not supported")
        cl = hdrs.get("content-length")
        if cl is not None:
            try:
                if int(cl) > max_bytes:
                    raise DCPMError("RESPONSE_TOO_LARGE", "declared content-length exceeds limit")
            except ValueError:
                raise DCPMError("HTTP_ERROR", "invalid content-length") from None
        decomp = zlib.decompressobj(16 + zlib.MAX_WBITS) if enc in ("gzip", "x-gzip") else None
        out = bytearray()
        try:
            while True:
                if self._clock() > deadline:
                    raise DCPMError("TIMEOUT", "request deadline exceeded")
                chunk = resp.read(65536)
                if not chunk:
                    break
                if decomp is None:
                    out += chunk
                    if len(out) > max_bytes:
                        raise DCPMError("RESPONSE_TOO_LARGE", "response exceeds size limit")
                    continue
                pending = chunk
                while pending:
                    data = decomp.decompress(pending, max_bytes - len(out) + 1)
                    out += data
                    if len(out) > max_bytes:
                        raise DCPMError("RESPONSE_TOO_LARGE", "decompressed response exceeds size limit")
                    pending = decomp.unconsumed_tail
        except http.client.IncompleteRead:
            raise DCPMError("NETWORK_ERROR", "incomplete response body") from None
        except zlib.error:
            raise DCPMError("PARSE_FAILED", "invalid gzip stream") from None
        if decomp is not None and not decomp.eof:
            raise DCPMError("NETWORK_ERROR", "truncated gzip stream")
        return bytes(out)
