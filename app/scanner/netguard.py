"""Target validation and SSRF-safe network primitives.

Every outbound connection the scanner makes goes through this module:

* ``normalize_domain`` turns user input into a bare, IDNA-encoded hostname and
  rejects IP literals, single-label names and internal TLDs.
* ``resolve_public`` resolves A/AAAA and refuses the target if ANY address is not
  globally routable (loopback, RFC1918, link-local/metadata 169.254.x.x, CGNAT,
  multicast, reserved, IPv4-mapped private IPv6...).
* ``safe_fetch`` performs a small number of plain GET requests, connecting to the
  *already validated* IP (pinning, so DNS rebinding cannot swap the address
  between validation and connection), only on ports 80/443, re-validating every
  redirect hop and reading a bounded amount of body.
"""
from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import dns.exception
import dns.resolver

BLOCKED_SUFFIXES = (
    ".localhost", ".local", ".internal", ".intranet", ".lan", ".home", ".corp",
    ".arpa", ".test", ".invalid", ".example", ".onion", ".localdomain",
)
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
ALLOWED_PORTS = {"http": 80, "https": 443}


class UnsafeTarget(ValueError):
    """The target is not a public internet domain and must not be contacted."""


class InvalidDomain(ValueError):
    """The input is not a syntactically valid domain name."""


def normalize_domain(raw: str) -> str:
    if not raw or not isinstance(raw, str):
        raise InvalidDomain("empty")
    s = raw.strip().lower()
    if len(s) > 300:
        raise InvalidDomain("too long")
    if "://" in s:
        s = urlsplit(s).netloc or ""
    s = s.split("/")[0].split("?")[0].split("#")[0]
    if "@" in s:  # userinfo tricks: http://good.com@evil.internal
        raise InvalidDomain("userinfo not allowed")
    if s.startswith("["):
        raise UnsafeTarget("IP literals are not allowed")
    s = s.split(":")[0].rstrip(".")
    try:
        ipaddress.ip_address(s)
        raise UnsafeTarget("IP addresses are not allowed; enter a domain name")
    except ValueError:
        pass
    try:
        s = s.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidDomain("invalid IDN") from exc
    if len(s) > 253 or "." not in s:
        raise InvalidDomain("a full domain like example.com is required")
    labels = s.split(".")
    if not all(_LABEL_RE.match(lbl) for lbl in labels):
        raise InvalidDomain("invalid characters")
    tld = labels[-1]
    if not (tld.isalpha() or tld.startswith("xn--")) or len(tld) < 2:
        raise InvalidDomain("invalid top-level domain")
    if s == "localhost" or any(s.endswith(suf) for suf in BLOCKED_SUFFIXES):
        raise UnsafeTarget("internal or reserved domain")
    return s


def base_domain(host: str) -> str:
    """Domain used for e-mail checks: strips a leading ``www.``."""
    return host[4:] if host.startswith("www.") else host


def is_public_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return bool(addr.is_global) and not (addr.is_multicast or addr.is_reserved or addr.is_unspecified)


def make_resolver(timeout: float = 4.0) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout
    return r


def resolve_ips(host: str, resolver: dns.resolver.Resolver | None = None) -> list[str]:
    resolver = resolver or make_resolver()
    ips: list[str] = []
    for rtype in ("A", "AAAA"):
        try:
            ips += [r.to_text() for r in resolver.resolve(host, rtype)]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            continue
        except dns.exception.Timeout:
            continue
    return ips


def resolve_public(host: str, resolver: dns.resolver.Resolver | None = None) -> list[str]:
    ips = resolve_ips(host, resolver)
    if not ips:
        raise UnsafeTarget(f"{host} has no A/AAAA records")
    bad = [ip for ip in ips if not is_public_ip(ip)]
    if bad:
        raise UnsafeTarget(f"{host} resolves to non-public address(es)")
    return ips


def _pick_ip(ips: list[str]) -> str:
    v4 = [ip for ip in ips if ":" not in ip]
    return (v4 or ips)[0]


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, ip: str, port: int, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, ip: str, port: int, timeout: float, context: ssl.SSLContext):
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


@dataclass
class Hop:
    url: str
    status: int | None = None
    headers: list[tuple[str, str]] = field(default_factory=list)
    ip: str | None = None
    error: str | None = None
    tls_verified: bool | None = None


@dataclass
class FetchResult:
    hops: list[Hop]
    body: str = ""
    error: str | None = None

    @property
    def final(self) -> Hop | None:
        return self.hops[-1] if self.hops else None


def _one_request(url: str, user_agent: str, timeout: float, max_bytes: int,
                 resolver, read_body: bool) -> tuple[Hop, str]:
    parts = urlsplit(url)
    scheme = parts.scheme
    if scheme not in ALLOWED_PORTS:
        raise UnsafeTarget(f"scheme {scheme!r} not allowed")
    if parts.port not in (None, ALLOWED_PORTS[scheme]):
        raise UnsafeTarget("only standard ports 80/443 are contacted")
    host = normalize_domain(parts.hostname or "")
    ip = _pick_ip(resolve_public(host, resolver))
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    hop = Hop(url=url, ip=ip)
    body = ""

    def _do(conn: http.client.HTTPConnection) -> None:
        nonlocal body
        conn.request("GET", path, headers={
            "Host": host, "User-Agent": user_agent, "Accept": "text/html,*/*;q=0.5",
            "Accept-Encoding": "identity", "Connection": "close"})
        resp = conn.getresponse()
        hop.status = resp.status
        hop.headers = [(k.lower(), v) for k, v in resp.getheaders()]
        if read_body and resp.status == 200:
            body = resp.read(max_bytes).decode("utf-8", errors="replace")
        conn.close()

    if scheme == "https":
        try:
            _do(_PinnedHTTPSConnection(host, ip, 443, timeout, ssl.create_default_context()))
            hop.tls_verified = True
        except ssl.SSLCertVerificationError:
            # Certificate problems are reported by the TLS collector; still read headers.
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            _do(_PinnedHTTPSConnection(host, ip, 443, timeout, ctx))
            hop.tls_verified = False
    else:
        _do(_PinnedHTTPConnection(host, ip, 80, timeout))
    return hop, body


def safe_fetch(url: str, *, user_agent: str, timeout: float = 8.0, max_redirects: int = 5,
               max_bytes: int = 512_000, resolver=None, read_body: bool = True) -> FetchResult:
    hops: list[Hop] = []
    current = url
    for _ in range(max_redirects + 1):
        try:
            hop, body = _one_request(current, user_agent, timeout, max_bytes, resolver, read_body)
        except UnsafeTarget as exc:
            hops.append(Hop(url=current, error=f"blocked: {exc}"))
            return FetchResult(hops, error="blocked")
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            hops.append(Hop(url=current, error=type(exc).__name__ + ": " + str(exc)[:200]))
            return FetchResult(hops, error="connection")
        hops.append(hop)
        location = dict(hop.headers).get("location")
        if hop.status in (301, 302, 303, 307, 308) and location:
            current = urljoin(current, location)
            continue
        return FetchResult(hops, body=body)
    return FetchResult(hops, error="too_many_redirects")
