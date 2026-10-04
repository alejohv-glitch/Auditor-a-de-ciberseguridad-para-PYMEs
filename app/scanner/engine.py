"""Scan orchestration: SCANNER -> RAW FACTS. Rules and scoring live elsewhere.

``run_scan`` never raises for target-side problems; it returns facts with an
``outcome`` so the caller can store a failed scan with a clear reason.
"""
from __future__ import annotations

import datetime as dt
import time
from concurrent.futures import ThreadPoolExecutor

from ..config import settings
from . import netguard
from .dns_checks import collect_dns
from .email_checks import collect_email
from .tls_checks import collect_tls
from .web_checks import collect_web

SCANNER_VERSION = "1.0.0"


class ScanError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def run_scan(target: str, *, resolver=None, timeout: float | None = None) -> dict:
    """Collect raw facts for ``target``. Raises ScanError for unscannable targets."""
    host = netguard.normalize_domain(target)
    base = netguard.base_domain(host)
    resolver = resolver or netguard.make_resolver()
    started = time.monotonic()
    timeout = timeout or settings.scan_timeout_s

    dns_facts = collect_dns(host, base, resolver)
    if not dns_facts["resolver_ok"]:
        raise ScanError("dns_timeout", "DNS resolution timed out")
    if not dns_facts["domain_exists"]:
        raise ScanError("nxdomain", "The domain does not exist")

    try:
        ips = netguard.resolve_public(host, resolver)
        web_ip: str | None = netguard._pick_ip(ips)
        web_block = None
    except netguard.UnsafeTarget as exc:
        ips, web_ip, web_block = [], None, str(exc)
        if dns_facts["A"]["records"] or dns_facts["AAAA"]["records"]:
            # Resolves, but to private/reserved space: refuse the whole scan (SSRF guard).
            raise ScanError("unsafe_target", "The domain points to a non-public address") from exc

    with ThreadPoolExecutor(max_workers=3) as pool:
        f_email = pool.submit(collect_email, base, resolver, dns_facts["MX"], dns_facts["TXT"])
        f_tls = pool.submit(collect_tls, host, web_ip) if web_ip else None
        f_web = pool.submit(collect_web, host, settings.scanner_user_agent, 8.0, resolver) if web_ip else None
        email = f_email.result(timeout=timeout)
        tls = f_tls.result(timeout=timeout) if f_tls else {"available": False, "error": "no_public_ip"}
        web = f_web.result(timeout=timeout) if f_web else {"final": None, "technologies": [],
                                                           "http": {"reachable": False},
                                                           "https": {"reachable": False}}
    return {
        "meta": {
            "target": host, "base_domain": base, "scanner_version": SCANNER_VERSION,
            "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "duration_ms": int((time.monotonic() - started) * 1000),
            "ips": ips, "web_block": web_block,
        },
        "dns": dns_facts,
        "email": email,
        "tls": tls,
        "web": web,
    }
