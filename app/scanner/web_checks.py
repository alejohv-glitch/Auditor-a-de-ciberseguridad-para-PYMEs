"""HTTP facts: at most 3 GET requests (http://, https://, /.well-known/security.txt).

No crawling, no path guessing, no form submission, no payloads.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from .netguard import FetchResult, safe_fetch

SECURITY_HEADERS = ("strict-transport-security", "content-security-policy", "x-content-type-options",
                    "x-frame-options", "referrer-policy", "permissions-policy",
                    "cross-origin-opener-policy")
VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)*")
GENERATOR_RE = re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]*content=[\"']([^\"']{1,120})", re.I)
GENERATOR_RE2 = re.compile(r"<meta[^>]+content=[\"']([^\"']{1,120})[\"'][^>]*name=[\"']generator", re.I)
# Answers that usually come from a WAF / bot filter rather than the real site.
BLOCKED_STATUSES = {403, 429, 503}
SESSION_COOKIE_RE = re.compile(r"sess|sid|auth|token|login|jwt|logged_in|remember|csrf|phpsessid", re.I)

HEADER_TECH = [
    ("cf-ray", "Cloudflare", "cdn"), ("x-amz-cf-id", "Amazon CloudFront", "cdn"),
    ("x-served-by", "Fastly", "cdn"), ("x-vercel-id", "Vercel", "hosting"),
    ("x-nf-request-id", "Netlify", "hosting"), ("x-shopify-stage", "Shopify", "platform"),
    ("x-wix-request-id", "Wix", "platform"), ("x-akamai-transformed", "Akamai", "cdn"),
    ("x-sucuri-id", "Sucuri", "waf"), ("x-litespeed-cache", "LiteSpeed Cache", "cache"),
]
BODY_TECH = [
    ("/wp-content/", "WordPress", "cms"), ("/wp-includes/", "WordPress", "cms"),
    ("cdn.shopify.com", "Shopify", "platform"), ("static.wixstatic.com", "Wix", "platform"),
    ("squarespace.com", "Squarespace", "platform"), ("/media/jui/", "Joomla", "cms"),
    ("drupal-settings-json", "Drupal", "cms"), ("prestashop", "PrestaShop", "cms"),
    ("/skin/frontend/", "Magento", "cms"), ("webflow.com", "Webflow", "platform"),
]


def parse_set_cookie(value: str) -> dict:
    parts = [p.strip() for p in value.split(";")]
    name = parts[0].split("=", 1)[0] if parts else ""
    attrs = {p.split("=", 1)[0].lower(): (p.split("=", 1)[1] if "=" in p else True) for p in parts[1:] if p}
    return {
        "name": name[:80],
        "secure": "secure" in attrs,
        "httponly": "httponly" in attrs,
        "samesite": (attrs.get("samesite") if isinstance(attrs.get("samesite"), str) else None),
        "session_like": bool(SESSION_COOKIE_RE.search(name)),
    }


def detect_technologies(headers: dict[str, str], body: str) -> list[dict]:
    found: dict[str, dict] = {}

    def add(name: str, kind: str, source: str, version: str | None = None) -> None:
        if name not in found:
            found[name] = {"name": name, "kind": kind, "source": source, "version": version}

    if headers.get("server"):
        v = VERSION_RE.search(headers["server"])
        add(headers["server"].split("/")[0].split(" ")[0][:40], "server", "Server header", v.group(0) if v else None)
    if headers.get("x-powered-by"):
        v = VERSION_RE.search(headers["x-powered-by"])
        add(headers["x-powered-by"].split("/")[0][:40], "framework", "X-Powered-By header", v.group(0) if v else None)
    for hdr, name, kind in HEADER_TECH:
        if hdr in headers:
            add(name, kind, f"{hdr} header")
    gen = GENERATOR_RE.search(body) or GENERATOR_RE2.search(body)
    if gen:
        v = VERSION_RE.search(gen.group(1))
        add(gen.group(1).split(" ")[0][:40], "cms", "meta generator", v.group(0) if v else None)
    low = body.lower()
    for marker, name, kind in BODY_TECH:
        if marker in low:
            add(name, kind, "page markup")
    return list(found.values())


def _summarize(res: FetchResult) -> dict:
    return {
        "error": res.error,
        "chain": [{"url": h.url, "status": h.status, "error": h.error, "tls_verified": h.tls_verified}
                  for h in res.hops],
    }


def collect_web(host: str, user_agent: str, timeout: float = 8.0, resolver=None) -> dict:
    facts: dict = {"host": host}
    http_res = safe_fetch(f"http://{host}/", user_agent=user_agent, timeout=timeout,
                          resolver=resolver, read_body=False)
    facts["http"] = _summarize(http_res)
    final_http = http_res.final
    facts["http"]["redirects_to_https"] = bool(
        final_http and final_http.status and urlsplit(final_http.url).scheme == "https")
    facts["http"]["reachable"] = bool(http_res.hops and http_res.hops[0].status)
    facts["http"]["blocked"] = bool(final_http and final_http.status in BLOCKED_STATUSES)

    https_res = safe_fetch(f"https://{host}/", user_agent=user_agent, timeout=timeout, resolver=resolver)
    facts["https"] = _summarize(https_res)
    final = https_res.final
    facts["https"]["reachable"] = bool(final and final.status)
    if not (final and final.status):
        # Fall back to whatever answered over plain HTTP so header checks can still run.
        final, body, scheme = final_http, "", "http"
        facts["https"]["reachable"] = False
    else:
        body, scheme = https_res.body, urlsplit(final.url).scheme
    if final and final.status:
        headers = {}
        cookies = []
        for k, v in final.headers:
            if k == "set-cookie":
                cookies.append(parse_set_cookie(v))
            else:
                headers[k] = v
        facts["final"] = {
            "url": final.url, "status": final.status, "scheme": scheme,
            "host": urlsplit(final.url).hostname,
            "headers": {k: v[:1000] for k, v in headers.items() if k in SECURITY_HEADERS
                        or k in ("server", "x-powered-by", "x-generator", "x-aspnet-version", "via", "content-type")},
            "cookies": cookies[:30],
        }
        facts["technologies"] = detect_technologies(headers, body)
        # We never try to evade a block (no UA spoofing); we just do not grade a block page.
        facts["blocked_response"] = final.status in BLOCKED_STATUSES
        facts["cross_domain_redirect"] = facts["final"]["host"] not in (host, f"www.{host}", host.removeprefix("www."))
    else:
        facts["final"] = None
        facts["technologies"] = []

    if facts["https"]["reachable"]:
        sec = safe_fetch(f"https://{host}/.well-known/security.txt", user_agent=user_agent,
                         timeout=timeout, resolver=resolver, max_redirects=2, max_bytes=32_000)
        f = sec.final
        ctype = dict(f.headers).get("content-type", "") if f else ""
        facts["security_txt"] = bool(f and f.status == 200 and "text/plain" in ctype
                                     and "contact:" in sec.body.lower())
    else:
        facts["security_txt"] = None
    return facts
