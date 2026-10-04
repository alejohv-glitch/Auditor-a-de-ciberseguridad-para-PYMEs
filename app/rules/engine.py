"""RAW FACTS -> FINDINGS. Deterministic, side-effect free.

Each rule returns a ``Result``:
  status   fail | pass | unknown (could not be verified, never penalised) | na
  severity critical | high | medium | low | info (meaningful when status == fail)
  evidence dict of observed values (also used to fill the catalogue text)

Severity policy (docs/SCORING.md):
  critical  directly exploitable by anyone today with significant business impact
  high      a core control missing or broken (no DMARC, invalid certificate, no HTTPS)
  medium    a control present but weak / an obsolete configuration
  low       missing hardening that reduces impact of other problems
  info      recommendation or best practice; no score impact
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .catalog import RULES

ANALYSIS_VERSION = "2026.10.1"


@dataclass
class Result:
    rule_id: str
    status: str
    severity: str = "info"
    evidence: dict = field(default_factory=dict)

    @property
    def category(self) -> str:
        return RULES[self.rule_id]["category"]

    @property
    def kind(self) -> str:
        return RULES[self.rule_id]["kind"]

    def to_dict(self) -> dict:
        d = asdict(self)
        d.update(category=self.category, kind=self.kind, effort=RULES[self.rule_id]["effort"])
        return d


def _fail(rule: str, severity: str, **ev) -> Result:
    return Result(rule, "fail", severity, ev)


def _pass(rule: str, **ev) -> Result:
    return Result(rule, "pass", "info", ev)


def _unknown(rule: str, **ev) -> Result:
    return Result(rule, "unknown", "info", ev)


def _na(rule: str, **ev) -> Result:
    return Result(rule, "na", "info", ev)


# ---------------------------------------------------------------------- e-mail
def email_rules(f: dict) -> list[Result]:
    email, dom = f.get("email") or {}, (f.get("email") or {}).get("domain", f["meta"]["base_domain"])
    out: list[Result] = []
    mx = email.get("mx", {})
    has_mx = bool(mx.get("hosts")) and not mx.get("null_mx")
    spf = email.get("spf", {})
    dmarc = email.get("dmarc", {})

    if spf.get("status") == "timeout":
        out.append(_unknown("spf_present", domain=dom))
    elif not spf.get("records"):
        # A domain that sends no mail still needs "v=spf1 -all" to stop spoofing.
        out.append(_fail("spf_present", "high" if has_mx else "medium", domain=dom, has_mx=has_mx))
    elif len(spf["records"]) > 1:
        out.append(_pass("spf_present", domain=dom))
        out.append(_fail("spf_single", "high", count=len(spf["records"]), records=spf["records"]))
    else:
        out.append(_pass("spf_present", domain=dom, record=spf["records"][0]))
        out.append(_pass("spf_single"))
        q = spf.get("all")
        meanings = {"+": ("permite que CUALQUIER servidor envíe en su nombre", "allows ANY server to send as you"),
                    "?": ("neutral, no indica nada", "neutral, it states nothing"),
                    None: ("no hay mecanismo «all» (equivale a neutral)", "no \"all\" mechanism (equivalent to neutral)")}
        if q == "+":
            out.append(_fail("spf_all", "critical", qualifier="+", meaning=meanings["+"][0],
                             meaning_en=meanings["+"][1], record=spf["records"][0]))
        elif q in ("?", None) and not spf.get("redirect"):
            out.append(_fail("spf_all", "medium", qualifier=q or "", meaning=meanings[q][0],
                             meaning_en=meanings[q][1], record=spf["records"][0]))
        else:
            out.append(_pass("spf_all", qualifier=q or "redirect"))
        lookups = spf.get("lookups", 0)
        if lookups > 10:
            out.append(_fail("spf_lookups", "medium", lookups=lookups))
        else:
            out.append(_pass("spf_lookups", lookups=lookups))

    if dmarc.get("status") == "timeout":
        out.append(_unknown("dmarc_present", domain=dom))
    elif not dmarc.get("records"):
        out.append(_fail("dmarc_present", "high", domain=dom, has_mx=has_mx))
    elif len(dmarc["records"]) > 1:
        out.append(_pass("dmarc_present", domain=dom))
        out.append(_fail("dmarc_valid", "high", detail=f"Hay {len(dmarc['records'])} registros DMARC (solo se permite uno).", detail_en=f"{len(dmarc['records'])} DMARC records found (only one allowed).",
                         records=dmarc["records"]))
    else:
        tags = dmarc.get("tags", {})
        policy = tags.get("p", "").lower()
        out.append(_pass("dmarc_present", domain=dom, record=dmarc["records"][0]))
        if policy not in ("none", "quarantine", "reject"):
            out.append(_fail("dmarc_valid", "high", detail=f"Falta la etiqueta p= o no es válida: {dmarc['records'][0]}", detail_en=f"Missing or invalid p= tag: {dmarc['records'][0]}",
                             record=dmarc["records"][0]))
        else:
            out.append(_pass("dmarc_valid"))
            pct = tags.get("pct", "100")
            pct_note = f" (pct={pct})" if pct != "100" else ""
            if policy == "none":
                out.append(_fail("dmarc_policy", "medium", policy=policy, pct_note=pct_note, record=dmarc["records"][0]))
            elif pct != "100":
                out.append(_fail("dmarc_policy", "low", policy=policy, pct_note=pct_note, record=dmarc["records"][0]))
            else:
                out.append(_pass("dmarc_policy", policy=policy))
            if "rua" not in tags:
                out.append(_fail("dmarc_reporting", "low", domain=dom))
            else:
                out.append(_pass("dmarc_reporting", rua=tags["rua"]))

    dkim = email.get("dkim", {})
    if has_mx:
        if dkim.get("found"):
            out.append(_pass("dkim_found", selectors=", ".join(dkim["found"])))
        else:
            out.append(_unknown("dkim_found", checked=len(dkim.get("selectors_checked", []))))
        out.append(_pass("mta_sts") if email.get("mta_sts") else _fail("mta_sts", "info", domain=dom))
    else:
        out.append(_na("dkim_found"))
        out.append(_na("mta_sts"))
    return out


# ------------------------------------------------------------------- HTTPS/TLS
def tls_rules(f: dict) -> list[Result]:
    tls, web, host = f.get("tls") or {}, f.get("web") or {}, f["meta"]["target"]
    out: list[Result] = []
    if not f["meta"].get("ips"):
        return [_na(r) for r in ("https_available", "http_redirect", "cert_trusted", "cert_expiry", "tls_legacy", "hsts")]
    if not tls.get("available"):
        out.append(_fail("https_available", "high", host=host, detail=tls.get("error", "no response")))
        if web.get("http", {}).get("reachable"):
            out.append(_fail("http_redirect", "medium", host=host,
                             status=(web["http"].get("chain") or [{}])[-1].get("status")))
        else:
            out.append(_na("http_redirect"))
        return out + [_na(r) for r in ("cert_trusted", "cert_expiry", "tls_legacy", "hsts")]

    out.append(_pass("https_available", host=host, version=tls.get("version")))
    http = web.get("http", {})
    if not http.get("reachable"):
        out.append(_pass("http_redirect", note="port 80 closed"))
    elif http.get("redirects_to_https"):
        out.append(_pass("http_redirect"))
    elif http.get("blocked"):
        out.append(_unknown("http_redirect", reason="blocked_response"))
    else:
        out.append(_fail("http_redirect", "medium", host=host, status=(http.get("chain") or [{}])[-1].get("status")))

    cert = tls.get("certificate") or {}
    days = cert.get("days_remaining")
    if not tls.get("verified"):
        detail = tls.get("verify_error", "unknown error")
        sev = "high"
        out.append(_fail("cert_trusted", sev, host=host, detail=detail, issuer=cert.get("issuer_org") or cert.get("issuer_cn"),
                         not_after=cert.get("not_after"), sans=cert.get("sans")))
    else:
        out.append(_pass("cert_trusted", issuer=cert.get("issuer_org") or cert.get("issuer_cn")))
    if days is None:
        out.append(_unknown("cert_expiry"))
    elif days < 0:
        out.append(_na("cert_expiry", days=days))  # already covered by cert_trusted (expired)
    elif days < 7:
        out.append(_fail("cert_expiry", "high", days=days, not_after=cert.get("not_after", "")[:10],
                         issuer=cert.get("issuer_org") or cert.get("issuer_cn")))
    elif days <= 20:
        out.append(_fail("cert_expiry", "medium", days=days, not_after=cert.get("not_after", "")[:10],
                         issuer=cert.get("issuer_org") or cert.get("issuer_cn")))
    else:
        out.append(_pass("cert_expiry", days=days, not_after=cert.get("not_after", "")[:10]))

    legacy = tls.get("legacy") or {}
    supported = [v for v, s in legacy.items() if s == "supported"]
    if supported:
        out.append(_fail("tls_legacy", "medium", versions=", ".join(supported)))
    elif legacy and all(s == "not_supported" for s in legacy.values()):
        out.append(_pass("tls_legacy"))
    else:
        out.append(_unknown("tls_legacy", probes=legacy))

    final = web.get("final") or {}
    if web.get("blocked_response"):
        out.append(_unknown("hsts", reason="blocked_response"))
    elif final.get("scheme") == "https":
        hsts = (final.get("headers") or {}).get("strict-transport-security")
        if not hsts:
            out.append(_fail("hsts", "low", detail="No se envía la cabecera Strict-Transport-Security.", detail_en="Strict-Transport-Security header not sent."))
        else:
            try:
                max_age = int(hsts.lower().split("max-age=")[1].split(";")[0].strip().strip('"'))
            except (IndexError, ValueError):
                max_age = 0
            if max_age < 15552000:  # 180 days
                out.append(_fail("hsts", "info", detail=f"HSTS con max-age corto ({max_age}s): {hsts}", detail_en=f"HSTS max-age is short ({max_age}s): {hsts}", value=hsts))
            else:
                out.append(_pass("hsts", value=hsts))
    else:
        out.append(_na("hsts"))
    return out


# --------------------------------------------------------------------- headers
def header_rules(f: dict) -> list[Result]:
    final = (f.get("web") or {}).get("final")
    ids = ("csp", "xcto", "frame_protection", "referrer_policy", "permissions_policy")
    if not final:
        return [_na(r) for r in ids]
    if (f.get("web") or {}).get("blocked_response"):
        return [_unknown(r, reason="blocked_response") for r in ids]
    h = final.get("headers") or {}
    csp = h.get("content-security-policy", "")
    out = [
        _pass("csp", value=csp[:300]) if csp else _fail("csp", "low"),
        _pass("xcto") if h.get("x-content-type-options", "").lower().strip() == "nosniff" else _fail("xcto", "low"),
        _pass("frame_protection", value=h.get("x-frame-options") or "frame-ancestors")
        if (h.get("x-frame-options") or "frame-ancestors" in csp.lower()) else _fail("frame_protection", "low"),
        _pass("referrer_policy", value=h["referrer-policy"]) if h.get("referrer-policy") else _fail("referrer_policy", "info"),
        _pass("permissions_policy") if h.get("permissions-policy") else _fail("permissions_policy", "info"),
    ]
    return out


# --------------------------------------------------------------------- cookies
def cookie_rules(f: dict) -> list[Result]:
    final = (f.get("web") or {}).get("final")
    ids = ("cookie_secure", "cookie_httponly", "cookie_samesite")
    if not final or not final.get("cookies") or (f.get("web") or {}).get("blocked_response"):
        return [_na(r) for r in ids]
    cookies = final["cookies"]
    out: list[Result] = []
    https = final.get("scheme") == "https"
    insecure = [c for c in cookies if not c["secure"]]
    if https and insecure:
        sev = "medium" if any(c["session_like"] for c in insecure) else "low"
        out.append(_fail("cookie_secure", sev, names=", ".join(c["name"] for c in insecure[:8])))
    elif https:
        out.append(_pass("cookie_secure"))
    else:
        out.append(_na("cookie_secure"))
    session = [c for c in cookies if c["session_like"]]
    if not session:
        return out + [_na("cookie_httponly"), _na("cookie_samesite")]
    no_ho = [c for c in session if not c["httponly"]]
    out.append(_fail("cookie_httponly", "low", names=", ".join(c["name"] for c in no_ho[:8])) if no_ho
               else _pass("cookie_httponly"))
    no_ss = [c for c in session if not c["samesite"]]
    out.append(_fail("cookie_samesite", "low", names=", ".join(c["name"] for c in no_ss[:8])) if no_ss
               else _pass("cookie_samesite"))
    return out


# ------------------------------------------------------------------------- DNS
def dns_rules(f: dict) -> list[Result]:
    d, dom = f.get("dns") or {}, f["meta"]["base_domain"]
    out: list[Result] = []
    ns = d.get("NS", {})
    if ns.get("status") == "ok":
        recs = ns["records"]
        out.append(_fail("ns_redundancy", "medium", count=len(recs), ns=", ".join(recs)) if len(recs) < 2
                   else _pass("ns_redundancy", ns=", ".join(recs)))
    else:
        out.append(_unknown("ns_redundancy"))
    caa = d.get("CAA", {})
    if caa.get("status") in ("ok",):
        out.append(_pass("caa", records=caa["records"]))
    elif caa.get("status") in ("nodata", "nxdomain"):
        out.append(_fail("caa", "low", domain=dom))
    else:
        out.append(_unknown("caa"))
    ds = d.get("DS", {})
    if ds.get("status") == "ok":
        out.append(_pass("dnssec"))
    elif ds.get("status") in ("nodata", "nxdomain"):
        out.append(_fail("dnssec", "low", domain=dom))
    else:
        out.append(_unknown("dnssec"))
    return out


# -------------------------------------------------------------------- exposure
def exposure_rules(f: dict) -> list[Result]:
    web = f.get("web") or {}
    final = web.get("final")
    if not final:
        return [_na(r) for r in ("server_version", "cms_version", "security_txt")]
    if web.get("blocked_response"):
        return [_unknown(r, reason="blocked_response") for r in ("server_version", "cms_version", "security_txt")]
    h = final.get("headers") or {}
    out: list[Result] = []
    disclosed = None
    for header in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        v = h.get(header, "")
        if v and any(ch.isdigit() for ch in v) and "." in v:
            disclosed = (header, v)
            break
    out.append(_fail("server_version", "low", header=disclosed[0], value=disclosed[1][:100]) if disclosed
               else _pass("server_version"))
    cms = [t for t in web.get("technologies", []) if t.get("source") == "meta generator" and t.get("version")]
    out.append(_fail("cms_version", "low", value=f"{cms[0]['name']} {cms[0]['version']}") if cms
               else _pass("cms_version"))
    sec = web.get("security_txt")
    out.append(_pass("security_txt") if sec else (_fail("security_txt", "info") if sec is False else _na("security_txt")))
    return out


ALL_RULESETS = (email_rules, tls_rules, header_rules, cookie_rules, dns_rules, exposure_rules)


def evaluate(facts: dict) -> list[Result]:
    results: list[Result] = []
    for ruleset in ALL_RULESETS:
        results.extend(ruleset(facts))
    return results
