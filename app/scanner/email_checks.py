"""E-mail authentication facts: SPF, DMARC, DKIM (common selectors), MTA-STS, TLS-RPT.

Read-only DNS lookups. No e-mail is ever sent and no SMTP connection is opened.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import dns.resolver

from .dns_checks import query

# Selectors used by the most common providers. DKIM cannot be enumerated, so a
# miss is reported as "not verifiable", never as "missing".
DKIM_SELECTORS = ("google", "selector1", "selector2", "default", "k1", "k2", "mail", "dkim",
                  "s1", "s2", "mxvault", "zoho", "protonmail", "smtp", "everlytickey1")
SPF_LOOKUP_MECHS = ("include", "a", "mx", "ptr", "exists", "redirect")
MAX_SPF_QUERIES = 20  # safety cap on our own recursion


def parse_spf(record: str) -> dict:
    terms = record.split()[1:]
    mechanisms, all_qualifier, redirect = [], None, None
    for t in terms:
        tl = t.lower()
        if tl.startswith("redirect="):
            redirect = t.split("=", 1)[1]
            continue
        if "=" in tl:  # other modifiers (exp=)
            continue
        qual = tl[0] if tl[0] in "+-~?" else "+"
        mech = tl[1:] if tl[0] in "+-~?" else tl
        name = mech.split(":")[0].split("/")[0]
        if name == "all":
            all_qualifier = qual
        mechanisms.append({"qualifier": qual, "mechanism": name, "value": mech.split(":", 1)[1] if ":" in mech else None})
    return {"mechanisms": mechanisms, "all": all_qualifier, "redirect": redirect}


def count_spf_lookups(resolver: dns.resolver.Resolver, record: str, budget: list[int], seen: set[str]) -> int:
    """Count DNS-querying mechanisms (RFC 7208 §4.6.4 limit is 10), recursing into includes."""
    parsed = parse_spf(record)
    count = 0
    targets = []
    for m in parsed["mechanisms"]:
        if m["mechanism"] in SPF_LOOKUP_MECHS:
            count += 1
            if m["mechanism"] == "include" and m["value"]:
                targets.append(m["value"])
    if parsed["redirect"]:
        count += 1
        targets.append(parsed["redirect"])
    for t in targets:
        if t in seen or budget[0] <= 0:
            continue
        seen.add(t)
        budget[0] -= 1
        res = query(resolver, t, "TXT")
        spf = [r for r in res["records"] if r.lower().startswith("v=spf1")]
        if spf:
            count += count_spf_lookups(resolver, spf[0], budget, seen)
    return count


def parse_dmarc(record: str) -> dict:
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def collect_email(base: str, resolver: dns.resolver.Resolver, mx: dict | None = None,
                  txt: dict | None = None) -> dict:
    mx = mx if mx is not None else query(resolver, base, "MX")
    txt = txt if txt is not None else query(resolver, base, "TXT")
    mx_hosts = [m["exchange"] for m in mx["records"]]
    null_mx = len(mx["records"]) == 1 and mx_hosts[0] in ("", ".")
    spf_records = [r for r in txt["records"] if r.lower().startswith("v=spf1")]
    spf: dict = {"status": txt["status"], "records": spf_records}
    if len(spf_records) == 1:
        spf.update(parse_spf(spf_records[0]))
        spf["lookups"] = count_spf_lookups(resolver, spf_records[0], [MAX_SPF_QUERIES], set())

    dmarc_q = query(resolver, f"_dmarc.{base}", "TXT")
    dmarc_records = [r for r in dmarc_q["records"] if r.lower().replace(" ", "").startswith("v=dmarc1")]
    dmarc: dict = {"status": dmarc_q["status"], "records": dmarc_records}
    if len(dmarc_records) == 1:
        dmarc["tags"] = parse_dmarc(dmarc_records[0])

    def _dkim(sel: str) -> bool:
        rec = " ".join(query(resolver, f"{sel}._domainkey.{base}", "TXT")["records"]).replace(" ", "")
        return "p=" in rec and "p=;" not in rec and not rec.endswith("p=")

    with ThreadPoolExecutor(max_workers=5) as pool:  # 15 small lookups; parallel keeps scans fast
        dkim_found = [sel for sel, ok in zip(DKIM_SELECTORS, pool.map(_dkim, DKIM_SELECTORS)) if ok]

    mta_sts = query(resolver, f"_mta-sts.{base}", "TXT")
    tls_rpt = query(resolver, f"_smtp._tls.{base}", "TXT")
    return {
        "domain": base,
        "mx": {"status": mx["status"], "hosts": mx_hosts, "null_mx": null_mx},
        "spf": spf,
        "dmarc": dmarc,
        "dkim": {"selectors_checked": list(DKIM_SELECTORS), "found": dkim_found},
        "mta_sts": any(r.lower().startswith("v=stsv1") for r in mta_sts["records"]),
        "tls_rpt": any(r.lower().startswith("v=tlsrptv1") for r in tls_rpt["records"]),
    }
