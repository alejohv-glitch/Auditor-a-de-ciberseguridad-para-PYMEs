"""DNS fact collection. Only standard public queries via a recursive resolver."""
from __future__ import annotations

import dns.exception
import dns.resolver

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA")


def query(resolver: dns.resolver.Resolver, name: str, rtype: str) -> dict:
    """Return {'status': ok|nodata|nxdomain|timeout|error, 'records': [...]}."""
    try:
        answer = resolver.resolve(name, rtype)
    except dns.resolver.NXDOMAIN:
        return {"status": "nxdomain", "records": []}
    except dns.resolver.NoAnswer:
        return {"status": "nodata", "records": []}
    except dns.exception.Timeout:
        return {"status": "timeout", "records": []}
    except (dns.resolver.NoNameservers, dns.exception.DNSException) as exc:
        return {"status": "error", "records": [], "error": type(exc).__name__}
    records = []
    for r in answer:
        if rtype == "TXT":
            records.append(b"".join(r.strings).decode("utf-8", errors="replace"))
        elif rtype == "MX":
            records.append({"preference": r.preference, "exchange": r.exchange.to_text().rstrip(".")})
        elif rtype == "CAA":
            records.append({"flags": r.flags, "tag": r.tag.decode(), "value": r.value.decode(errors="replace")})
        else:
            records.append(r.to_text().rstrip("."))
    if rtype in ("A", "AAAA", "NS", "TXT"):
        records = sorted(records)
    return {"status": "ok", "records": records}


def collect_dns(host: str, base: str, resolver: dns.resolver.Resolver) -> dict:
    facts: dict = {"host": host, "base": base}
    for rtype in RECORD_TYPES:
        name = host if rtype in ("A", "AAAA") else base
        facts[rtype] = query(resolver, name, rtype)
    facts["www_CNAME"] = query(resolver, f"www.{base}", "CNAME")
    # DNSSEC: a DS record at the parent zone means the delegation is signed.
    facts["DS"] = query(resolver, base, "DS")
    statuses = {facts[t]["status"] for t in ("A", "AAAA", "NS", "SOA")}
    facts["domain_exists"] = not (facts["SOA"]["status"] == "nxdomain" and facts["NS"]["status"] == "nxdomain"
                                  and facts["A"]["status"] == "nxdomain")
    facts["resolver_ok"] = statuses != {"timeout"}
    return facts
