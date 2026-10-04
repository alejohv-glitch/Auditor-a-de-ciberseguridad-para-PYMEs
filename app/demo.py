"""DEMO data. Clearly fictitious facts for a fictitious company, evaluated by the
REAL rule engine and scoring, so the demo shows exactly what a real report looks
like. Everything produced from here is flagged ``is_demo`` and labelled DEMO.

The domain uses the reserved ``.example`` TLD so it can never be a real company.
"""
from __future__ import annotations

import copy
import datetime as dt

from .models import Scan
from .services import new_public_id, persist_results

DEMO_DOMAIN = "clinica-demo.example"


def demo_facts(variant: int = 0) -> dict:
    """variant 0 = current state; variant 1 = an older, worse state (for history/diff)."""
    now = dt.datetime.now(dt.timezone.utc)
    facts = {
        "meta": {"target": DEMO_DOMAIN, "base_domain": DEMO_DOMAIN, "scanner_version": "demo",
                 "collected_at": now.isoformat(timespec="seconds"), "duration_ms": 9400,
                 "ips": ["192.0.2.10"], "web_block": None, "demo": True},
        "dns": {
            "A": {"status": "ok", "records": ["192.0.2.10"]}, "AAAA": {"status": "nodata", "records": []},
            "MX": {"status": "ok", "records": [{"preference": 0, "exchange": "clinica-demo-example.mail.protection.outlook.com"}]},
            "NS": {"status": "ok", "records": ["ns1.hosting-demo.example", "ns2.hosting-demo.example"]},
            "TXT": {"status": "ok", "records": ["v=spf1 include:spf.protection.outlook.com include:servers.mcsv.net ?all"]},
            "CAA": {"status": "nodata", "records": []}, "SOA": {"status": "ok", "records": ["ns1.hosting-demo.example."]},
            "DS": {"status": "nodata", "records": []}, "www_CNAME": {"status": "nodata", "records": []},
            "domain_exists": True, "resolver_ok": True,
        },
        "email": {
            "domain": DEMO_DOMAIN,
            "mx": {"status": "ok", "hosts": ["clinica-demo-example.mail.protection.outlook.com"], "null_mx": False},
            "spf": {"status": "ok", "records": ["v=spf1 include:spf.protection.outlook.com include:servers.mcsv.net ?all"],
                    "mechanisms": [], "all": "?", "redirect": None, "lookups": 4},
            "dmarc": {"status": "ok", "records": ["v=DMARC1; p=none"], "tags": {"v": "DMARC1", "p": "none"}},
            "dkim": {"selectors_checked": ["selector1", "selector2", "google"], "found": ["selector1"]},
            "mta_sts": False, "tls_rpt": False,
        },
        "tls": {
            "host": DEMO_DOMAIN, "ip": "192.0.2.10", "available": True, "verified": True, "version": "TLSv1.2",
            "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
            "certificate": {"subject_cn": DEMO_DOMAIN, "issuer_cn": "R11", "issuer_org": "Let's Encrypt",
                            "not_before": (now - dt.timedelta(days=78)).isoformat(),
                            "not_after": (now + dt.timedelta(days=5)).isoformat(), "days_remaining": 5,
                            "sans": [DEMO_DOMAIN, f"www.{DEMO_DOMAIN}"], "self_signed": False,
                            "signature_algorithm": "sha256", "key_type": "RSA", "key_size": 2048},
            "legacy": {"TLSv1": "supported", "TLSv1.1": "supported"},
        },
        "web": {
            "host": DEMO_DOMAIN,
            "http": {"error": None, "reachable": True, "redirects_to_https": True,
                     "chain": [{"url": f"http://{DEMO_DOMAIN}/", "status": 301}, {"url": f"https://{DEMO_DOMAIN}/", "status": 200}]},
            "https": {"error": None, "reachable": True, "chain": [{"url": f"https://{DEMO_DOMAIN}/", "status": 200, "tls_verified": True}]},
            "final": {"url": f"https://{DEMO_DOMAIN}/", "status": 200, "scheme": "https", "host": DEMO_DOMAIN,
                      "headers": {"server": "Apache/2.4.41 (Ubuntu)", "x-powered-by": "PHP/7.4.3",
                                  "content-type": "text/html; charset=UTF-8"},
                      "cookies": [{"name": "PHPSESSID", "secure": False, "httponly": True, "samesite": None, "session_like": True}]},
            "technologies": [{"name": "Apache", "kind": "server", "source": "Server header", "version": "2.4.41"},
                             {"name": "PHP", "kind": "framework", "source": "X-Powered-By header", "version": "7.4.3"},
                             {"name": "WordPress", "kind": "cms", "source": "meta generator", "version": "6.2.1"}],
            "cross_domain_redirect": False, "security_txt": False,
        },
    }
    if variant == 1:
        facts = copy.deepcopy(facts)
        facts["email"]["dmarc"] = {"status": "nxdomain", "records": []}
        facts["tls"]["certificate"]["days_remaining"] = 72
        facts["web"]["http"]["redirects_to_https"] = False
        facts["web"]["http"]["chain"] = [{"url": f"http://{DEMO_DOMAIN}/", "status": 200}]
    return facts


def build_demo_scan(variant: int = 0) -> Scan:
    """A transient (unsaved) Scan evaluated by the real engine."""
    scan = Scan(public_id="demo", hostname=DEMO_DOMAIN, trigger="demo", is_demo=True)
    persist_results(None, scan, demo_facts(variant))
    scan.created_at = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    return scan


def seed_demo(session, user_email: str = "demo@demo.example") -> None:
    """Create a DEMO organisation with history, for sales demos inside the dashboard."""
    from sqlalchemy import select

    from .models import Domain, Membership, Organization, ScoreHistory, User
    from .security import hash_password
    from .services import compute_changes

    if session.scalar(select(Organization).where(Organization.is_demo.is_(True))):
        return
    org = Organization(name="Clínica Demo S.L. (DEMO)", plan="business", is_demo=True)
    user = session.scalar(select(User).where(User.email == user_email))
    if not user:
        import secrets
        pw = secrets.token_urlsafe(12)
        user = User(email=user_email, password_hash=hash_password(pw))
        print(f"DEMO login: {user_email} / {pw}")
    session.add_all([org, user])
    session.flush()
    session.add(Membership(user_id=user.id, org_id=org.id))
    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    dom = Domain(org_id=org.id, hostname=DEMO_DOMAIN, client_name="Clínica Demo (DEMO)",
                 authorized_by_user_id=user.id, authorized_at=now,
                 authorization_statement="DEMO data - fictitious domain", monitoring_enabled=True,
                 next_scan_at=now + dt.timedelta(hours=20))
    session.add(dom)
    session.flush()
    prev = None
    for i, variant in enumerate((1, 0)):
        scan = Scan(public_id=new_public_id(), hostname=DEMO_DOMAIN, org_id=org.id, domain_id=dom.id,
                    trigger="demo", is_demo=True, status="completed",
                    created_at=now - dt.timedelta(days=7 * (1 - i)), finished_at=now - dt.timedelta(days=7 * (1 - i)),
                    duration_ms=9400)
        persist_results(session, scan, demo_facts(variant))
        session.add(scan)
        session.flush()
        scan.changes = compute_changes(prev, scan)
        session.add(ScoreHistory(domain_id=dom.id, scan_id=scan.id, score=scan.score, grade=scan.grade,
                                 recorded_at=scan.created_at))
        prev = scan
