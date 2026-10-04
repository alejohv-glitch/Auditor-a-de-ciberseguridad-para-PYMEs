"""HTTP-level tests: auth, authorization/multi-tenancy, CSRF, rate limits, plans, reports, privacy."""
import re

from sqlalchemy import func, select

from app import db as dbmod
from app.models import AuditLog, Domain, Finding, Lead, Organization, Scan, User
from app.scanner.engine import ScanError
from tests.conftest import add_domain, csrf, register


def _org(email):
    with dbmod.session_scope() as s:
        u = s.scalar(select(User).where(User.email == email))
        return s.get(Organization, u.memberships[0].org_id)


def _set_plan(email, plan):
    with dbmod.session_scope() as s:
        u = s.scalar(select(User).where(User.email == email))
        s.get(Organization, u.memberships[0].org_id).plan = plan


# ------------------------------------------------------------------ auth
def test_register_login_logout(client):
    register(client)
    assert client.get("/app").status_code == 200
    client.post("/logout", data={"csrf": csrf(client)})
    assert client.get("/app").status_code == 303
    r = client.post("/login", data={"csrf": csrf(client), "email": "A@Example.com", "password": "correct-horse-1"})
    assert r.status_code == 303 and r.headers["location"] == "/app"


def test_password_is_hashed(client):
    register(client)
    with dbmod.session_scope() as s:
        u = s.scalar(select(User))
        assert u.password_hash.startswith("$argon2id$") and "correct-horse-1" not in u.password_hash


def test_wrong_password_generic_error(client):
    register(client)
    client.post("/logout", data={"csrf": csrf(client)})
    r1 = client.post("/login", data={"csrf": csrf(client), "email": "a@example.com", "password": "wrong-password"})
    r2 = client.post("/login", data={"csrf": csrf(client), "email": "nobody@example.com", "password": "wrong-password"})
    assert r1.status_code == r2.status_code == 400
    assert "incorrectos" in r1.text and "incorrectos" in r2.text


def test_register_validation(client):
    r = client.post("/register", data={"csrf": csrf(client), "email": "bad", "password": "x", "accept_terms": "yes"})
    assert r.status_code == 400
    r = client.post("/register", data={"csrf": csrf(client), "email": "a@b.com", "password": "short", "accept_terms": "yes"})
    assert r.status_code == 400
    r = client.post("/register", data={"csrf": csrf(client), "email": "a@b.com", "password": "long-enough-pw"})
    assert r.status_code == 400  # terms not accepted


def test_login_rate_limited(client):
    register(client)
    client.post("/logout", data={"csrf": csrf(client)})
    codes = [client.post("/login", data={"csrf": csrf(client), "email": "a@example.com", "password": "nope-nope-nope"}).status_code
             for _ in range(10)]
    assert codes[-1] == 429


def test_register_rate_limited(client):
    codes = []
    for i in range(7):
        client.cookies.delete("sid")
        codes.append(client.post("/register", data={"csrf": csrf(client), "email": f"u{i}@x.com",
                                                    "password": "long-enough-pw", "accept_terms": "yes"}).status_code)
    assert codes[:5] == [303] * 5 and codes[-1] == 429


def test_password_reset_flow(client, monkeypatch):
    register(client)
    client.post("/logout", data={"csrf": csrf(client)})
    sent = {}
    from app.web import auth_routes
    monkeypatch.setattr(auth_routes, "send_email", lambda to, subj, text: sent.update(text=text))
    r = client.post("/forgot", data={"csrf": csrf(client), "email": "a@example.com"})
    assert r.status_code == 200 and "Si existe" in r.text
    token = re.search(r"/reset/([\w-]+)", sent["text"]).group(1)
    r = client.post(f"/reset/{token}", data={"csrf": csrf(client), "password": "brand-new-pass-9"})
    assert r.status_code == 303
    # token is single-use
    r = client.post(f"/reset/{token}", data={"csrf": csrf(client), "password": "another-pass-99"})
    assert r.status_code == 400
    r = client.post("/login", data={"csrf": csrf(client), "email": "a@example.com", "password": "brand-new-pass-9"})
    assert r.status_code == 303


def test_forgot_unknown_email_same_answer(client):
    r = client.post("/forgot", data={"csrf": csrf(client), "email": "ghost@example.com"})
    assert r.status_code == 200 and "Si existe" in r.text


def test_session_cookie_flags(client):
    r = register(client)
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "samesite=lax" in cookie.lower()


# ------------------------------------------------------------------ CSRF / headers
def test_csrf_required(client):
    register(client)
    r = client.post("/app/domains", data={"hostname": "x.com", "authorized": "yes"})
    assert r.status_code == 400
    r = client.post("/app/domains", data={"csrf": "forged", "hostname": "x.com", "authorized": "yes"})
    assert r.status_code == 400


def test_security_headers(client):
    r = client.get("/")
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp and "unsafe-inline" not in csp
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}


# ------------------------------------------------------------------ scans & reports
def test_add_domain_requires_authorization(client):
    register(client)
    r = client.post("/app/domains", data={"csrf": csrf(client), "hostname": "acme-test.com"})
    assert "autorizado" in r.headers["location"] or "autorizado" in r.headers["location"].encode().decode()
    with dbmod.session_scope() as s:
        assert s.scalar(select(func.count(Domain.id))) == 0


def test_add_domain_scan_and_report(client):
    register(client)
    loc = add_domain(client)
    r = client.get(loc)
    assert r.status_code == 303 and r.headers["location"].endswith("/report")
    rep = client.get(loc + "/report")
    assert rep.status_code == 200 and "acme-test.com" in rep.text and "Problemas por prioridad" in rep.text
    assert "No sustituye a una auditoría profesional" in rep.text or "no sustituye a una auditoría profesional" in rep.text.lower()
    assert client.get(loc + "/report?lang=en").text.count("Issues by priority") == 1
    with dbmod.session_scope() as s:
        d = s.scalar(select(Domain))
        assert d.authorized_at and d.authorization_statement and d.authorized_by_user_id
        scan = s.scalar(select(Scan))
        assert scan.status == "completed" and scan.analysis_version and scan.findings
        assert s.scalar(select(func.count(AuditLog.id)).where(AuditLog.action == "scan_completed")) == 1


def test_internal_domain_rejected(client):
    register(client)
    for host in ("localhost", "10.0.0.1", "169.254.169.254", "db.internal"):
        r = client.post("/app/domains", data={"csrf": csrf(client), "hostname": host, "authorized": "yes"})
        assert "err=" in r.headers["location"]
    with dbmod.session_scope() as s:
        assert s.scalar(select(func.count(Domain.id))) == 0


def test_failed_scan_shows_message(client):
    register(client)
    def failing(host):
        raise ScanError("nxdomain", "nope")
    client.scanner_state["scanner"] = failing
    loc = add_domain(client, "does-not-exist-123.com")
    r = client.get(loc)
    assert r.status_code == 200 and "El análisis falló" in r.text and "no existe" in r.text
    assert client.get(loc + "/status").json()["status"] == "failed"


def test_scanner_crash_is_contained(client):
    register(client)
    def crash(host):
        raise RuntimeError("boom")
    client.scanner_state["scanner"] = crash
    loc = add_domain(client)
    assert client.get(loc + "/status").json()["status"] == "failed"


def test_free_plan_limits(client):
    register(client)
    add_domain(client, "one.com")
    r = client.post("/app/domains", data={"csrf": csrf(client), "hostname": "two.com", "authorized": "yes"})
    assert "plan" in r.headers["location"].lower()
    # export and technical view are paid features
    with dbmod.session_scope() as s:
        pid = s.scalar(select(Scan)).public_id
    assert client.get(f"/scans/{pid}/export.json").status_code == 402
    assert "Detalles técnicos" not in client.get(f"/scans/{pid}/report?level=technical").text
    # monitoring requires a paid plan
    with dbmod.session_scope() as s:
        did = s.scalar(select(Domain)).id
    r = client.post(f"/app/domains/{did}/monitoring", data={"csrf": csrf(client), "enabled": "yes", "interval": "24"})
    assert "Pro" in r.headers["location"] or "err=" in r.headers["location"]


def test_manual_scan_rate_limit(client):
    register(client)
    add_domain(client)
    with dbmod.session_scope() as s:
        did = s.scalar(select(Domain)).id
    r1 = client.post(f"/app/domains/{did}/scan", data={"csrf": csrf(client)})
    r2 = client.post(f"/app/domains/{did}/scan", data={"csrf": csrf(client)})
    assert r1.headers["location"].startswith("/scans/")
    assert "err=" in r2.headers["location"]


def test_paid_plan_features(client):
    register(client)
    _set_plan("a@example.com", "pro")
    loc = add_domain(client)
    assert client.get(loc + "/export.json").json()["disclaimer"].startswith("Automated assessment")
    assert "Detalles técnicos" in client.get(loc + "/report?level=technical").text
    r = client.post(loc + "/notes", data={"csrf": csrf(client), "notes": "<script>alert(1)</script> Revisado"})
    assert r.status_code == 303
    html = client.get(loc + "/report").text
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html  # escaped


def test_white_label_brand_color_validated(client):
    register(client)
    _set_plan("a@example.com", "agency")
    client.post("/app/branding", data={"csrf": csrf(client), "brand_name": "Agencia X", "brand_color": "red;}</style><script>",
                                       "report_lang": "es"})
    assert _org("a@example.com").brand_color is None
    client.post("/app/branding", data={"csrf": csrf(client), "brand_name": "Agencia X", "brand_color": "#112233", "report_lang": "es"})
    loc = add_domain(client)
    html = client.get(loc + "/report").text
    assert "Agencia X" in html and "--brand: #112233" in html


def test_webhook_channel_ssrf_blocked(client):
    register(client)
    _set_plan("a@example.com", "pro")
    for url in ("http://example.com/hook", "https://localhost/hook", "https://169.254.169.254/latest", "https://10.0.0.1/x"):
        r = client.post("/app/channels", data={"csrf": csrf(client), "kind": "webhook", "target": url})
        assert "err=" in r.headers["location"], url


# ------------------------------------------------------------------ multi-tenancy
def test_tenant_isolation(client):
    register(client, "alice@example.com")
    loc = add_domain(client, "alice-co.com")
    pid = loc.rsplit("/", 1)[1]
    with dbmod.session_scope() as s:
        did = s.scalar(select(Domain)).id
    client.post("/logout", data={"csrf": csrf(client)})
    register(client, "bob@example.com")
    _set_plan("bob@example.com", "business")
    for path in (f"/scans/{pid}", f"/scans/{pid}/report", f"/scans/{pid}/status", f"/scans/{pid}/export.json",
                 f"/app/domains/{did}"):
        assert client.get(path).status_code == 404, path
    for path in (f"/app/domains/{did}/scan", f"/app/domains/{did}/delete", f"/app/domains/{did}/monitoring",
                 f"/scans/{pid}/notes", f"/scans/{pid}/delete"):
        assert client.post(path, data={"csrf": csrf(client), "enabled": "yes"}).status_code == 404, path
    assert "alice-co.com" not in client.get("/app").text
    with dbmod.session_scope() as s:
        assert s.scalar(select(func.count(Domain.id))) == 1 and s.scalar(select(func.count(Scan.id))) == 1


def test_admin_hidden_from_users(client):
    register(client)
    assert client.get("/admin").status_code == 404
    with dbmod.session_scope() as s:
        s.scalar(select(User)).is_admin = True
    r = client.get("/admin")
    assert r.status_code == 200 and "MRR" in r.text


# ------------------------------------------------------------------ public lead-gen check
def test_public_check_requires_authorization(client):
    r = client.post("/check", data={"csrf": csrf(client), "domain": "acme-test.com"})
    assert r.status_code == 400


def test_public_check_teaser_and_cache(client):
    r = client.post("/check", data={"csrf": csrf(client), "domain": "acme-test.com", "authorized": "yes",
                                    "email": "lead@x.com"})
    assert r.status_code == 303
    page = client.get(r.headers["location"])
    assert page.status_code == 200 and "Obtener el informe completo" in page.text
    assert page.text.count('class="finding ') == 3  # teaser only
    r2 = client.post("/check", data={"csrf": csrf(client), "domain": "ACME-test.com", "authorized": "yes"})
    assert r2.headers["location"] == r.headers["location"]  # cached: no second scan of the same target
    with dbmod.session_scope() as s:
        assert s.scalar(select(func.count(Scan.id))) == 1 and s.scalar(select(func.count(Lead.id))) == 2


def test_public_check_rate_limit(client):
    codes = [client.post("/check", data={"csrf": csrf(client), "domain": f"site{i}.com", "authorized": "yes"}).status_code
             for i in range(4)]
    assert codes == [303, 303, 303, 429]


def test_public_check_rejects_private(client):
    r = client.post("/check", data={"csrf": csrf(client), "domain": "127.0.0.1", "authorized": "yes"})
    assert r.status_code == 400


def test_public_result_not_listing_private_scans(client):
    register(client)
    loc = add_domain(client)
    pid = loc.rsplit("/", 1)[1]
    assert client.get(f"/check/{pid}").status_code == 404  # account scans are not exposed publicly


def test_demo_is_labelled(client):
    r = client.get("/demo")
    assert r.status_code == 200 and "DEMO" in r.text and "Datos ficticios" in r.text
    assert "DEMO" in client.get("/").text


# ------------------------------------------------------------------ privacy
def test_delete_domain_cascades(client):
    register(client)
    add_domain(client)
    with dbmod.session_scope() as s:
        did = s.scalar(select(Domain)).id
    client.post(f"/app/domains/{did}/delete", data={"csrf": csrf(client)})
    with dbmod.session_scope() as s:
        assert s.scalar(select(func.count(Scan.id))) == 0 and s.scalar(select(func.count(Finding.id))) == 0


def test_delete_account(client):
    register(client)
    add_domain(client)
    r = client.post("/app/account/delete", data={"csrf": csrf(client), "confirm": "nope"})
    assert "err" in r.headers["location"]
    client.post("/app/account/delete", data={"csrf": csrf(client), "confirm": "DELETE"})
    with dbmod.session_scope() as s:
        assert s.scalar(select(func.count(User.id))) == 0
        assert s.scalar(select(func.count(Domain.id))) == 0
        assert s.scalar(select(func.count(Organization.id))) == 0
    assert client.get("/app").status_code == 303


def test_reset_token_not_logged(client, caplog):
    import logging
    with caplog.at_level(logging.INFO, logger="app.http"):
        client.get("/reset/supersecrettoken123")
    assert "supersecrettoken123" not in caplog.text


def test_no_raw_ip_or_password_stored(client):
    register(client)
    with dbmod.session_scope() as s:
        for log in s.scalars(select(AuditLog)).all():
            assert "testclient" not in str(log.ip_hash) and "correct-horse-1" not in str(log.detail)
