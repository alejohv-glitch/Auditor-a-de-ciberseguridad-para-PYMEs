import datetime as dt

from sqlalchemy import func, select

from app import db as dbmod
from app import notify, services
from app.db import utcnow
from app.demo import seed_demo
from app.models import Domain, Lead, Notification, NotificationChannel, Organization, Scan, ScoreHistory, User
from app.security import hash_password
from tests.conftest import fake_scanner_factory


def _setup(plan="pro", monitoring=True):
    dbmod.Base.metadata.drop_all(dbmod.engine)
    dbmod.init_db()
    with dbmod.session_scope() as s:
        org = Organization(name="Acme", plan=plan)
        user = User(email="m@x.com", password_hash=hash_password("x" * 12))
        s.add_all([org, user])
        s.flush()
        d = Domain(org_id=org.id, hostname="acme-test.com", authorized_at=utcnow(), authorized_by_user_id=user.id,
                   authorization_statement="ok", monitoring_enabled=monitoring)
        s.add(d)
        s.add(NotificationChannel(org_id=org.id, kind="webhook", target="https://hooks.example.com/x"))
        s.flush()
        return org.id, d.id


def test_monitoring_runs_due_domains_and_reschedules():
    _, did = _setup()
    assert services.run_monitoring(fake_scanner_factory()) == 1
    assert services.run_monitoring(fake_scanner_factory()) == 0  # not due again yet
    with dbmod.session_scope() as s:
        d = s.get(Domain, did)
        assert d.next_scan_at > utcnow() + dt.timedelta(hours=23)
        assert s.scalar(select(func.count(ScoreHistory.id))) == 1


def test_free_plan_not_monitored():
    _setup(plan="free")
    assert services.run_monitoring(fake_scanner_factory()) == 0


def test_change_detection_and_alert(monkeypatch):
    _, did = _setup()
    sent = []
    monkeypatch.setattr(notify, "dispatch", lambda kind, target, subject, text, payload: (sent.append(payload) or (True, None)))
    services.run_monitoring(fake_scanner_factory())
    assert sent == []  # first scan: baseline, no alert

    def worse(f):
        f["email"]["dmarc"] = {"status": "nxdomain", "records": []}
        f["dns"]["NS"]["records"] = ["ns1.other.example"]
    services.run_monitoring(fake_scanner_factory(worse), now=utcnow() + dt.timedelta(days=2))
    assert len(sent) == 1
    reasons = " ".join(sent[0]["reasons"])
    assert "dmarc_present" in reasons and "dns_ns" in reasons and "Score dropped" in reasons
    with dbmod.session_scope() as s:
        latest = s.scalars(select(Scan).where(Scan.domain_id == did).order_by(Scan.id.desc())).first()
        assert latest.changes["score_delta"] < 0 and "dmarc_present" in latest.changes["new"]
        assert s.scalar(select(func.count(Notification.id))) == 1


def test_cert_expiry_alert(monkeypatch):
    _setup()
    sent = []
    monkeypatch.setattr(notify, "dispatch", lambda *a: (sent.append(a[4]) or (True, None)))
    services.run_monitoring(fake_scanner_factory())
    services.run_monitoring(fake_scanner_factory(), now=utcnow() + dt.timedelta(days=2))
    # demo facts have a certificate expiring in 5 days
    assert any("Certificate expires" in r for p in sent for r in p["reasons"])


def test_failed_notification_is_recorded_not_raised(monkeypatch):
    _setup()

    class Boom(notify.Channel):
        kind = "webhook"

        def send(self, *a):
            raise notify.NotifyError("down")
    monkeypatch.setitem(notify.CHANNELS, "webhook", Boom())
    services.run_monitoring(fake_scanner_factory())

    def worse(f):
        f["email"]["dmarc"] = {"status": "nxdomain", "records": []}
    services.run_monitoring(fake_scanner_factory(worse), now=utcnow() + dt.timedelta(days=2))
    with dbmod.session_scope() as s:
        n = s.scalar(select(Notification))
        assert n.status == "failed" and n.detail == "NotifyError"


def test_channels_respect_plan(monkeypatch):
    org_id, _ = _setup()
    with dbmod.session_scope() as s:
        s.add(NotificationChannel(org_id=org_id, kind="discord", target="https://discord.example.com/x"))
    kinds = []
    monkeypatch.setattr(notify, "dispatch", lambda kind, *a: (kinds.append(kind) or (True, None)))
    services.run_monitoring(fake_scanner_factory())
    services.run_monitoring(fake_scanner_factory(lambda f: f["email"].update(dmarc={"status": "nxdomain", "records": []})),
                            now=utcnow() + dt.timedelta(days=2))
    assert kinds == ["webhook"]  # discord is a Business feature


def test_discord_and_webhook_payloads(monkeypatch):
    posted = []
    monkeypatch.setattr(notify, "validate_webhook_url", lambda u: u)

    class R:
        status_code = 204
    monkeypatch.setattr(notify.httpx, "post", lambda url, json, **k: (posted.append(json) or R()))
    assert notify.dispatch("discord", "https://d.example.com", "S", "T", {"event": "e"}) == (True, None)
    assert notify.dispatch("webhook", "https://w.example.com", "S", "T", {"event": "e"}) == (True, None)
    assert posted[0]["content"].startswith("**S**") and posted[1]["event"] == "e"
    assert notify.dispatch("carrier-pigeon", "x", "S", "T", {}) == (False, "unknown channel")


def test_stuck_scans_are_failed():
    _setup()
    with dbmod.session_scope() as s:
        s.add(Scan(public_id="stuck1", hostname="a.com", status="running", created_at=utcnow() - dt.timedelta(hours=1)))
    assert services.sweep_stuck() == 1
    with dbmod.session_scope() as s:
        assert s.scalar(select(Scan)).status == "failed"


def test_purge_retention():
    org_id, _ = _setup(plan="free")
    old = utcnow() - dt.timedelta(days=400)
    with dbmod.session_scope() as s:
        s.add(Lead(hostname="x.com", created_at=old))
        s.add(Scan(public_id="p1", hostname="x.com", trigger="public", status="completed", created_at=old))
        s.add(Scan(public_id="p2", hostname="x.com", org_id=org_id, status="completed", created_at=old))
        s.add(Scan(public_id="p3", hostname="x.com", org_id=org_id, status="completed"))
    out = services.purge_expired()
    assert out == {"leads": 1, "public_scans": 1, "history_scans": 1}


def test_demo_seed_is_marked_and_not_monitored():
    _setup()
    with dbmod.session_scope() as s:
        seed_demo(s)
    with dbmod.session_scope() as s:
        demo_org = s.scalar(select(Organization).where(Organization.is_demo.is_(True)))
        assert "DEMO" in demo_org.name
        assert all(sc.is_demo for sc in s.scalars(select(Scan).where(Scan.org_id == demo_org.id)))
        assert all(d.org_id != demo_org.id for d in services.due_domains(s, utcnow() + dt.timedelta(days=3)))
