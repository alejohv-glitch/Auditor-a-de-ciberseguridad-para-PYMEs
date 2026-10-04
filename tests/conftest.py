import copy
import os

os.environ["DATABASE_URL"] = "sqlite://"
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("EMAIL_BACKEND", "console")

import dns.exception  # noqa: E402
import dns.resolver  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import db as dbmod  # noqa: E402
from app.demo import demo_facts  # noqa: E402
from app.security import limiter  # noqa: E402


class _Rec:
    def __init__(self, text):
        self._t = text

    def to_text(self):
        return self._t


class _Txt:
    def __init__(self, s):
        self.strings = [s.encode()]


class _Mx:
    def __init__(self, s):
        pref, exch = s.split()
        self.preference, self.exchange = int(pref), _Rec(exch)


class FakeResolver:
    """records: {(name, rtype): list | Exception class}"""

    def __init__(self, records=None):
        self.records = records or {}
        self.queries = []

    def resolve(self, name, rtype):
        self.queries.append((name, rtype))
        val = self.records.get((name, rtype))
        if val is None:
            raise dns.resolver.NoAnswer()
        if isinstance(val, type) and issubclass(val, Exception):
            raise val()
        if rtype == "TXT":
            return [_Txt(v) for v in val]
        if rtype == "MX":
            return [_Mx(v) for v in val]
        return [_Rec(v) for v in val]


@pytest.fixture
def fake_resolver():
    return FakeResolver


def fake_scanner_factory(mutate=None):
    def scanner(hostname):
        f = copy.deepcopy(demo_facts())
        f["meta"]["target"] = f["meta"]["base_domain"] = hostname
        f["email"]["domain"] = hostname
        f["meta"].pop("demo", None)
        if mutate:
            mutate(f)
        return f
    return scanner


@pytest.fixture
def facts():
    f = copy.deepcopy(demo_facts())
    f["meta"].pop("demo", None)
    return f


@pytest.fixture
def client(monkeypatch):
    dbmod.Base.metadata.drop_all(dbmod.engine)
    dbmod.init_db()
    limiter.reset()
    from app import services
    from app.main import app
    from app.web import dashboard, public

    state = {"scanner": fake_scanner_factory()}

    def sync_submit(scan_id):
        services.execute_scan(scan_id, state["scanner"])

    monkeypatch.setattr(dashboard, "submit", sync_submit)
    monkeypatch.setattr(public, "submit", sync_submit)
    c = TestClient(app, follow_redirects=False)
    c.get("/login")
    c.scanner_state = state
    return c


def csrf(c):
    return c.cookies.get("csrftoken")


def register(c, email="a@example.com", password="correct-horse-1"):
    r = c.post("/register", data={"csrf": csrf(c), "email": email, "password": password, "accept_terms": "yes"})
    assert r.status_code == 303, r.text
    return r


def add_domain(c, host="acme-test.com"):
    r = c.post("/app/domains", data={"csrf": csrf(c), "hostname": host, "authorized": "yes"})
    assert r.status_code == 303
    return r.headers["location"]
