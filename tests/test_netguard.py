import pytest

from app.scanner import netguard
from app.scanner.netguard import InvalidDomain, UnsafeTarget, normalize_domain


@pytest.mark.parametrize("raw,expected", [
    ("Example.COM", "example.com"),
    ("https://www.example.com/path?q=1", "www.example.com"),
    ("example.com.", "example.com"),
    ("example.com:8443", "example.com"),
    ("  shop.example.co.uk ", "shop.example.co.uk"),
    ("münchen.de", "xn--mnchen-3ya.de"),
])
def test_normalize_valid(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "localhost", "intranet", "foo.local", "printer.internal", "a.test",
                                 "-bad.com", "bad_char!.com", "a" * 300, "x.123"])
def test_normalize_invalid_or_internal(raw):
    with pytest.raises((InvalidDomain, UnsafeTarget)):
        normalize_domain(raw)


@pytest.mark.parametrize("raw", ["127.0.0.1", "10.0.0.5", "169.254.169.254", "[::1]", "http://192.168.1.1/admin"])
def test_ip_literals_rejected(raw):
    with pytest.raises((UnsafeTarget, InvalidDomain)):
        normalize_domain(raw)


def test_userinfo_trick_rejected():
    with pytest.raises(InvalidDomain):
        normalize_domain("http://good.com@evil.internal/")


@pytest.mark.parametrize("ip,public", [
    ("8.8.8.8", True), ("2606:4700::1111", True), ("127.0.0.1", False), ("10.1.2.3", False),
    ("172.16.0.1", False), ("192.168.0.1", False), ("169.254.169.254", False), ("100.64.0.1", False),
    ("0.0.0.0", False), ("::1", False), ("fd00::1", False), ("::ffff:10.0.0.1", False), ("224.0.0.1", False),
])
def test_is_public_ip(ip, public):
    assert netguard.is_public_ip(ip) is public


def test_resolve_public_rejects_any_private(fake_resolver):
    r = fake_resolver({("rebind.com", "A"): ["93.184.216.34", "127.0.0.1"]})
    with pytest.raises(UnsafeTarget):
        netguard.resolve_public("rebind.com", r)


def test_resolve_public_ok(fake_resolver):
    r = fake_resolver({("ok.com", "A"): ["93.184.216.34"], ("ok.com", "AAAA"): ["2606:2800:220:1::1"]})
    assert netguard.resolve_public("ok.com", r) == ["93.184.216.34", "2606:2800:220:1::1"]


def test_resolve_public_no_records(fake_resolver):
    with pytest.raises(UnsafeTarget):
        netguard.resolve_public("empty.com", fake_resolver({}))


@pytest.mark.parametrize("url", ["https://ok.com:8443/", "ftp://ok.com/", "gopher://ok.com/", "http://ok.com:22/"])
def test_one_request_rejects_ports_and_schemes(url, fake_resolver):
    r = fake_resolver({("ok.com", "A"): ["93.184.216.34"]})
    with pytest.raises(UnsafeTarget):
        netguard._one_request(url, "ua", 1, 100, r, False)


def test_redirect_to_metadata_is_blocked(monkeypatch, fake_resolver):
    resolver = fake_resolver({("metadata.attacker.com", "A"): ["169.254.169.254"]})
    original = netguard._one_request
    calls = []

    def fake_one(url, ua, timeout, max_bytes, res, read_body):
        calls.append(url)
        if len(calls) == 1:
            return netguard.Hop(url=url, status=302, headers=[("location", "http://metadata.attacker.com/latest/")],
                                ip="93.184.216.34"), ""
        return original(url, ua, timeout, max_bytes, res, read_body)

    monkeypatch.setattr(netguard, "_one_request", fake_one)
    res = netguard.safe_fetch("https://ok.com/", user_agent="ua", resolver=resolver)
    assert res.error == "blocked"
    assert res.hops[-1].error.startswith("blocked")


def test_redirect_loop_limited(monkeypatch):
    def loop(url, *a):
        return netguard.Hop(url=url, status=301, headers=[("location", url)]), ""
    monkeypatch.setattr(netguard, "_one_request", loop)
    res = netguard.safe_fetch("https://ok.com/", user_agent="ua", max_redirects=3)
    assert res.error == "too_many_redirects" and len(res.hops) == 4


def test_connection_error_reported(monkeypatch):
    def boom(*a):
        raise ConnectionRefusedError("refused")
    monkeypatch.setattr(netguard, "_one_request", boom)
    res = netguard.safe_fetch("https://ok.com/", user_agent="ua")
    assert res.error == "connection" and "ConnectionRefusedError" in res.hops[0].error
