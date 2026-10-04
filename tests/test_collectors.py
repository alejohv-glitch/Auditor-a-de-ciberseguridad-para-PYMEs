import datetime as dt
import ssl

import dns.exception
import dns.resolver
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.scanner import engine, tls_checks
from app.scanner.dns_checks import collect_dns, query
from app.scanner.email_checks import collect_email, count_spf_lookups, parse_dmarc, parse_spf
from app.scanner.web_checks import detect_technologies, parse_set_cookie


# ------------------------------------------------------------------ DNS
def test_query_statuses(fake_resolver):
    r = fake_resolver({("a.com", "A"): ["1.2.3.4"], ("nx.com", "A"): dns.resolver.NXDOMAIN,
                       ("slow.com", "A"): dns.exception.Timeout})
    assert query(r, "a.com", "A") == {"status": "ok", "records": ["1.2.3.4"]}
    assert query(r, "nx.com", "A")["status"] == "nxdomain"
    assert query(r, "slow.com", "A")["status"] == "timeout"
    assert query(r, "none.com", "A")["status"] == "nodata"


def test_collect_dns_nonexistent(fake_resolver):
    nx = dns.resolver.NXDOMAIN
    r = fake_resolver({(n, t): nx for n in ("ghost.com", "www.ghost.com") for t in ("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA", "DS", "CNAME")})
    facts = collect_dns("ghost.com", "ghost.com", r)
    assert facts["domain_exists"] is False


def test_collect_dns_all_timeouts(fake_resolver):
    to = dns.exception.Timeout
    r = fake_resolver({("t.com", t): to for t in ("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA", "DS")})
    assert collect_dns("t.com", "t.com", r)["resolver_ok"] is False


def test_run_scan_nxdomain_raises(monkeypatch, fake_resolver):
    nx = dns.resolver.NXDOMAIN
    r = fake_resolver({(n, t): nx for n in ("ghost.com", "www.ghost.com") for t in ("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA", "DS", "CNAME")})
    with pytest.raises(engine.ScanError) as e:
        engine.run_scan("ghost.com", resolver=r)
    assert e.value.code == "nxdomain"


def test_run_scan_private_target_refused(fake_resolver):
    r = fake_resolver({("evil.com", "A"): ["10.0.0.1"], ("evil.com", "NS"): ["ns.evil.com"],
                       ("evil.com", "SOA"): ["x"]})
    with pytest.raises(engine.ScanError) as e:
        engine.run_scan("evil.com", resolver=r)
    assert e.value.code == "unsafe_target"


def test_run_scan_dns_timeout(fake_resolver):
    to = dns.exception.Timeout
    r = fake_resolver({("t.com", t): to for t in ("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA", "DS")})
    with pytest.raises(engine.ScanError) as e:
        engine.run_scan("t.com", resolver=r)
    assert e.value.code == "dns_timeout"


def test_run_scan_mail_only_domain(fake_resolver):
    """Domain with no website: e-mail checks still run, web checks are skipped."""
    r = fake_resolver({("mailonly.com", "NS"): ["ns1.x.com", "ns2.x.com"], ("mailonly.com", "SOA"): ["x"],
                       ("mailonly.com", "TXT"): ["v=spf1 -all"], ("_dmarc.mailonly.com", "TXT"): ["v=DMARC1; p=reject"]})
    facts = engine.run_scan("mailonly.com", resolver=r)
    assert facts["tls"]["available"] is False and facts["meta"]["ips"] == []
    assert facts["email"]["spf"]["all"] == "-"


# ---------------------------------------------------------------- e-mail
def test_parse_spf():
    p = parse_spf("v=spf1 ip4:1.2.3.4 include:_spf.google.com ~all")
    assert p["all"] == "~" and [m["mechanism"] for m in p["mechanisms"]] == ["ip4", "include", "all"]
    assert parse_spf("v=spf1 redirect=_spf.x.com")["redirect"] == "_spf.x.com"
    assert parse_spf("v=spf1 +all")["all"] == "+"
    assert parse_spf("v=spf1 a mx")["all"] is None


def test_spf_lookup_count_recursive(fake_resolver):
    r = fake_resolver({("inc1.com", "TXT"): ["v=spf1 include:inc2.com a mx"],
                       ("inc2.com", "TXT"): ["v=spf1 ip4:1.1.1.1 include:inc1.com"]})  # loop
    n = count_spf_lookups(r, "v=spf1 include:inc1.com mx ~all", [20], set())
    assert n == 2 + 3 + 1  # top: include+mx; inc1: include+a+mx; inc2: include (loop not followed)


def test_parse_dmarc():
    assert parse_dmarc("v=DMARC1; p=quarantine; rua=mailto:x@y.com; pct=50") == {
        "v": "DMARC1", "p": "quarantine", "rua": "mailto:x@y.com", "pct": "50"}


def test_collect_email_missing_everything(fake_resolver):
    e = collect_email("bare.com", fake_resolver({}))
    assert e["spf"]["records"] == [] and e["dmarc"]["records"] == [] and e["dkim"]["found"] == []
    assert e["mx"]["hosts"] == []


def test_collect_email_multiple_spf_and_dkim(fake_resolver):
    r = fake_resolver({("x.com", "TXT"): ["v=spf1 a -all", "v=spf1 mx -all"],
                       ("x.com", "MX"): ["10 mail.x.com."],
                       ("google._domainkey.x.com", "TXT"): ["v=DKIM1; k=rsa; p=MIIBIjAN"],
                       ("_dmarc.x.com", "TXT"): ["v=DMARC1; p=reject"]})
    e = collect_email("x.com", r)
    assert len(e["spf"]["records"]) == 2 and e["dkim"]["found"] == ["google"]
    assert e["dmarc"]["tags"]["p"] == "reject"


# ------------------------------------------------------------------- TLS
def _self_signed(days_valid: int, cn="x.com") -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - dt.timedelta(days=60)).not_valid_after(now + dt.timedelta(days=days_valid))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), False).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


def test_parse_certificate():
    c = tls_checks.parse_certificate(_self_signed(30))
    assert c["subject_cn"] == "x.com" and c["self_signed"] and 28 <= c["days_remaining"] <= 30
    assert c["sans"] == ["x.com"] and c["key_type"] == "ECDSA"


def test_parse_expired_certificate():
    assert tls_checks.parse_certificate(_self_signed(-5))["days_remaining"] < 0


def test_collect_tls_no_ip():
    assert tls_checks.collect_tls("x.com", None)["error"] == "no_public_ip"


def test_collect_tls_https_down(monkeypatch):
    def refused(*a):
        raise ConnectionRefusedError()
    monkeypatch.setattr(tls_checks, "_handshake", refused)
    f = tls_checks.collect_tls("x.com", "93.184.216.34")
    assert f["available"] is False and f["error"] == "connect_failed"


def test_collect_tls_invalid_cert(monkeypatch):
    der = _self_signed(30, "other.com")
    calls = []

    def hs(ip, host, ctx, timeout):
        calls.append(ctx.verify_mode)
        if ctx.verify_mode == ssl.CERT_REQUIRED and ctx.maximum_version != ssl.TLSVersion.TLSv1:
            err = ssl.SSLCertVerificationError("certificate verify failed")
            err.verify_message, err.verify_code = "self-signed certificate", 18
            raise err
        return "TLSv1.3", ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128), der

    monkeypatch.setattr(tls_checks, "_handshake", hs)
    monkeypatch.setattr(tls_checks, "_probe_legacy", lambda *a: "not_supported")
    f = tls_checks.collect_tls("x.com", "93.184.216.34")
    assert f["verified"] is False and f["verify_error"] == "self-signed certificate"
    assert f["certificate"]["subject_cn"] == "other.com"


def test_collect_tls_slow_service(monkeypatch):
    def slow(*a):
        raise TimeoutError()
    monkeypatch.setattr(tls_checks, "_handshake", slow)
    assert tls_checks.collect_tls("x.com", "93.184.216.34")["available"] is False


# ------------------------------------------------------------------- HTTP
def test_parse_set_cookie():
    c = parse_set_cookie("PHPSESSID=abc; path=/; HttpOnly; SameSite=Lax")
    assert c == {"name": "PHPSESSID", "secure": False, "httponly": True, "samesite": "Lax", "session_like": True}
    assert parse_set_cookie("_ga=1; Secure")["session_like"] is False


def test_detect_technologies():
    t = detect_technologies({"server": "nginx/1.18.0", "cf-ray": "x", "x-powered-by": "PHP/8.1.2"},
                            '<meta name="generator" content="WordPress 6.4.2"><link href="/wp-content/x.css">')
    names = {x["name"]: x for x in t}
    assert names["nginx"]["version"] == "1.18.0" and "Cloudflare" in names
    assert names["WordPress"]["version"] == "6.4.2" and names["PHP"]["version"] == "8.1.2"
