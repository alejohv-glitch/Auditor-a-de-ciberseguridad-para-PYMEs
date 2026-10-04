import pytest

from app.models import Finding, Scan
from app.reports import build_report, render_finding
from app.rules.catalog import RULES
from app.rules.engine import Result, evaluate
from app.scoring import WEIGHTS, compute_score, grade_for


def by_id(results):
    return {r.rule_id: r for r in results}


def perfect(f):
    """Mutate demo facts into a well-configured domain."""
    f["email"]["spf"].update(records=["v=spf1 include:spf.protection.outlook.com -all"], all="-", lookups=2)
    f["email"]["dmarc"] = {"status": "ok", "records": ["v=DMARC1; p=reject; rua=mailto:d@x.com"],
                           "tags": {"p": "reject", "rua": "mailto:d@x.com"}}
    f["email"]["mta_sts"] = True
    f["tls"]["certificate"]["days_remaining"] = 80
    f["tls"]["legacy"] = {"TLSv1": "not_supported", "TLSv1.1": "not_supported"}
    f["web"]["final"]["headers"] = {
        "strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "permissions-policy": "camera=()",
        "server": "nginx"}
    f["web"]["final"]["cookies"] = [{"name": "sid", "secure": True, "httponly": True, "samesite": "Lax", "session_like": True}]
    f["web"]["technologies"] = []
    f["web"]["security_txt"] = True
    f["dns"]["CAA"] = {"status": "ok", "records": [{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}]}
    f["dns"]["DS"] = {"status": "ok", "records": ["x"]}
    return f


def test_perfect_domain_scores_100(facts):
    s = compute_score(evaluate(perfect(facts)))
    assert s["score"] == 100 and s["grade"] == "A" and s["deductions"] == []


def test_dmarc_missing_is_high_and_caps(facts):
    f = perfect(facts)
    f["email"]["dmarc"] = {"status": "nxdomain", "records": []}
    res = by_id(evaluate(f))
    assert res["dmarc_present"].status == "fail" and res["dmarc_present"].severity == "high"
    s = compute_score(list(res.values()))
    assert s["score"] <= 70 and s["counts"]["high"] == 1


def test_spf_plus_all_is_critical(facts):
    f = perfect(facts)
    f["email"]["spf"].update(records=["v=spf1 +all"], all="+")
    r = by_id(evaluate(f))["spf_all"]
    assert r.severity == "critical"
    s = compute_score(evaluate(f))
    assert s["score"] <= 40 and s["cap"] == "critical"


def test_spf_invalid_multiple(facts):
    f = perfect(facts)
    f["email"]["spf"] = {"status": "ok", "records": ["v=spf1 a -all", "v=spf1 mx -all"]}
    assert by_id(evaluate(f))["spf_single"].severity == "high"


def test_spf_too_many_lookups(facts):
    f = perfect(facts)
    f["email"]["spf"]["lookups"] = 14
    assert by_id(evaluate(f))["spf_lookups"].severity == "medium"


def test_domain_without_mx(facts):
    f = perfect(facts)
    f["email"]["mx"] = {"status": "nodata", "hosts": [], "null_mx": False}
    f["email"]["spf"] = {"status": "nodata", "records": []}
    res = by_id(evaluate(f))
    assert res["spf_present"].severity == "medium"  # still spoofable, but not a mail domain
    assert res["dkim_found"].status == "na" and res["mta_sts"].status == "na"


def test_dkim_not_found_is_unknown_not_penalised(facts):
    f = perfect(facts)
    f["email"]["dkim"]["found"] = []
    res = evaluate(f)
    assert by_id(res)["dkim_found"].status == "unknown"
    assert compute_score(res)["score"] == 100


def test_dmarc_policy_none_and_pct(facts):
    f = perfect(facts)
    f["email"]["dmarc"]["tags"] = {"p": "none", "rua": "x"}
    assert by_id(evaluate(f))["dmarc_policy"].severity == "medium"
    f["email"]["dmarc"]["tags"] = {"p": "reject", "pct": "20", "rua": "x"}
    assert by_id(evaluate(f))["dmarc_policy"].severity == "low"
    f["email"]["dmarc"]["tags"] = {"p": "bogus"}
    assert by_id(evaluate(f))["dmarc_valid"].severity == "high"


def test_https_down(facts):
    f = perfect(facts)
    f["tls"] = {"available": False, "error": "connect_failed"}
    f["web"]["http"] = {"reachable": True, "redirects_to_https": False, "chain": [{"status": 200}]}
    res = by_id(evaluate(f))
    assert res["https_available"].severity == "high"
    assert res["http_redirect"].status == "fail"
    assert res["cert_trusted"].status == "na"


def test_invalid_certificate(facts):
    f = perfect(facts)
    f["tls"]["verified"] = False
    f["tls"]["verify_error"] = "certificate has expired"
    f["tls"]["certificate"]["days_remaining"] = -3
    res = by_id(evaluate(f))
    assert res["cert_trusted"].severity == "high" and res["cert_expiry"].status == "na"


@pytest.mark.parametrize("days,sev", [(3, "high"), (15, "medium"), (45, None)])
def test_cert_expiry_thresholds(facts, days, sev):
    f = perfect(facts)
    f["tls"]["certificate"]["days_remaining"] = days
    r = by_id(evaluate(f))["cert_expiry"]
    assert (r.severity if r.status == "fail" else None) == sev


def test_legacy_tls_unknown_when_probe_unavailable(facts):
    f = perfect(facts)
    f["tls"]["legacy"] = {"TLSv1": "unknown", "TLSv1.1": "not_supported"}
    assert by_id(evaluate(f))["tls_legacy"].status == "unknown"


def test_missing_headers_are_not_critical(facts):
    f = perfect(facts)
    f["web"]["final"]["headers"] = {}
    res = [r for r in evaluate(f) if r.category == "headers" and r.status == "fail"]
    assert {r.rule_id for r in res} == {"csp", "xcto", "frame_protection", "referrer_policy", "permissions_policy"}
    assert all(r.severity in ("low", "info") for r in res)


def test_cookie_rules(facts):
    f = perfect(facts)
    f["web"]["final"]["cookies"] = [{"name": "PHPSESSID", "secure": False, "httponly": False, "samesite": None, "session_like": True},
                                    {"name": "_ga", "secure": False, "httponly": False, "samesite": None, "session_like": False}]
    res = by_id(evaluate(f))
    assert res["cookie_secure"].severity == "medium" and "PHPSESSID" in res["cookie_secure"].evidence["names"]
    assert res["cookie_httponly"].status == "fail" and "_ga" not in res["cookie_httponly"].evidence["names"]


def test_no_cookies_category_excluded_and_rescaled(facts):
    f = perfect(facts)
    f["web"]["final"]["cookies"] = []
    s = compute_score(evaluate(f))
    assert s["categories"]["cookies"]["applicable"] is False and s["score"] == 100
    assert abs(sum(c["weight"] for c in s["categories"].values()) - 100) < 0.5


def test_version_disclosure(facts):
    f = perfect(facts)
    f["web"]["final"]["headers"]["server"] = "Apache/2.4.41 (Ubuntu)"
    assert by_id(evaluate(f))["server_version"].severity == "low"


def test_dns_timeout_is_unknown(facts):
    f = perfect(facts)
    f["dns"]["NS"] = {"status": "timeout", "records": []}
    f["email"]["spf"] = {"status": "timeout", "records": []}
    res = by_id(evaluate(f))
    assert res["ns_redundancy"].status == "unknown" and res["spf_present"].status == "unknown"


def test_incomplete_facts_do_not_crash(facts):
    f = {"meta": facts["meta"], "dns": {}, "email": {}, "tls": {}, "web": {}}
    s = compute_score(evaluate(f))
    assert 0 <= s["score"] <= 100


def test_deductions_explain_every_point(facts):
    s = compute_score(evaluate(facts))
    assert abs((100 - sum(d["points"] for d in s["deductions"])) - s["raw_score"]) <= 1


def test_grades():
    assert [grade_for(x) for x in (95, 80, 65, 45, 10)] == list("ABCDF")
    assert sum(WEIGHTS.values()) == 100


def test_every_rule_renders_both_languages(facts):
    for rule_id in RULES:
        for lang in ("es", "en"):
            for status in ("fail", "pass"):
                out = render_finding(rule_id, status, "medium", {}, lang)
                assert out["title"] and out["why"] and out["fix"]


def test_report_from_demo_has_no_missing_placeholders(facts):
    res = evaluate(facts)
    score = compute_score(res)
    scan = Scan(hostname="x.com", summary=score,
                findings=[Finding(rule_id=r.rule_id, status=r.status, severity=r.severity, evidence=r.evidence) for r in res])
    for lang in ("es", "en"):
        rep = build_report(scan, lang)
        assert rep["problems"] and rep["summary"]
        for p in rep["problems"]:
            assert "?" not in p["found"].replace("?all", ""), p
        order = ["critical", "high", "medium", "low", "info"]
        sevs = [order.index(p["severity"]) for p in rep["problems"]]
        assert sevs == sorted(sevs)


def test_result_to_dict():
    d = Result("csp", "fail", "low").to_dict()
    assert d["category"] == "headers" and d["kind"] == "hardening"


def test_waf_block_page_is_not_graded(facts):
    f = perfect(facts)
    f["web"]["final"].update(status=403, headers={"content-type": "text/plain"}, cookies=[])
    f["web"]["blocked_response"] = True
    f["web"]["http"]["blocked"] = True
    f["web"]["http"]["redirects_to_https"] = False
    res = by_id(evaluate(f))
    for rid in ("csp", "xcto", "hsts", "http_redirect", "server_version"):
        assert res[rid].status == "unknown", rid
    assert compute_score(list(res.values()))["score"] == 100
