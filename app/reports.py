"""Report view-model: turns stored findings into localized, prioritized content.

The executive summary is generated deterministically from findings (no LLM).
``Explainer`` is the extension point for an optional AI rewrite of the summary;
it only receives already-computed findings and may never add new ones.
"""
from __future__ import annotations

from .rules.catalog import CATEGORIES, EFFORT, KINDS, RULES, SEVERITY_LABELS
from .scoring import SEVERITY_ORDER


class _SafeDict(dict):
    def __missing__(self, key):  # unknown placeholders render as "?" instead of crashing
        return "?"


def render_finding(rule_id: str, status: str, severity: str, evidence: dict, lang: str,
                   points_lost: float = 0.0) -> dict:
    meta = RULES[rule_id]
    t = meta[lang]
    ev = dict(evidence or {})
    if lang == "en":
        ev.update({k[:-3]: v for k, v in ev.items() if k.endswith("_en")})
    fmt = _SafeDict({k: (", ".join(map(str, v)) if isinstance(v, list) else v) for k, v in ev.items()})
    return {
        "rule_id": rule_id,
        "status": status,
        "severity": severity,
        "severity_label": SEVERITY_LABELS[severity][lang],
        "category": meta["category"],
        "category_label": CATEGORIES[meta["category"]][lang],
        "kind": meta["kind"],
        "kind_label": KINDS[meta["kind"]][lang],
        "effort_label": EFFORT[meta["effort"]][lang],
        # For unverified controls name the control itself ("HSTS enabled"), not a problem.
        "title": (t["ok"] if status == "pass" or (status == "unknown" and rule_id != "dkim_found")
                  else t["title"]).format_map(fmt),
        "found": t["found"].format_map(fmt),
        "why": t["why"],
        "fix": t["fix"].format_map(fmt),
        "evidence": {k: v for k, v in ev.items() if not k.endswith("_en")},
        "points_lost": points_lost,
    }


TEXT = {
    "es": {
        "intro": "Hemos analizado {n} controles de seguridad públicamente observables de {domain}.",
        "none": "No encontramos problemas de prioridad alta o crítica en los controles analizados.",
        "top": "Lo más importante a corregir: {items}.",
        "email_risk": "Su dominio es más fácil de suplantar por correo de lo necesario (facturas falsas, fraude del CEO).",
        "web_risk": "Hay problemas en la conexión segura (HTTPS) de su web que los visitantes pueden notar.",
        "quick": "{n} de los problemas encontrados se pueden corregir en minutos con un cambio de configuración.",
        "unknown": "{n} controles no pudieron verificarse y no restan puntos.",
        "blocked": "La web respondió a nuestra petición automatizada con un bloqueo (cortafuegos o filtro anti-bots), así que sus cabeceras no se han evaluado. No intentamos sortear bloqueos.",
    },
    "en": {
        "intro": "We analysed {n} publicly observable security controls for {domain}.",
        "none": "We found no high or critical priority issues in the analysed controls.",
        "top": "Most important to fix: {items}.",
        "email_risk": "Your domain is easier to impersonate by email than it needs to be (fake invoices, CEO fraud).",
        "web_risk": "There are problems with your website's secure connection (HTTPS) that visitors may notice.",
        "quick": "{n} of the issues found can be fixed in minutes with a configuration change.",
        "unknown": "{n} controls could not be verified and do not reduce the score.",
        "blocked": "The website answered our automated request with a block (firewall or bot filter), so its headers were not assessed. We never try to bypass blocks.",
    },
}


def executive_summary(domain: str, findings: list[dict], lang: str) -> list[str]:
    t = TEXT[lang]
    fails = [f for f in findings if f["status"] == "fail"]
    checked = [f for f in findings if f["status"] in ("pass", "fail")]
    lines = [t["intro"].format(n=len(checked), domain=domain)]
    serious = [f for f in fails if f["severity"] in ("critical", "high")]
    if serious:
        lines.append(t["top"].format(items="; ".join(f["title"] for f in serious[:3])))
    else:
        lines.append(t["none"])
    if any(f["category"] == "email" and f["severity"] in ("critical", "high", "medium") for f in fails):
        lines.append(t["email_risk"])
    if any(f["category"] == "tls" and f["severity"] in ("critical", "high") for f in fails):
        lines.append(t["web_risk"])
    quick = [f for f in fails if RULES[f["rule_id"]]["effort"] == "low" and f["severity"] != "info"]
    if quick:
        lines.append(t["quick"].format(n=len(quick)))
    unknown = [f for f in findings if f["status"] == "unknown"]
    if any(f["evidence"].get("reason") == "blocked_response" for f in unknown):
        lines.append(t["blocked"])
    if unknown:
        lines.append(t["unknown"].format(n=len(unknown)))
    return lines


class Explainer:
    """Optional AI layer. Default: identity (deterministic summary is used as-is).
    An implementation may rephrase ``summary`` but receives only computed findings."""

    def rewrite_summary(self, summary: list[str], findings: list[dict], lang: str) -> list[str]:
        return summary


def build_report(scan, lang: str = "es", explainer: Explainer | None = None) -> dict:
    lang = lang if lang in ("es", "en") else "es"
    deductions = {d["rule_id"]: d["points"] for d in (scan.summary or {}).get("deductions", [])}
    findings = [render_finding(f.rule_id, f.status, f.severity, f.evidence, lang, deductions.get(f.rule_id, 0.0))
                for f in scan.findings if f.rule_id in RULES]
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    problems = sorted([f for f in findings if f["status"] == "fail"],
                      key=lambda f: (order[f["severity"]], -f["points_lost"]))
    passed = [f for f in findings if f["status"] == "pass"]
    unknown = [f for f in findings if f["status"] == "unknown"]
    summary = executive_summary(scan.hostname, findings, lang)
    if explainer:
        summary = explainer.rewrite_summary(summary, problems, lang)
    cats = (scan.summary or {}).get("categories", {})
    return {
        "lang": lang,
        "problems": problems,
        "passed": passed,
        "unknown": unknown,
        "summary": summary,
        "categories": [{"id": c, "label": CATEGORIES[c][lang], **v} for c, v in cats.items()],
        "score": scan.summary or {},
    }
