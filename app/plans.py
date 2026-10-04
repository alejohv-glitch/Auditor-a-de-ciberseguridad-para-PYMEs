"""Plan catalogue and limits. Prices in EUR cents, VAT excluded.
Rationale in docs/BUSINESS_PLAN.md (pricing section)."""
from __future__ import annotations

PLANS: dict[str, dict] = {
    "free": {
        "name": "Free", "price_cents": 0,
        "domains": 1, "manual_scans_per_day": 2, "monitoring": False, "min_interval_h": None,
        "history_days": 30, "channels": ("email",), "export": False, "technical_report": False,
        "white_label": False, "seats": 1, "support": "docs",
    },
    "pro": {
        "name": "Pro", "price_cents": 1900,
        "domains": 3, "manual_scans_per_day": 10, "monitoring": True, "min_interval_h": 24,
        "history_days": 365, "channels": ("email", "webhook"), "export": True, "technical_report": True,
        "white_label": False, "seats": 1, "support": "email 2 business days",
    },
    "business": {
        "name": "Business", "price_cents": 4900,
        "domains": 10, "manual_scans_per_day": 30, "monitoring": True, "min_interval_h": 24,
        "history_days": 730, "channels": ("email", "webhook", "discord", "telegram"), "export": True,
        "technical_report": True, "white_label": False, "seats": 3, "support": "email next business day",
    },
    "agency": {
        "name": "Agency", "price_cents": 9900,
        "domains": 30, "manual_scans_per_day": 100, "monitoring": True, "min_interval_h": 24,
        "history_days": 730, "channels": ("email", "webhook", "discord", "telegram"), "export": True,
        "technical_report": True, "white_label": True, "seats": 5, "support": "priority email",
    },
}

# One-off services (Phase A revenue). Delivered with the same engine + human review.
SERVICES = [
    {"id": "review", "name": "Informe revisado", "price_cents": 9900,
     "includes": "Análisis + revisión manual del consultor + informe PDF + 30 min de llamada"},
    {"id": "fix", "name": "Informe + corrección guiada", "price_cents": 24900,
     "includes": "Lo anterior + acompañamiento para corregir SPF/DKIM/DMARC y cabeceras + re-análisis de verificación"},
]


def plan(name: str | None) -> dict:
    return PLANS.get(name or "free", PLANS["free"])


def can(org_plan: str, feature: str) -> bool:
    return bool(plan(org_plan).get(feature))
