"""Internal business + technical metrics. Visible only to users with is_admin."""
from __future__ import annotations

import datetime as dt
from collections import Counter

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select

from ..db import utcnow
from ..models import Domain, Lead, Organization, Scan, Subscription, User
from ..plans import PLANS
from .deps import get_db, render, require_admin

router = APIRouter()


def compute_metrics(db, days: int = 30) -> dict:
    since = utcnow() - dt.timedelta(days=days)
    orgs = db.scalars(select(Organization).where(Organization.is_demo.is_(False))).all()
    paid = [o for o in orgs if o.plan != "free"]
    active_subs = db.scalars(select(Subscription).where(Subscription.status == "active")).all()
    canceled = db.scalar(select(func.count(Subscription.id)).where(Subscription.canceled_at >= since)) or 0
    mrr = sum(s.amount_cents if s.interval == "month" else s.amount_cents // 12 for s in active_subs) / 100
    scans = db.scalars(select(Scan).where(Scan.created_at >= since, Scan.is_demo.is_(False))).all()
    done = [s for s in scans if s.status == "completed"]
    failed = [s for s in scans if s.status == "failed"]
    durations = sorted(s.duration_ms for s in done if s.duration_ms)
    users = db.scalar(select(func.count(User.id))) or 0
    leads = db.scalar(select(func.count(Lead.id)).where(Lead.created_at >= since)) or 0
    leads_with_email = db.scalar(select(func.count(Lead.id)).where(Lead.created_at >= since, Lead.email.is_not(None))) or 0
    finished = len(done) + len(failed)
    return {
        "days": days,
        "users": users, "orgs": len(orgs), "free_orgs": len(orgs) - len(paid), "paid_orgs": len(paid),
        "conversion": round(100 * len(paid) / len(orgs), 1) if orgs else 0.0,
        "mrr_eur": mrr, "churned_subs": canceled,
        "churn_rate": round(100 * canceled / (len(active_subs) + canceled), 1) if (active_subs or canceled) else 0.0,
        "domains": db.scalar(select(func.count(Domain.id))) or 0,
        "monitored": db.scalar(select(func.count(Domain.id)).where(Domain.monitoring_enabled.is_(True))) or 0,
        "scans": len(scans), "scans_by_trigger": dict(Counter(s.trigger for s in scans)),
        "scans_per_user": round(len(scans) / users, 1) if users else 0,
        "leads": leads, "leads_with_email": leads_with_email,
        "success_rate": round(100 * len(done) / finished, 1) if finished else None,
        "failure_rate": round(100 * len(failed) / finished, 1) if finished else None,
        "failures_by_code": dict(Counter(s.error_code for s in failed)),
        "p50_ms": durations[len(durations) // 2] if durations else None,
        "p95_ms": durations[int(len(durations) * 0.95)] if durations else None,
        "by_plan": dict(Counter(o.plan for o in orgs)),
        "price_list": {k: v["price_cents"] / 100 for k, v in PLANS.items()},
    }


@router.get("/admin")
def admin_dashboard(request: Request, user=Depends(require_admin), db=Depends(get_db)):
    return render(request, "admin.html", {"user": user, "m": compute_metrics(db)})
