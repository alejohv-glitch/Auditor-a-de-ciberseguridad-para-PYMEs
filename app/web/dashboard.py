"""Authenticated app: domains, scans, reports, monitoring, settings, billing."""
from __future__ import annotations

import datetime as dt
import re
import secrets

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import func, select

from ..billing import get_billing
from ..db import utcnow
from ..models import Domain, NotificationChannel, Scan, ScoreHistory
from ..notify import NotifyError, validate_webhook_url
from ..plans import PLANS, SERVICES
from ..plans import plan as plan_of
from ..reports import build_report
from ..scanner import netguard
from ..security import EMAIL_RE, limiter
from ..services import audit, create_scan, submit
from .deps import csrf_protect, get_db, owned_domain, owned_scan, render, require_org, require_user

router = APIRouter(dependencies=[Depends(csrf_protect)])
AUTH_STATEMENT = "I confirm that I own or am authorized to assess this domain. / Confirmo que soy propietario del dominio o estoy autorizado para evaluarlo."
HEX_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")
VERIFY_PREFIX = "_seclara-verify"


def _latest(db, domain_id: int, n: int = 2) -> list[Scan]:
    return db.scalars(select(Scan).where(Scan.domain_id == domain_id, Scan.status == "completed")
                      .order_by(Scan.id.desc()).limit(n)).all()


@router.get("/app")
def dashboard(request: Request, user=Depends(require_user), org=Depends(require_org), db=Depends(get_db)):
    rows = []
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "passed": 0}
    for d in db.scalars(select(Domain).where(Domain.org_id == org.id).order_by(Domain.hostname)).all():
        latest = _latest(db, d.id)
        cur = latest[0] if latest else None
        prev = latest[1] if len(latest) > 1 else None
        running = db.scalar(select(Scan).where(Scan.domain_id == d.id, Scan.status.in_(("queued", "running"))))
        if cur:
            for k in ("critical", "high", "medium", "low"):
                totals[k] += cur.summary["counts"][k]
            totals["passed"] += cur.summary["passed"]
        rows.append({"domain": d, "scan": cur, "prev": prev, "running": running,
                     "changes": (cur.changes or {}) if cur else {}})
    p = plan_of(org.plan)
    return render(request, "dashboard.html", {"user": user, "org": org, "rows": rows, "totals": totals,
                                              "plan": p, "auth_statement": AUTH_STATEMENT,
                                              "can_add": len(rows) < p["domains"]})


@router.post("/app/domains")
def add_domain(request: Request, hostname: str = Form(...), authorized: str = Form(""), client_name: str = Form(""),
               user=Depends(require_user), org=Depends(require_org), db=Depends(get_db)):
    p = plan_of(org.plan)
    count = db.scalar(select(func.count(Domain.id)).where(Domain.org_id == org.id))
    err = None
    try:
        host = netguard.normalize_domain(hostname)
    except (netguard.InvalidDomain, netguard.UnsafeTarget) as exc:
        err, host = f"Dominio no válido: {exc}", None
    if not err and authorized != "yes":
        err = "Debe confirmar que está autorizado a evaluar el dominio."
    if not err and count >= p["domains"]:
        err = f"Su plan {p['name']} permite {p['domains']} dominio(s). Mejore su plan para añadir más."
    if not err and db.scalar(select(Domain).where(Domain.org_id == org.id, Domain.hostname == host)):
        err = "Ese dominio ya está en su cuenta."
    if err:
        return RedirectResponse(f"/app?err={err}", 303)
    d = Domain(org_id=org.id, hostname=host, client_name=client_name.strip()[:120] or None,
               authorized_by_user_id=user.id, authorized_at=utcnow(), authorization_statement=AUTH_STATEMENT,
               verification_token=secrets.token_hex(16))
    db.add(d)
    db.flush()
    audit(db, "domain_added", org_id=org.id, user_id=user.id, target=host, detail={"authorized": True})
    scan = create_scan(db, host, org_id=org.id, domain_id=d.id)
    db.commit()
    submit(scan.id)
    return RedirectResponse(f"/scans/{scan.public_id}", 303)


@router.get("/app/domains/{domain_id}")
def domain_detail(request: Request, domain_id: int, user=Depends(require_user), org=Depends(require_org),
                  db=Depends(get_db)):
    d = owned_domain(db, org, domain_id)
    p = plan_of(org.plan)
    since = utcnow() - dt.timedelta(days=min(p["history_days"], 90))
    history = db.scalars(select(ScoreHistory).where(ScoreHistory.domain_id == d.id, ScoreHistory.recorded_at >= since)
                         .order_by(ScoreHistory.recorded_at)).all()
    scans = db.scalars(select(Scan).where(Scan.domain_id == d.id).order_by(Scan.id.desc()).limit(20)).all()
    latest = _latest(db, d.id, 1)
    return render(request, "domain.html", {"user": user, "org": org, "d": d, "plan": p, "history": history,
                                           "scans": scans, "latest": latest[0] if latest else None,
                                           "verify_name": f"{VERIFY_PREFIX}.{netguard.base_domain(d.hostname)}"})


@router.post("/app/domains/{domain_id}/scan")
def rescan(request: Request, domain_id: int, user=Depends(require_user), org=Depends(require_org), db=Depends(get_db)):
    d = owned_domain(db, org, domain_id)
    if org.is_demo:
        return RedirectResponse(f"/app/domains/{d.id}?err=Los datos DEMO no se re-analizan.", 303)
    p = plan_of(org.plan)
    day_ago = utcnow() - dt.timedelta(days=1)
    used = db.scalar(select(func.count(Scan.id)).where(Scan.org_id == org.id, Scan.trigger == "manual",
                                                       Scan.created_at > day_ago))
    if used >= p["manual_scans_per_day"]:
        return RedirectResponse(f"/app/domains/{d.id}?err=Límite diario de análisis del plan alcanzado.", 303)
    if not limiter.hit(f"rescan:{d.id}", 1, 120):
        return RedirectResponse(f"/app/domains/{d.id}?err=Espere 2 minutos entre análisis del mismo dominio.", 303)
    scan = create_scan(db, d.hostname, org_id=org.id, domain_id=d.id)
    audit(db, "scan_requested", org_id=org.id, user_id=user.id, target=d.hostname)
    db.commit()
    submit(scan.id)
    return RedirectResponse(f"/scans/{scan.public_id}", 303)


@router.post("/app/domains/{domain_id}/monitoring")
def set_monitoring(domain_id: int, enabled: str = Form(""), interval: int = Form(24),
                   user=Depends(require_user), org=Depends(require_org), db=Depends(get_db)):
    d = owned_domain(db, org, domain_id)
    p = plan_of(org.plan)
    if enabled == "yes" and not p["monitoring"]:
        return RedirectResponse(f"/app/domains/{d.id}?err=La monitorización requiere el plan Pro o superior.", 303)
    d.monitoring_enabled = enabled == "yes"
    d.monitor_interval_hours = max(p["min_interval_h"] or 24, min(int(interval), 168))
    d.next_scan_at = utcnow() + dt.timedelta(hours=d.monitor_interval_hours) if d.monitoring_enabled else None
    audit(db, "monitoring_changed", org_id=org.id, user_id=user.id, target=d.hostname,
          detail={"enabled": d.monitoring_enabled, "interval": d.monitor_interval_hours})
    return RedirectResponse(f"/app/domains/{d.id}?ok=1", 303)


@router.post("/app/domains/{domain_id}/verify")
def verify_domain(domain_id: int, user=Depends(require_user), org=Depends(require_org), db=Depends(get_db)):
    """Optional ownership proof: TXT record <prefix>.<domain> containing the token."""
    d = owned_domain(db, org, domain_id)
    from ..scanner.dns_checks import query
    res = query(netguard.make_resolver(), f"{VERIFY_PREFIX}.{netguard.base_domain(d.hostname)}", "TXT")
    if d.verification_token and d.verification_token in res["records"]:
        d.verified_at = utcnow()
        audit(db, "domain_verified", org_id=org.id, user_id=user.id, target=d.hostname)
        return RedirectResponse(f"/app/domains/{d.id}?ok=verified", 303)
    return RedirectResponse(f"/app/domains/{d.id}?err=No se encontró el registro TXT de verificación (puede tardar en propagarse).", 303)


@router.post("/app/domains/{domain_id}/delete")
def delete_domain(domain_id: int, user=Depends(require_user), org=Depends(require_org), db=Depends(get_db)):
    d = owned_domain(db, org, domain_id)
    audit(db, "domain_deleted", org_id=org.id, user_id=user.id, target=d.hostname)
    db.delete(d)  # cascades to scans, findings, score history
    return RedirectResponse("/app?ok=deleted", 303)


# ------------------------------------------------------------------- scans
@router.get("/scans/{public_id}")
def scan_view(request: Request, public_id: str, user=Depends(require_user), org=Depends(require_org),
              db=Depends(get_db)):
    scan = owned_scan(db, org, public_id)
    if scan.status in ("queued", "running"):
        return render(request, "scan_pending.html", {"scan": scan, "user": user})
    if scan.status == "failed":
        return render(request, "scan_failed.html", {"scan": scan, "user": user})
    return RedirectResponse(f"/scans/{public_id}/report", 303)


@router.get("/scans/{public_id}/status")
def scan_status(public_id: str, org=Depends(require_org), db=Depends(get_db)):
    scan = owned_scan(db, org, public_id)
    return JSONResponse({"status": scan.status, "score": scan.score, "error": scan.error_message})


@router.get("/scans/{public_id}/report")
def report(request: Request, public_id: str, lang: str | None = None, level: str = "basic",
           user=Depends(require_user), org=Depends(require_org), db=Depends(get_db)):
    scan = owned_scan(db, org, public_id)
    if scan.status != "completed":
        return RedirectResponse(f"/scans/{public_id}", 303)
    p = plan_of(org.plan)
    if level == "technical" and not p["technical_report"]:
        level = "basic"
    brand = None
    if p["white_label"] and org.brand_name:
        brand = {"name": org.brand_name, "color": org.brand_color if org.brand_color and HEX_COLOR.match(org.brand_color) else None}
    return render(request, "report.html", {"scan": scan, "report": build_report(scan, lang or org.report_lang),
                                           "level": level, "brand": brand, "demo": scan.is_demo, "user": user,
                                           "can_export": p["export"], "technical_allowed": p["technical_report"]})


@router.get("/scans/{public_id}/export.json")
def export_json(public_id: str, org=Depends(require_org), db=Depends(get_db)):
    scan = owned_scan(db, org, public_id)
    if not plan_of(org.plan)["export"]:
        raise HTTPException(402, "Export requires a paid plan")
    rep = build_report(scan, org.report_lang)
    return JSONResponse({
        "domain": scan.hostname, "scan_id": scan.public_id, "created_at": scan.created_at.isoformat() + "Z",
        "score": scan.score, "grade": scan.grade, "analysis_version": scan.analysis_version, "demo": scan.is_demo,
        "summary": rep["summary"], "problems": rep["problems"], "passed": [f["title"] for f in rep["passed"]],
        "changes": scan.changes, "raw_facts": scan.raw_facts,
        "disclaimer": "Automated assessment of publicly observable controls. Not a penetration test.",
    }, headers={"Content-Disposition": f'attachment; filename="{scan.hostname}-{scan.public_id[:8]}.json"'})


@router.post("/scans/{public_id}/notes")
def save_notes(public_id: str, notes: str = Form(""), user=Depends(require_user), org=Depends(require_org),
               db=Depends(get_db)):
    scan = owned_scan(db, org, public_id)
    scan.reviewer_notes = notes.strip()[:5000] or None
    audit(db, "reviewer_notes_saved", org_id=org.id, user_id=user.id, target=scan.hostname)
    return RedirectResponse(f"/scans/{public_id}/report?level=technical", 303)


@router.post("/scans/{public_id}/delete")
def delete_scan(public_id: str, user=Depends(require_user), org=Depends(require_org), db=Depends(get_db)):
    scan = owned_scan(db, org, public_id)
    dom = scan.domain_id
    audit(db, "scan_deleted", org_id=org.id, user_id=user.id, target=scan.hostname)
    db.delete(scan)
    return RedirectResponse(f"/app/domains/{dom}" if dom else "/app", 303)


# ---------------------------------------------------------------- settings
@router.get("/app/settings")
def settings_page(request: Request, user=Depends(require_user), org=Depends(require_org), db=Depends(get_db)):
    channels = db.scalars(select(NotificationChannel).where(NotificationChannel.org_id == org.id)).all()
    return render(request, "settings.html", {"user": user, "org": org, "plan": plan_of(org.plan),
                                             "channels": channels})


@router.post("/app/channels")
def add_channel(kind: str = Form(...), target: str = Form(...), user=Depends(require_user),
                org=Depends(require_org), db=Depends(get_db)):
    p = plan_of(org.plan)
    if kind not in p["channels"]:
        return RedirectResponse("/app/settings?err=Canal no incluido en su plan.", 303)
    target = target.strip()
    if kind == "email":
        if not EMAIL_RE.match(target):
            return RedirectResponse("/app/settings?err=Email no válido.", 303)
    else:
        try:
            validate_webhook_url(target)
        except (NotifyError, netguard.InvalidDomain, netguard.UnsafeTarget) as exc:
            return RedirectResponse(f"/app/settings?err=URL no válida: {exc}", 303)
    if db.scalar(select(func.count(NotificationChannel.id)).where(NotificationChannel.org_id == org.id)) >= 10:
        return RedirectResponse("/app/settings?err=Máximo 10 canales.", 303)
    db.add(NotificationChannel(org_id=org.id, kind=kind, target=target[:500]))
    audit(db, "channel_added", org_id=org.id, user_id=user.id, detail={"kind": kind})
    return RedirectResponse("/app/settings?ok=1", 303)


@router.post("/app/channels/{channel_id}/delete")
def delete_channel(channel_id: int, user=Depends(require_user), org=Depends(require_org), db=Depends(get_db)):
    ch = db.scalar(select(NotificationChannel).where(NotificationChannel.id == channel_id,
                                                     NotificationChannel.org_id == org.id))
    if not ch:
        raise HTTPException(404)
    db.delete(ch)
    return RedirectResponse("/app/settings?ok=1", 303)


@router.post("/app/branding")
def branding(brand_name: str = Form(""), brand_color: str = Form(""), report_lang: str = Form("es"),
             user=Depends(require_user), org=Depends(require_org), db=Depends(get_db)):
    org.report_lang = report_lang if report_lang in ("es", "en") else "es"
    if plan_of(org.plan)["white_label"]:
        org.brand_name = brand_name.strip()[:120] or None
        org.brand_color = brand_color if HEX_COLOR.match(brand_color or "") else None
    audit(db, "settings_changed", org_id=org.id, user_id=user.id)
    return RedirectResponse("/app/settings?ok=1", 303)


@router.get("/app/billing")
def billing_page(request: Request, user=Depends(require_user), org=Depends(require_org)):
    return render(request, "billing.html", {"user": user, "org": org, "plans": PLANS, "services": SERVICES,
                                            "provider": get_billing().name})


@router.post("/app/billing/checkout")
def checkout(plan: str = Form(...), user=Depends(require_user), org=Depends(require_org)):
    if plan not in PLANS or plan == "free":
        raise HTTPException(400)
    url = get_billing().checkout_url(org, plan)
    return RedirectResponse(url, 303)
