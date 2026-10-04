"""Public pages: landing, free lead-gen check, demo report, legal pages."""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select

from ..config import settings
from ..db import utcnow
from ..demo import build_demo_scan
from ..models import Lead, Scan
from ..plans import PLANS, SERVICES
from ..reports import build_report
from ..scanner.netguard import InvalidDomain, UnsafeTarget, normalize_domain
from ..security import EMAIL_RE, ip_hash, limiter
from ..services import audit, create_scan, submit
from .deps import client_ip, csrf_protect, current_user, get_db, render

router = APIRouter(dependencies=[Depends(csrf_protect)])
PUBLIC_TEASER_FINDINGS = 3
PUBLIC_CACHE = dt.timedelta(hours=24)


@router.get("/")
def landing(request: Request, user=Depends(current_user)):
    demo = build_report(build_demo_scan(), "es")
    return render(request, "landing.html", {"user": user, "plans": PLANS, "services": SERVICES,
                                            "demo": demo, "demo_score": demo["score"]})


@router.post("/check")
def public_check(request: Request, domain: str = Form(...), authorized: str = Form(""), email: str = Form(""),
                 marketing: str = Form(""), db=Depends(get_db)):
    ip = client_ip(request)
    ctx = {"domain": domain[:253], "email": email[:254]}
    if authorized != "yes":
        return render(request, "check_form.html", {**ctx, "error": "Debe confirmar que es propietario del dominio o está autorizado a evaluarlo."}, 400)
    try:
        host = normalize_domain(domain)
    except (InvalidDomain, UnsafeTarget) as exc:
        return render(request, "check_form.html", {**ctx, "error": f"Dominio no válido: {exc}"}, 400)
    email = email.strip().lower()
    if email and not EMAIL_RE.match(email):
        return render(request, "check_form.html", {**ctx, "error": "Email no válido."}, 400)
    # Re-use a recent public result for the same domain: cheaper, and stops the free
    # check from being used to hammer a third party.
    recent = db.scalar(select(Scan).where(Scan.hostname == host, Scan.trigger == "public",
                                          Scan.status.in_(("queued", "running", "completed")),
                                          Scan.created_at > utcnow() - PUBLIC_CACHE).order_by(Scan.id.desc()))
    if not recent and not limiter.hit(f"public-check:{ip}", settings.public_check_per_ip_hour, 3600):
        return render(request, "check_form.html", {**ctx, "error": "Ha alcanzado el límite de análisis gratuitos por hora. Cree una cuenta gratuita para continuar."}, 429)
    scan = recent or create_scan(db, host, trigger="public")
    db.add(Lead(hostname=host, email=email or None, marketing_consent=(marketing == "yes" and bool(email)),
                scan_id=scan.id, ip_hash=ip_hash(ip)))
    audit(db, "public_check", target=host, ip_hash=ip_hash(ip), detail={"cached": bool(recent)})
    db.commit()
    if not recent:
        submit(scan.id)
    return RedirectResponse(f"/check/{scan.public_id}", 303)


@router.get("/check")
def check_form(request: Request):
    return render(request, "check_form.html")


@router.get("/check/{public_id}")
def public_result(request: Request, public_id: str, db=Depends(get_db)):
    scan = db.scalar(select(Scan).where(Scan.public_id == public_id, Scan.trigger == "public"))
    if not scan:
        raise HTTPException(404)
    if scan.status in ("queued", "running"):
        return render(request, "scan_pending.html", {"scan": scan})
    report = build_report(scan, "es") if scan.status == "completed" else None
    teaser = report["problems"][:PUBLIC_TEASER_FINDINGS] if report else []
    hidden = len(report["problems"]) - len(teaser) if report else 0
    return render(request, "check_result.html", {"scan": scan, "report": report, "teaser": teaser, "hidden": hidden})


@router.get("/demo")
def demo_report(request: Request, lang: str = "es", level: str = "basic"):
    scan = build_demo_scan()
    prev = build_demo_scan(variant=1)
    from ..services import compute_changes
    scan.changes = compute_changes(prev, scan)
    return render(request, "report.html", {"scan": scan, "report": build_report(scan, lang), "level": level,
                                           "brand": None, "demo": True, "can_export": False})


@router.get("/privacy")
def privacy(request: Request):
    return render(request, "privacy.html", {"retention": settings.lead_retention_days})


@router.get("/terms")
def terms(request: Request):
    return render(request, "terms.html")
