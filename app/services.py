"""Application services: run + persist scans, compute changes, monitoring, alerts.

Scans run in a small thread pool so HTTP requests return immediately; the scan
page polls the status. A sweeper marks scans stuck in queued/running as failed,
so the user never stares at a spinner forever.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import select

from . import notify
from .config import settings
from .db import session_scope, utcnow
from .models import AuditLog, Domain, Finding, Notification, NotificationChannel, Organization, Scan, ScoreHistory
from .plans import plan as plan_of
from .rules.engine import ANALYSIS_VERSION, evaluate
from .scanner.engine import SCANNER_VERSION, ScanError, run_scan
from .scanner.netguard import InvalidDomain, UnsafeTarget
from .scoring import compute_score

log = logging.getLogger("app.scan")
_pool = ThreadPoolExecutor(max_workers=settings.scan_workers, thread_name_prefix="scan")
STUCK_AFTER = dt.timedelta(minutes=5)
ALERT_SCORE_DROP = 5
ALERT_CERT_DAYS = 14

ERROR_MESSAGES = {
    "nxdomain": "El dominio no existe (NXDOMAIN).",
    "dns_timeout": "Los servidores DNS no respondieron a tiempo. Inténtelo más tarde.",
    "unsafe_target": "El dominio apunta a una dirección no pública; por seguridad no se analiza.",
    "invalid_domain": "El dominio no es válido.",
    "timeout": "El análisis tardó demasiado y se canceló.",
    "internal": "Error interno durante el análisis.",
    "stuck": "El análisis no terminó a tiempo.",
}


def audit(session, action: str, *, org_id=None, user_id=None, target=None, ip_hash=None, detail=None) -> None:
    session.add(AuditLog(org_id=org_id, user_id=user_id, action=action, target=target, ip_hash=ip_hash, detail=detail))
    log.info(json.dumps({"event": action, "org_id": org_id, "user_id": user_id, "target": target}))


def new_public_id() -> str:
    return secrets.token_urlsafe(16)


def create_scan(session, hostname: str, *, org_id=None, domain_id=None, trigger="manual") -> Scan:
    scan = Scan(public_id=new_public_id(), hostname=hostname, org_id=org_id, domain_id=domain_id,
                trigger=trigger, status="queued")
    session.add(scan)
    session.flush()
    return scan


def persist_results(session, scan: Scan, facts: dict) -> None:
    results = evaluate(facts)
    score = compute_score(results)
    lost = {d["rule_id"]: d["points"] for d in score["deductions"]}
    scan.findings = [Finding(rule_id=r.rule_id, category=r.category, kind=r.kind, status=r.status,
                             severity=r.severity, evidence=r.evidence, points_lost=lost.get(r.rule_id, 0.0))
                     for r in results]
    scan.raw_facts = facts
    scan.summary = score
    scan.score, scan.grade = score["score"], score["grade"]
    scan.analysis_version, scan.scanner_version = ANALYSIS_VERSION, facts["meta"]["scanner_version"]
    scan.status = "completed"


def execute_scan(scan_id: int, scanner=run_scan) -> None:
    """Run a queued scan to completion (or failure). Safe to call in a worker thread."""
    with session_scope() as s:
        scan = s.get(Scan, scan_id)
        if not scan or scan.status not in ("queued",):
            return
        scan.status, scan.started_at = "running", utcnow()
        hostname = scan.hostname
        audit(s, "scan_started", org_id=scan.org_id, target=hostname, detail={"scan": scan.public_id})
    t0 = time.monotonic()
    facts, err = None, None
    try:
        facts = scanner(hostname)
    except ScanError as exc:
        err = (exc.code, ERROR_MESSAGES.get(exc.code, str(exc)))
    except (InvalidDomain,) as exc:
        err = ("invalid_domain", ERROR_MESSAGES["invalid_domain"])
    except UnsafeTarget:
        err = ("unsafe_target", ERROR_MESSAGES["unsafe_target"])
    except TimeoutError:
        err = ("timeout", ERROR_MESSAGES["timeout"])
    except Exception:  # noqa: BLE001
        log.exception("scan crashed")
        err = ("internal", ERROR_MESSAGES["internal"])
    with session_scope() as s:
        scan = s.get(Scan, scan_id)
        if scan is None:
            return
        scan.finished_at = utcnow()
        scan.duration_ms = int((time.monotonic() - t0) * 1000)
        if err:
            scan.status, scan.error_code, scan.error_message = "failed", err[0], err[1]
            audit(s, "scan_failed", org_id=scan.org_id, target=hostname, detail={"code": err[0]})
            return
        persist_results(s, scan, facts)
        audit(s, "scan_completed", org_id=scan.org_id, target=hostname,
              detail={"score": scan.score, "ms": scan.duration_ms})
        if scan.domain_id:
            after_domain_scan(s, scan)


def submit(scan_id: int) -> None:
    _pool.submit(execute_scan, scan_id)


def sweep_stuck() -> int:
    cutoff = utcnow() - STUCK_AFTER
    with session_scope() as s:
        stuck = s.scalars(select(Scan).where(Scan.status.in_(("queued", "running")), Scan.created_at < cutoff)).all()
        for sc in stuck:
            sc.status, sc.error_code, sc.error_message, sc.finished_at = "failed", "stuck", ERROR_MESSAGES["stuck"], utcnow()
        return len(stuck)


# ------------------------------------------------------------------ changes
WATCHED_FACTS = {
    "dns_a": lambda f: sorted(f["dns"]["A"]["records"]),
    "dns_mx": lambda f: sorted(m["exchange"] for m in f["dns"]["MX"]["records"]),
    "dns_ns": lambda f: sorted(f["dns"]["NS"]["records"]),
    "spf": lambda f: f["email"]["spf"].get("records"),
    "dmarc": lambda f: f["email"]["dmarc"].get("records"),
    "cert_issuer": lambda f: (f["tls"].get("certificate") or {}).get("issuer_org"),
    "headers": lambda f: sorted(((f["web"].get("final") or {}).get("headers") or {}).keys()),
    "technologies": lambda f: sorted(t["name"] for t in f["web"].get("technologies", [])),
}


def _safe(fn, facts):
    try:
        return fn(facts)
    except (KeyError, TypeError, AttributeError):
        return None


def compute_changes(prev: Scan | None, cur: Scan) -> dict:
    if prev is None:
        return {"first_scan": True}
    prev_fail = {f.rule_id: f.severity for f in prev.findings if f.status == "fail"}
    cur_fail = {f.rule_id: f.severity for f in cur.findings if f.status == "fail"}
    changed_facts = {}
    for key, fn in WATCHED_FACTS.items():
        a, b = _safe(fn, prev.raw_facts or {}), _safe(fn, cur.raw_facts or {})
        if a != b:
            changed_facts[key] = {"before": a, "after": b}
    return {
        "first_scan": False,
        "previous_scan": prev.public_id,
        "score_before": prev.score, "score_after": cur.score,
        "score_delta": (cur.score or 0) - (prev.score or 0),
        "fixed": sorted(set(prev_fail) - set(cur_fail)),
        "new": sorted(set(cur_fail) - set(prev_fail)),
        "facts": changed_facts,
    }


def alert_reasons(changes: dict, cur: Scan) -> list[str]:
    reasons = []
    if changes.get("first_scan"):
        return reasons
    if changes["score_delta"] <= -ALERT_SCORE_DROP:
        reasons.append(f"Score dropped {changes['score_before']} -> {changes['score_after']}")
    if changes["new"]:
        reasons.append("New findings: " + ", ".join(changes["new"]))
    for k in ("dns_ns", "dns_mx", "spf", "dmarc", "cert_issuer"):
        if k in changes["facts"]:
            reasons.append(f"Changed: {k}")
    days = ((cur.raw_facts or {}).get("tls", {}).get("certificate") or {}).get("days_remaining")
    if days is not None and days <= ALERT_CERT_DAYS:
        reasons.append(f"Certificate expires in {days} days")
    return reasons


def after_domain_scan(s, scan: Scan) -> None:
    prev = s.scalars(select(Scan).where(Scan.domain_id == scan.domain_id, Scan.status == "completed",
                                        Scan.id != scan.id).order_by(Scan.id.desc()).limit(1)).first()
    scan.changes = compute_changes(prev, scan)
    s.add(ScoreHistory(domain_id=scan.domain_id, scan_id=scan.id, score=scan.score, grade=scan.grade))
    reasons = alert_reasons(scan.changes, scan)
    if reasons:
        notify_org(s, scan, "posture_changed", reasons)


def notify_org(s, scan: Scan, event: str, reasons: list[str]) -> None:
    org = s.get(Organization, scan.org_id)
    allowed = plan_of(org.plan)["channels"] if org else ()
    channels = s.scalars(select(NotificationChannel).where(NotificationChannel.org_id == scan.org_id,
                                                           NotificationChannel.enabled.is_(True))).all()
    subject = f"[{settings.app_name}] Security posture changed: {scan.hostname}"
    text = "\n".join(f"- {r}" for r in reasons) + f"\n\nScore: {scan.score}/100\n{settings.base_url}/scans/{scan.public_id}"
    payload = {"event": event, "domain": scan.hostname, "score": scan.score, "reasons": reasons, "scan": scan.public_id}
    for ch in channels:
        if ch.kind not in allowed:
            continue
        ok, err = notify.dispatch(ch.kind, ch.target, subject, text, payload)
        s.add(Notification(org_id=scan.org_id, channel_id=ch.id, scan_id=scan.id, event=event,
                           status="sent" if ok else "failed", detail=err))


# --------------------------------------------------------------- monitoring
def due_domains(s, now: dt.datetime | None = None) -> list[Domain]:
    now = now or utcnow()
    rows = s.scalars(select(Domain).join(Organization).where(
        Domain.monitoring_enabled.is_(True), Domain.authorized_at.is_not(None),
        Organization.is_demo.is_(False))).all()
    return [d for d in rows if plan_of(d.org.plan)["monitoring"] and (d.next_scan_at is None or d.next_scan_at <= now)]


def run_monitoring(scanner=run_scan, now: dt.datetime | None = None) -> int:
    """Scan every due domain sequentially (gentle on targets and on our budget)."""
    sweep_stuck()
    with session_scope() as s:
        ids = []
        for d in due_domains(s, now):
            scan = create_scan(s, d.hostname, org_id=d.org_id, domain_id=d.id, trigger="monitor")
            d.next_scan_at = (now or utcnow()) + dt.timedelta(hours=max(d.monitor_interval_hours,
                                                                        plan_of(d.org.plan)["min_interval_h"] or 24))
            ids.append(scan.id)
    for sid in ids:
        execute_scan(sid, scanner)
    return len(ids)


def start_monitor_thread() -> None:
    def loop():
        while True:
            try:
                run_monitoring()
            except Exception:  # noqa: BLE001
                log.exception("monitor loop error")
            time.sleep(settings.monitor_interval_s)
    threading.Thread(target=loop, daemon=True, name="monitor").start()


def purge_expired(now: dt.datetime | None = None) -> dict:
    """Data retention: public lead scans and leads older than LEAD_RETENTION_DAYS;
    domain scans older than the org plan's history window."""
    from .models import Lead
    now = now or utcnow()
    out = {"leads": 0, "public_scans": 0, "history_scans": 0}
    with session_scope() as s:
        cutoff = now - dt.timedelta(days=settings.lead_retention_days)
        for lead in s.scalars(select(Lead).where(Lead.created_at < cutoff)).all():
            s.delete(lead)
            out["leads"] += 1
        for sc in s.scalars(select(Scan).where(Scan.trigger == "public", Scan.created_at < cutoff)).all():
            s.delete(sc)
            out["public_scans"] += 1
        for org in s.scalars(select(Organization).where(Organization.is_demo.is_(False))).all():
            keep = now - dt.timedelta(days=plan_of(org.plan)["history_days"])
            for sc in s.scalars(select(Scan).where(Scan.org_id == org.id, Scan.created_at < keep)).all():
                s.delete(sc)
                out["history_scans"] += 1
    return out
