"""Operations CLI.

  python -m app.cli init-db
  python -m app.cli monitor              # run due monitoring scans (cron hourly)
  python -m app.cli purge                # apply data-retention rules (cron daily)
  python -m app.cli seed-demo            # create the DEMO organisation
  python -m app.cli make-admin EMAIL
  python -m app.cli set-plan EMAIL PLAN  # manual billing: activate a plan
  python -m app.cli scan DOMAIN [--json] # one-off scan from the terminal (authorized domains only)
  python -m app.cli sample-report OUT.html
"""
from __future__ import annotations

import argparse
import json
import sys

from sqlalchemy import select

from .db import init_db, session_scope


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="app.cli")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-db")
    sub.add_parser("monitor")
    sub.add_parser("purge")
    sub.add_parser("seed-demo")
    a = sub.add_parser("make-admin"); a.add_argument("email")
    sp = sub.add_parser("set-plan"); sp.add_argument("email"); sp.add_argument("plan"); sp.add_argument("--months", type=int, default=1)
    sc = sub.add_parser("scan"); sc.add_argument("domain"); sc.add_argument("--json", action="store_true")
    sr = sub.add_parser("sample-report"); sr.add_argument("out"); sr.add_argument("--lang", default="es")
    args = p.parse_args(argv)
    init_db()

    if args.cmd == "init-db":
        print("ok")
    elif args.cmd == "monitor":
        from .services import run_monitoring
        print(json.dumps({"event": "monitor_run", "scans": run_monitoring()}))
    elif args.cmd == "purge":
        from .services import purge_expired
        print(json.dumps({"event": "purge", **purge_expired()}))
    elif args.cmd == "seed-demo":
        from .demo import seed_demo
        with session_scope() as s:
            seed_demo(s)
        print("DEMO organisation ready")
    elif args.cmd in ("make-admin", "set-plan"):
        from .models import Membership, Organization, User
        with session_scope() as s:
            user = s.scalar(select(User).where(User.email == args.email.lower()))
            if not user:
                print("user not found", file=sys.stderr)
                return 1
            if args.cmd == "make-admin":
                user.is_admin = True
            else:
                from .billing import apply_subscription
                from .plans import PLANS
                if args.plan not in PLANS:
                    print(f"unknown plan; choose {list(PLANS)}", file=sys.stderr)
                    return 1
                m = s.scalar(select(Membership).where(Membership.user_id == user.id))
                apply_subscription(s, s.get(Organization, m.org_id), args.plan, months=args.months)
        print("ok")
    elif args.cmd == "scan":
        from .reports import build_report
        from .rules.engine import evaluate
        from .scanner.engine import run_scan
        from .scoring import compute_score
        facts = run_scan(args.domain)
        res = evaluate(facts)
        score = compute_score(res)
        if args.json:
            print(json.dumps({"facts": facts, "score": score, "results": [r.to_dict() for r in res]}, indent=2, default=str))
        else:
            from .models import Finding, Scan
            scan = Scan(hostname=facts["meta"]["target"], summary=score,
                        findings=[Finding(rule_id=r.rule_id, status=r.status, severity=r.severity, evidence=r.evidence)
                                  for r in res])
            rep = build_report(scan, "es")
            print(f"{scan.hostname}: {score['score']}/100 ({score['grade']})  {score['counts']}")
            for f in rep["problems"]:
                print(f"  [{f['severity'].upper():8}] {f['title']}")
    elif args.cmd == "sample-report":
        write_sample_report(args.out, args.lang)
        print(f"written {args.out}")
    return 0


def write_sample_report(out: str, lang: str = "es") -> None:
    """Render the DEMO report to a standalone HTML file (CSS inlined) for sharing."""
    import os

    from jinja2 import Environment, FileSystemLoader, select_autoescape

    from .config import settings
    from .demo import build_demo_scan
    from .reports import build_report
    from .services import compute_changes

    here = os.path.join(os.path.dirname(__file__), "web")
    env = Environment(loader=FileSystemLoader(os.path.join(here, "templates")), autoescape=select_autoescape())
    scan = build_demo_scan()
    scan.changes = compute_changes(build_demo_scan(1), scan)
    css = open(os.path.join(here, "static", "style.css"), encoding="utf-8").read()

    class _Req:  # minimal stand-in for templates that reference request
        query_params: dict = {}
        url = type("U", (), {"path": "/demo"})()
        state = type("S", (), {"csrf": "", "nonce": ""})()

    html = env.get_template("report.html").render(
        request=_Req(), app_name=settings.app_name, csrf="", nonce="", contact_email=settings.contact_email,
        scan=scan, report=build_report(scan, lang), level="technical", brand=None, demo=True, can_export=False,
        inline_css=css, standalone=True)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(html)


if __name__ == "__main__":
    raise SystemExit(main())
