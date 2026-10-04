"""Request helpers: DB session, current user/org, tenant-scoped lookups, CSRF, client IP.

Multi-tenancy rule: tenant data is ONLY fetched through ``owned_domain`` /
``owned_scan`` which filter by the caller's org_id and return 404 (not 403) for
anything else, so object IDs of other tenants are not even confirmed to exist.
"""
from __future__ import annotations

import datetime as dt
import os
import secrets

from fastapi import Depends, HTTPException, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

from ..config import settings
from ..db import SessionLocal, utcnow
from ..models import AuthSession, Domain, Membership, Organization, Scan, User
from ..security import token_hash

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=TEMPLATES_DIR)
SESSION_COOKIE = "sid"
CSRF_COOKIE = "csrftoken"
TRUST_PROXY = os.getenv("TRUST_PROXY", "0") == "1"


class LoginRequired(Exception):
    pass


def get_db():
    s = SessionLocal()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def client_ip(request: Request) -> str:
    if TRUST_PROXY:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def current_user(request: Request, db=Depends(get_db)) -> User | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    sess = db.scalar(select(AuthSession).where(AuthSession.token_hash == token_hash(token)))
    if not sess or sess.expires_at < utcnow():
        return None
    return db.get(User, sess.user_id)


def require_user(user: User | None = Depends(current_user)) -> User:
    if user is None:
        raise LoginRequired()
    return user


def require_org(user: User = Depends(require_user), db=Depends(get_db)) -> Organization:
    m = db.scalar(select(Membership).where(Membership.user_id == user.id).order_by(Membership.id))
    if not m:
        raise HTTPException(403)
    return db.get(Organization, m.org_id)


def require_admin(user: User = Depends(require_user)) -> User:
    if not user.is_admin:
        raise HTTPException(404)
    return user


def owned_domain(db, org: Organization, domain_id: int) -> Domain:
    d = db.scalar(select(Domain).where(Domain.id == domain_id, Domain.org_id == org.id))
    if not d:
        raise HTTPException(404)
    return d


def owned_scan(db, org: Organization, public_id: str) -> Scan:
    s = db.scalar(select(Scan).where(Scan.public_id == public_id, Scan.org_id == org.id))
    if not s:
        raise HTTPException(404)
    return s


def create_session(db, user: User) -> str:
    token = secrets.token_urlsafe(32)
    db.add(AuthSession(token_hash=token_hash(token), user_id=user.id,
                       expires_at=utcnow() + dt.timedelta(days=settings.session_days)))
    return token


def set_session_cookie(response, token: str) -> None:
    response.set_cookie(SESSION_COOKIE, token, httponly=True, secure=settings.cookie_secure, samesite="lax",
                        max_age=settings.session_days * 86400, path="/")


async def csrf_protect(request: Request) -> None:
    """Double-submit token: the form field must equal the csrftoken cookie.
    Combined with SameSite=Lax cookies this blocks cross-site form posts."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    form = await request.form()
    sent = form.get("csrf", "")
    cookie = request.cookies.get(CSRF_COOKIE, "")
    if not cookie or not isinstance(sent, str) or not secrets.compare_digest(sent, cookie):
        raise HTTPException(400, "CSRF token missing or invalid. Reload the page and try again.")


def render(request: Request, name: str, ctx: dict | None = None, status_code: int = 200):
    base = {"request": request, "app_name": settings.app_name, "csrf": getattr(request.state, "csrf", ""),
            "nonce": getattr(request.state, "nonce", ""), "contact_email": settings.contact_email}
    base.update(ctx or {})
    return templates.TemplateResponse(request, name, base, status_code=status_code)
