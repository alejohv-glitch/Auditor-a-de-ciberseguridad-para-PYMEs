from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select

from ..config import settings
from ..db import utcnow
from ..models import AuthSession, Membership, Organization, PasswordResetToken, User
from ..notify import send_email
from ..security import (EMAIL_RE, hash_password, ip_hash, limiter, new_token, password_problem, token_hash,
                        verify_password)
from ..services import audit
from .deps import (SESSION_COOKIE, client_ip, create_session, csrf_protect, current_user, get_db, render,
                   require_user, set_session_cookie)

router = APIRouter(dependencies=[Depends(csrf_protect)])
GENERIC_LOGIN_ERROR = "Email o contraseña incorrectos."


@router.get("/register")
def register_form(request: Request, user=Depends(current_user)):
    if user:
        return RedirectResponse("/app", 303)
    return render(request, "auth/register.html")


@router.post("/register")
def register(request: Request, email: str = Form(...), password: str = Form(...), company: str = Form(""),
             accept_terms: str = Form(""), db=Depends(get_db)):
    ip = client_ip(request)
    if not limiter.hit(f"register:{ip}", 5, 3600):
        return render(request, "auth/register.html", {"error": "Demasiados registros desde esta red. Inténtelo más tarde."}, 429)
    email = email.strip().lower()
    err = None
    if not EMAIL_RE.match(email):
        err = "Introduzca un email válido."
    elif (p := password_problem(password)):
        err = p
    elif accept_terms != "yes":
        err = "Debe aceptar las condiciones y la política de privacidad."
    elif db.scalar(select(User).where(User.email == email)):
        # Do not confirm account existence in a different way than other errors would.
        err = "No se pudo crear la cuenta con ese email. Si ya tiene cuenta, inicie sesión."
    if err:
        return render(request, "auth/register.html", {"error": err, "email": email, "company": company}, 400)
    user = User(email=email, password_hash=hash_password(password))
    org = Organization(name=(company.strip()[:120] or email.split("@")[1]))
    db.add_all([user, org])
    db.flush()
    db.add(Membership(user_id=user.id, org_id=org.id, role="owner"))
    audit(db, "user_registered", org_id=org.id, user_id=user.id, ip_hash=ip_hash(ip))
    token = create_session(db, user)
    resp = RedirectResponse("/app?welcome=1", 303)
    set_session_cookie(resp, token)
    return resp


@router.get("/login")
def login_form(request: Request, user=Depends(current_user)):
    if user:
        return RedirectResponse("/app", 303)
    return render(request, "auth/login.html")


@router.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...), db=Depends(get_db)):
    ip = client_ip(request)
    email = email.strip().lower()
    if not (limiter.hit(f"login-ip:{ip}", 20, 900) and limiter.hit(f"login-email:{email}", 8, 900)):
        return render(request, "auth/login.html", {"error": "Demasiados intentos. Espere 15 minutos."}, 429)
    user = db.scalar(select(User).where(User.email == email))
    if not verify_password(user.password_hash if user else None, password):
        audit(db, "login_failed", ip_hash=ip_hash(ip), detail={"known_user": bool(user)})
        return render(request, "auth/login.html", {"error": GENERIC_LOGIN_ERROR, "email": email}, 400)
    user.last_login_at = utcnow()
    audit(db, "login", user_id=user.id, ip_hash=ip_hash(ip))
    token = create_session(db, user)
    resp = RedirectResponse("/app", 303)
    set_session_cookie(resp, token)
    return resp


@router.post("/logout")
def logout(request: Request, db=Depends(get_db)):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        for s in db.scalars(select(AuthSession).where(AuthSession.token_hash == token_hash(token))):
            db.delete(s)
    resp = RedirectResponse("/", 303)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@router.get("/forgot")
def forgot_form(request: Request):
    return render(request, "auth/forgot.html")


@router.post("/forgot")
def forgot(request: Request, email: str = Form(...), db=Depends(get_db)):
    ip = client_ip(request)
    if not limiter.hit(f"forgot:{ip}", 5, 3600):
        return render(request, "auth/forgot.html", {"error": "Demasiadas solicitudes."}, 429)
    user = db.scalar(select(User).where(User.email == email.strip().lower()))
    if user:
        token = new_token()
        db.add(PasswordResetToken(token_hash=token_hash(token), user_id=user.id,
                                  expires_at=utcnow() + dt.timedelta(hours=1)))
        send_email(user.email, f"{settings.app_name}: restablecer contraseña",
                   f"Para elegir una nueva contraseña abra este enlace (válido 1 hora):\n"
                   f"{settings.base_url}/reset/{token}\n\nSi no lo ha solicitado, ignore este mensaje.")
        audit(db, "password_reset_requested", user_id=user.id, ip_hash=ip_hash(ip))
    # Same answer whether or not the account exists (no user enumeration).
    return render(request, "auth/forgot.html", {"sent": True})


@router.get("/reset/{token}")
def reset_form(request: Request, token: str):
    return render(request, "auth/reset.html", {"token": token})


@router.post("/reset/{token}")
def reset(request: Request, token: str, password: str = Form(...), db=Depends(get_db)):
    rec = db.scalar(select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash(token)))
    if not rec or rec.used_at or rec.expires_at < utcnow():
        return render(request, "auth/reset.html", {"token": token, "error": "Enlace inválido o caducado."}, 400)
    if (p := password_problem(password)):
        return render(request, "auth/reset.html", {"token": token, "error": p}, 400)
    user = db.get(User, rec.user_id)
    user.password_hash = hash_password(password)
    rec.used_at = utcnow()
    for s in db.scalars(select(AuthSession).where(AuthSession.user_id == user.id)):
        db.delete(s)  # log out everywhere after a reset
    audit(db, "password_reset", user_id=user.id)
    return RedirectResponse("/login?reset=1", 303)


@router.post("/app/account/delete")
def delete_account(request: Request, confirm: str = Form(""), user=Depends(require_user), db=Depends(get_db)):
    """GDPR erasure: deletes the user and every org they solely own (domains, scans, findings...)."""
    if confirm != "DELETE":
        return RedirectResponse("/app/settings?err=confirm", 303)
    for m in list(user.memberships):
        org = db.get(Organization, m.org_id)
        if org and len(org.members) == 1:
            db.delete(org)
    audit(db, "account_deleted", detail={"user_id": user.id})
    db.delete(user)
    resp = RedirectResponse("/?deleted=1", 303)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp
