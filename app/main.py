"""ASGI entry point: `uvicorn app.main:app`."""
from __future__ import annotations

import json
import logging
import os
import secrets
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import db as dbmod
from .config import settings
from .web import admin, auth_routes, dashboard, public
from .web.deps import CSRF_COOKIE, LoginRequired, render


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        msg = record.getMessage()
        base = {"ts": self.formatTime(record), "level": record.levelname, "logger": record.name}
        try:
            base.update(json.loads(msg))
        except (ValueError, TypeError):
            base["msg"] = msg
        if record.exc_info:
            base["exc"] = self.formatException(record.exc_info)[-2000:]
        return json.dumps(base)


def setup_logging() -> None:
    h = logging.StreamHandler()
    h.setFormatter(JsonFormatter())
    root = logging.getLogger("app")
    root.handlers = [h]
    root.setLevel(os.getenv("LOG_LEVEL", "INFO"))
    root.propagate = False


def _redact(path: str) -> str:
    """Password-reset tokens travel in the path: never write them to logs."""
    return "/reset/[redacted]" if path.startswith("/reset/") else path


def create_app() -> FastAPI:
    setup_logging()
    dbmod.init_db()
    app = FastAPI(title=settings.app_name, docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "web", "static")), name="static")
    access = logging.getLogger("app.http")

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        start = time.monotonic()
        request.state.nonce = secrets.token_urlsafe(16)
        csrf = request.cookies.get(CSRF_COOKIE)
        new_csrf = None
        if not csrf:
            csrf = new_csrf = secrets.token_urlsafe(24)
        request.state.csrf = csrf
        response = await call_next(request)
        if new_csrf:
            response.set_cookie(CSRF_COOKIE, new_csrf, httponly=True, secure=settings.cookie_secure,
                                samesite="lax", path="/")
        n = request.state.nonce
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; "
            f"style-src 'self' 'nonce-{n}'; img-src 'self' data:; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if settings.cookie_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.url.path.startswith(("/app", "/scans", "/admin", "/check/")):
            response.headers["Cache-Control"] = "no-store"
        # Access log without query strings (they may carry tokens) and without IPs.
        access.info(json.dumps({"event": "http", "method": request.method, "path": _redact(request.url.path)[:120],
                                "status": response.status_code, "ms": int((time.monotonic() - start) * 1000)}))
        return response

    @app.exception_handler(LoginRequired)
    async def _login_required(request: Request, exc: LoginRequired):
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException):
        if request.url.path.startswith("/api/") or request.url.path == "/healthz":
            return JSONResponse({"error": exc.detail}, status_code=exc.status_code)
        return render(request, "error.html", {"status": exc.status_code, "detail": exc.detail},
                      status_code=exc.status_code)

    @app.get("/healthz")
    def healthz():
        try:
            with dbmod.engine.connect() as c:
                c.execute(text("SELECT 1"))
            return {"status": "ok"}
        except Exception:  # noqa: BLE001
            return JSONResponse({"status": "db_error"}, status_code=503)

    app.include_router(public.router)
    app.include_router(auth_routes.router)
    app.include_router(dashboard.router)
    app.include_router(admin.router)

    if settings.monitor_in_process:
        from .services import start_monitor_thread
        start_monitor_thread()
    return app


app = create_app()
