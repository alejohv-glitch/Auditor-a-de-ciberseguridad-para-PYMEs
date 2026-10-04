"""Central configuration. All settings come from environment variables (12-factor).

Nothing secret has a usable default in production: SECRET_KEY must be set when
APP_ENV=production or the app refuses to start.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field


def _bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    app_name: str = field(default_factory=lambda: os.getenv("APP_NAME", "Seclara"))
    env: str = field(default_factory=lambda: os.getenv("APP_ENV", "development"))
    base_url: str = field(default_factory=lambda: os.getenv("BASE_URL", "http://localhost:8000"))
    secret_key: str = field(default_factory=lambda: os.getenv("SECRET_KEY", ""))
    database_url: str = field(default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./data/app.db"))
    cookie_secure: bool = field(default_factory=lambda: _bool("COOKIE_SECURE", False))
    session_days: int = field(default_factory=lambda: int(os.getenv("SESSION_DAYS", "14")))
    # Scanner
    scanner_user_agent: str = field(default_factory=lambda: os.getenv(
        "SCANNER_USER_AGENT",
        "SeclaraBot/1.0 (passive security posture check; +https://seclara.example/bot)"))
    scan_timeout_s: int = field(default_factory=lambda: int(os.getenv("SCAN_TIMEOUT_S", "45")))
    scan_workers: int = field(default_factory=lambda: int(os.getenv("SCAN_WORKERS", "4")))
    # Monitoring loop inside the web process (alternative: cron + `python -m app.cli monitor`)
    monitor_in_process: bool = field(default_factory=lambda: _bool("MONITOR_IN_PROCESS", False))
    monitor_interval_s: int = field(default_factory=lambda: int(os.getenv("MONITOR_INTERVAL_S", "3600")))
    # Email: "console" (dev: prints to stdout) or "smtp"
    email_backend: str = field(default_factory=lambda: os.getenv("EMAIL_BACKEND", "console"))
    smtp_host: str = field(default_factory=lambda: os.getenv("SMTP_HOST", ""))
    smtp_port: int = field(default_factory=lambda: int(os.getenv("SMTP_PORT", "587")))
    smtp_user: str = field(default_factory=lambda: os.getenv("SMTP_USER", ""))
    smtp_password: str = field(default_factory=lambda: os.getenv("SMTP_PASSWORD", ""))
    email_from: str = field(default_factory=lambda: os.getenv("EMAIL_FROM", "no-reply@localhost"))
    # Billing: "none" (manual invoicing) or "stripe" (requires keys; see docs/DEPLOYMENT.md)
    billing_provider: str = field(default_factory=lambda: os.getenv("BILLING_PROVIDER", "none"))
    stripe_secret_key: str = field(default_factory=lambda: os.getenv("STRIPE_SECRET_KEY", ""))
    stripe_webhook_secret: str = field(default_factory=lambda: os.getenv("STRIPE_WEBHOOK_SECRET", ""))
    # Public lead-gen check
    public_check_per_ip_hour: int = field(default_factory=lambda: int(os.getenv("PUBLIC_CHECK_PER_IP_HOUR", "3")))
    lead_retention_days: int = field(default_factory=lambda: int(os.getenv("LEAD_RETENTION_DAYS", "30")))
    contact_email: str = field(default_factory=lambda: os.getenv("CONTACT_EMAIL", "hola@seclara.example"))

    def __post_init__(self) -> None:
        if not self.secret_key:
            if self.env == "production":
                raise RuntimeError("SECRET_KEY must be set in production")
            # Ephemeral dev key: sessions do not survive restarts, which is fine in dev.
            self.secret_key = secrets.token_urlsafe(32)

    @property
    def is_production(self) -> bool:
        return self.env == "production"


settings = Settings()
