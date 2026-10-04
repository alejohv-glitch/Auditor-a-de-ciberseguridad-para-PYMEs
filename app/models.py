"""Database schema. Every tenant-owned row carries ``org_id``; all queries for
tenant data go through ``app.web.deps`` helpers that filter by the caller's org."""
from __future__ import annotations

import datetime as dt

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base, utcnow


class TimestampMixin:
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class Organization(TimestampMixin, Base):
    __tablename__ = "organizations"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    plan: Mapped[str] = mapped_column(String(20), default="free")
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    # White-label (used by agency plan; harmless otherwise)
    brand_name: Mapped[str | None] = mapped_column(String(120))
    brand_color: Mapped[str | None] = mapped_column(String(7))
    report_lang: Mapped[str] = mapped_column(String(2), default="es")
    members: Mapped[list["Membership"]] = relationship(back_populates="org", cascade="all, delete-orphan")
    domains: Mapped[list["Domain"]] = relationship(back_populates="org", cascade="all, delete-orphan")


class User(TimestampMixin, Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    last_login_at: Mapped[dt.datetime | None] = mapped_column(DateTime)
    memberships: Mapped[list["Membership"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("user_id", "org_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    role: Mapped[str] = mapped_column(String(20), default="owner")
    user: Mapped[User] = relationship(back_populates="memberships")
    org: Mapped[Organization] = relationship(back_populates="members")


class AuthSession(Base):
    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime)


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime)
    used_at: Mapped[dt.datetime | None] = mapped_column(DateTime)


class Domain(TimestampMixin, Base):
    __tablename__ = "domains"
    __table_args__ = (UniqueConstraint("org_id", "hostname"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    hostname: Mapped[str] = mapped_column(String(253))
    client_name: Mapped[str | None] = mapped_column(String(120))  # for consultants/agencies
    # Authorisation attestation (who, when, what statement) - required to scan.
    authorized_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    authorized_at: Mapped[dt.datetime | None] = mapped_column(DateTime)
    authorization_statement: Mapped[str | None] = mapped_column(Text)
    # Optional DNS TXT ownership proof
    verification_token: Mapped[str | None] = mapped_column(String(64))
    verified_at: Mapped[dt.datetime | None] = mapped_column(DateTime)
    monitoring_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    monitor_interval_hours: Mapped[int] = mapped_column(Integer, default=24)
    next_scan_at: Mapped[dt.datetime | None] = mapped_column(DateTime)
    org: Mapped[Organization] = relationship(back_populates="domains")
    scans: Mapped[list["Scan"]] = relationship(back_populates="domain", cascade="all, delete-orphan",
                                               order_by="Scan.created_at.desc()")


class Scan(TimestampMixin, Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    public_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)  # non-guessable URL id
    org_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    domain_id: Mapped[int | None] = mapped_column(ForeignKey("domains.id", ondelete="CASCADE"), index=True)
    hostname: Mapped[str] = mapped_column(String(253))
    trigger: Mapped[str] = mapped_column(String(20), default="manual")  # manual|monitor|public|demo
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued|running|completed|failed
    error_code: Mapped[str | None] = mapped_column(String(40))
    error_message: Mapped[str | None] = mapped_column(String(300))
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    score: Mapped[int | None] = mapped_column(Integer)
    grade: Mapped[str | None] = mapped_column(String(2))
    summary: Mapped[dict | None] = mapped_column(JSON)  # scoring output (counts, categories, deductions)
    raw_facts: Mapped[dict | None] = mapped_column(JSON)
    changes: Mapped[dict | None] = mapped_column(JSON)  # diff vs previous scan of the same domain
    analysis_version: Mapped[str | None] = mapped_column(String(20))
    scanner_version: Mapped[str | None] = mapped_column(String(20))
    reviewer_notes: Mapped[str | None] = mapped_column(Text)  # consultant review for paid audits
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    domain: Mapped[Domain | None] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[str] = mapped_column(String(40))
    category: Mapped[str] = mapped_column(String(20))
    kind: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(10))  # fail|pass|unknown|na
    severity: Mapped[str] = mapped_column(String(10))
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    points_lost: Mapped[float] = mapped_column(default=0.0)
    scan: Mapped[Scan] = relationship(back_populates="findings")


class ScoreHistory(Base):
    __tablename__ = "score_history"
    id: Mapped[int] = mapped_column(primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    recorded_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    score: Mapped[int] = mapped_column(Integer)
    grade: Mapped[str] = mapped_column(String(2))


class Subscription(TimestampMixin, Base):
    __tablename__ = "subscriptions"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    plan: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default="active")  # active|past_due|canceled
    provider: Mapped[str] = mapped_column(String(20), default="manual")
    provider_ref: Mapped[str | None] = mapped_column(String(120))
    amount_cents: Mapped[int] = mapped_column(Integer, default=0)
    interval: Mapped[str] = mapped_column(String(10), default="month")
    current_period_end: Mapped[dt.datetime | None] = mapped_column(DateTime)
    canceled_at: Mapped[dt.datetime | None] = mapped_column(DateTime)


class NotificationChannel(TimestampMixin, Base):
    __tablename__ = "notification_channels"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(20))  # email|webhook|discord|telegram
    target: Mapped[str] = mapped_column(String(500))  # address / URL (treat as secret: never logged)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class Notification(TimestampMixin, Base):
    __tablename__ = "notifications"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    channel_id: Mapped[int | None] = mapped_column(ForeignKey("notification_channels.id", ondelete="SET NULL"))
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    event: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(20))  # sent|failed
    detail: Mapped[str | None] = mapped_column(String(300))


class AuditLog(TimestampMixin, Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(60))
    target: Mapped[str | None] = mapped_column(String(253))
    ip_hash: Mapped[str | None] = mapped_column(String(16))  # truncated keyed hash, not the raw IP
    detail: Mapped[dict | None] = mapped_column(JSON)


class Lead(TimestampMixin, Base):
    """Public free-check requests. Purged after LEAD_RETENTION_DAYS unless converted."""
    __tablename__ = "leads"
    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(253), index=True)
    email: Mapped[str | None] = mapped_column(String(254))
    marketing_consent: Mapped[bool] = mapped_column(Boolean, default=False)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    ip_hash: Mapped[str | None] = mapped_column(String(16))
