"""Notification channels behind one interface. Add a channel = add a class + register it.

Webhook-type targets are user-supplied URLs, so they go through the same SSRF
guard as the scanner (public hosts, https only).
"""
from __future__ import annotations

import json
import logging
import smtplib
from email.message import EmailMessage
from urllib.parse import urlsplit

import httpx

from .config import settings
from .scanner import netguard

log = logging.getLogger("app.notify")


class NotifyError(Exception):
    pass


def validate_webhook_url(url: str) -> str:
    parts = urlsplit(url.strip())
    if parts.scheme != "https" or not parts.hostname:
        raise NotifyError("Webhook URL must be https://")
    host = netguard.normalize_domain(parts.hostname)
    netguard.resolve_public(host)
    return url.strip()


class Channel:
    kind = "base"

    def send(self, target: str, subject: str, text: str, payload: dict) -> None:
        raise NotImplementedError


class EmailChannel(Channel):
    kind = "email"

    def send(self, target, subject, text, payload):
        send_email(target, subject, text)


class WebhookChannel(Channel):
    kind = "webhook"

    def _post(self, url: str, body: dict) -> None:
        validate_webhook_url(url)
        r = httpx.post(url, json=body, timeout=10, follow_redirects=False)
        if r.status_code >= 400:
            raise NotifyError(f"HTTP {r.status_code}")

    def send(self, target, subject, text, payload):
        self._post(target, {"event": payload.get("event"), "subject": subject, "text": text, "data": payload})


class DiscordChannel(WebhookChannel):
    kind = "discord"

    def send(self, target, subject, text, payload):
        self._post(target, {"content": f"**{subject}**\n{text}"[:1900]})


class TelegramChannel(WebhookChannel):
    """target = "<bot_token>:<chat_id>" is NOT supported to avoid storing bot tokens;
    target is a full https://api.telegram.org/bot<token>/sendMessage?chat_id=<id> URL."""
    kind = "telegram"

    def send(self, target, subject, text, payload):
        self._post(target, {"text": f"{subject}\n{text}"[:4000]})


CHANNELS: dict[str, Channel] = {c.kind: c for c in (EmailChannel(), WebhookChannel(), DiscordChannel(), TelegramChannel())}


def send_email(to: str, subject: str, text: str) -> None:
    if settings.email_backend == "console":
        # Development only: never enable in production (would print reset links).
        print(f"\n--- EMAIL (console backend) to={to}\nSubject: {subject}\n\n{text}\n---\n", flush=True)
        return
    if settings.email_backend != "smtp":
        raise NotifyError("Unknown EMAIL_BACKEND")
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = settings.email_from, to, subject
    msg.set_content(text)
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as s:
        s.starttls()
        if settings.smtp_user:
            s.login(settings.smtp_user, settings.smtp_password)
        s.send_message(msg)


def dispatch(kind: str, target: str, subject: str, text: str, payload: dict) -> tuple[bool, str | None]:
    channel = CHANNELS.get(kind)
    if not channel:
        return False, "unknown channel"
    try:
        channel.send(target, subject, text, payload)
        return True, None
    except Exception as exc:  # noqa: BLE001 - a failing channel must never break a scan
        log.warning(json.dumps({"event": "notification_failed", "kind": kind, "error": type(exc).__name__}))
        return False, type(exc).__name__
