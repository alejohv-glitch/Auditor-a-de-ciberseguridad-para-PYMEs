"""Billing abstraction. MVP default = manual invoicing (no provider, no keys).

To go live with Stripe: implement ``StripeBilling.checkout_url`` with a Checkout
Session (mode=subscription, price per plan) and ``handle_webhook`` verifying the
signature with STRIPE_WEBHOOK_SECRET, then call ``apply_subscription``. The rest
of the app only reads ``Organization.plan`` and ``Subscription`` rows, so nothing
else changes.
"""
from __future__ import annotations

import datetime as dt
from urllib.parse import quote

from .config import settings
from .db import utcnow
from .models import Organization, Subscription
from .plans import plan as plan_of


class BillingProvider:
    name = "base"

    def checkout_url(self, org: Organization, plan: str) -> str:
        raise NotImplementedError


class ManualBilling(BillingProvider):
    """Sends the customer to an email to request an invoice / bank transfer.
    The admin then runs `python -m app.cli set-plan <email> <plan>`."""
    name = "manual"

    def checkout_url(self, org, plan):
        subject = quote(f"Alta plan {plan} - {org.name}")
        return f"mailto:{settings.contact_email}?subject={subject}"


class StripeBilling(BillingProvider):
    name = "stripe"

    def checkout_url(self, org, plan):  # pragma: no cover - requires credentials
        raise NotImplementedError("Configure Stripe price IDs and implement Checkout (see docs/DEPLOYMENT.md)")


def get_billing() -> BillingProvider:
    return StripeBilling() if settings.billing_provider == "stripe" else ManualBilling()


def apply_subscription(session, org: Organization, plan: str, *, provider: str = "manual",
                       provider_ref: str | None = None, months: int = 1) -> Subscription:
    """Single place where a plan change becomes effective."""
    for old in org_subscriptions(session, org):
        if old.status == "active":
            old.status, old.canceled_at = "canceled", utcnow()
    sub = Subscription(org_id=org.id, plan=plan, status="active", provider=provider, provider_ref=provider_ref,
                       amount_cents=plan_of(plan)["price_cents"],
                       current_period_end=utcnow() + dt.timedelta(days=30 * months))
    org.plan = plan
    session.add(sub)
    return sub


def org_subscriptions(session, org: Organization) -> list[Subscription]:
    from sqlalchemy import select
    return session.scalars(select(Subscription).where(Subscription.org_id == org.id)).all()
