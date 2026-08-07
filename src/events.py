"""Turning a verified Stripe event into an unlock decision.

Separated from `app.py` so the decisions are testable without HTTP, and so the
list of events that mean something is one readable block rather than a chain
of `elif`s buried in a route handler.

Which events matter, and why these:

- `checkout.session.completed` - the customer finished Checkout. For card
  payments this is when money is captured, so it is the unlock signal.
- `checkout.session.async_payment_succeeded` - the same outcome for delayed
  methods (bank debits, some wallets), which complete minutes to days later.
  Integrations that only listen for the first event silently fail to unlock
  every customer who did not pay by card.
- `charge.refunded` / `charge.dispute.created` - the money went back. Leaving
  a refunded customer unlocked is the mirror image of double-unlocking, and it
  gets noticed later and costs more.

Everything else is acknowledged and ignored. Returning 200 for an event we do
not handle is deliberate: a non-2xx tells Stripe to retry, and retrying an
event nobody will ever act on just fills the dashboard with failures.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .store import Store

log = logging.getLogger("events")

UNLOCK_EVENTS = frozenset(
    {"checkout.session.completed", "checkout.session.async_payment_succeeded"}
)
REVOKE_EVENTS = frozenset({"charge.refunded", "charge.dispute.created"})

DEFAULT_PRODUCT = "app_pro"


@dataclass(frozen=True)
class Outcome:
    """What the webhook did. Returned to Stripe as JSON, and logged."""

    action: str  # granted | revoked | duplicate | ignored | incomplete | stale
    event_id: str
    event_type: str
    customer_ref: Optional[str] = None
    detail: str = ""


def _customer_ref(obj: Dict[str, Any], store: Store) -> Optional[str]:
    """Find the identifier that ties this event to a user of your app.

    `client_reference_id` is the right answer, but only a Checkout Session
    carries it. Refunds and disputes deliver a **Charge** and a **Dispute**,
    which are different objects with no such field - so for those, the
    payment_intent recorded at purchase time is what identifies the owner.

    This was found by refunding a real payment, not by a unit test: a
    hand-written charge event tends to be written with the fields the code
    already reads.
    """
    for key in ("client_reference_id", "customer", "customer_email"):
        value = obj.get(key)
        if isinstance(value, str) and value:
            return value

    details = obj.get("customer_details")
    if isinstance(details, dict):
        email = details.get("email")
        if isinstance(email, str) and email:
            return email

    payment_intent = obj.get("payment_intent")
    if isinstance(payment_intent, str) and payment_intent:
        return store.owner_of(payment_intent)

    return None


def handle(event: Dict[str, Any], store: Store, product: str = DEFAULT_PRODUCT) -> Outcome:
    """Apply one verified event. Safe to call twice with the same event."""
    event_id = str(event.get("id", ""))
    event_type = str(event.get("type", ""))
    created = int(event.get("created", 0))
    obj = event.get("data", {}).get("object", {}) or {}

    if not event_id or not event_type:
        # Verified by signature but structurally wrong. Do not retry it.
        log.warning("event missing id or type, ignoring: %r", event)
        return Outcome("ignored", event_id, event_type, detail="missing id or type")

    if event_type not in UNLOCK_EVENTS and event_type not in REVOKE_EVENTS:
        log.info("no handler for type=%s id=%s, acknowledging", event_type, event_id)
        return Outcome("ignored", event_id, event_type, detail="no handler for this type")

    # Claimed before any state change, so a redelivery cannot reach the write.
    if not store.claim_event(event_id, event_type, created):
        return Outcome("duplicate", event_id, event_type, detail="already processed")

    # Past this point the event is claimed, so any failure has to hand the
    # claim back - otherwise Stripe's retry is swallowed as a duplicate and
    # the event is lost with nothing applied.
    try:
        if event_type in UNLOCK_EVENTS:
            # A session can complete with payment still pending - unlocking on
            # that gives the product away for free until the debit clears, or
            # fails.
            status = obj.get("payment_status")
            if status not in (None, "paid", "no_payment_required"):
                log.info("not unlocking id=%s payment_status=%s", event_id, status)
                return Outcome(
                    "incomplete", event_id, event_type, detail=f"payment_status={status}"
                )

        customer_ref = _customer_ref(obj, store)
        if customer_ref is None:
            if event_type in REVOKE_EVENTS:
                # The purchase that would have recorded the owner has not been
                # processed yet - deliveries are not ordered. Hand the claim
                # back and ask Stripe to retry: it backs off for up to three
                # days, by which time the purchase will have landed. Guessing
                # here would mean either revoking nobody or revoking the wrong
                # customer.
                log.warning(
                    "revoke event id=%s not attributable yet, requesting retry", event_id
                )
                store.release_event(event_id)
                return Outcome(
                    "retry", event_id, event_type, detail="owner unknown, retry later"
                )

            log.warning("no customer reference on event id=%s type=%s", event_id, event_type)
            return Outcome("ignored", event_id, event_type, detail="no customer reference")

        if event_type in UNLOCK_EVENTS:
            # Record who this payment belongs to before granting, so a refund
            # arriving later - carrying a Charge rather than a Session - can
            # still be attributed.
            payment_intent = obj.get("payment_intent")
            if isinstance(payment_intent, str) and payment_intent:
                store.link_payment(payment_intent, customer_ref)

            written = store.grant(customer_ref, product, created, event_id)
            action = "granted" if written else "stale"
        else:
            written = store.revoke(customer_ref, product, created, event_id)
            action = "revoked" if written else "stale"
    except Exception:
        log.exception("processing failed after claim id=%s, releasing", event_id)
        store.release_event(event_id)
        raise

    log.info("%s ref=%s id=%s type=%s", action, customer_ref, event_id, event_type)
    return Outcome(action, event_id, event_type, customer_ref=customer_ref)
