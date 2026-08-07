"""Stripe Checkout + webhook service.

    pip install -r requirements.txt
    cp .env.example .env      # fill in your test keys
    uvicorn app:app --port 8000

Endpoints:

    POST /api/checkout            create a Checkout Session, return its URL
    POST /api/webhook             receive Stripe events (signature verified)
    GET  /api/unlock/{ref}        the unlock signal a client app polls
    GET  /api/health              configuration check

The service never trusts the client about payment. The mobile app asks
/api/unlock, and the only thing that can flip that answer is a signed webhook
from Stripe. A success redirect proves the browser reached a URL, nothing more
- it can be typed by hand, so anything that unlocks on it is unlocked for
free.
"""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from dataclasses import asdict
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from src import signature
from src.config import Config, load_config
from src.events import handle
from src.store import Store

logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(name)s  %(message)s")
log = logging.getLogger("app")

state: Dict[str, Any] = {}


@asynccontextmanager
async def lifespan(_: FastAPI):
    config = load_config()
    state["config"] = config
    state["store"] = Store(config.database_path)

    missing = config.missing()
    if missing:
        # Warn, do not exit. The service still answers /api/health, which is
        # how you find out what is unset - a container that crash-loops on
        # boot tells you far less.
        log.warning("missing configuration: %s", ", ".join(missing))
    else:
        log.info("configured, database=%s", config.database_path)

    yield

    state["store"].close()
    state.clear()


app = FastAPI(title="Stripe Checkout + Webhook", lifespan=lifespan)


def _config() -> Config:
    return state["config"]


def _store() -> Store:
    return state["store"]


# ----------------------------------------------------------------------
# Health
# ----------------------------------------------------------------------


@app.get("/api/health")
def health() -> Dict[str, Any]:
    config = _config()
    missing = config.missing()
    # Names of missing variables only - never their values, and never a
    # partial key. A health endpoint is usually the least protected route.
    return {"ok": not missing, "missing_configuration": missing}


# ----------------------------------------------------------------------
# Checkout
# ----------------------------------------------------------------------


class CheckoutRequest(BaseModel):
    # Your user id, not Stripe's. It comes back on the webhook as
    # client_reference_id, which is what makes the payment attributable to a
    # user without a second lookup.
    customer_ref: str = Field(min_length=1, max_length=200)
    quantity: int = Field(default=1, ge=1, le=10)


@app.post("/api/checkout")
def create_checkout(request: CheckoutRequest) -> Dict[str, str]:
    config = _config()
    missing = config.missing()
    if missing:
        raise HTTPException(status_code=503, detail=f"not configured: {', '.join(missing)}")

    try:
        import stripe  # imported here so the webhook path works without it
    except ImportError as exc:
        raise HTTPException(
            status_code=503, detail="the stripe package is not installed"
        ) from exc

    stripe.api_key = config.secret_key
    parameters = {
        "mode": "payment",
        "line_items": [{"price": config.price_id, "quantity": request.quantity}],
        "client_reference_id": request.customer_ref,
        "success_url": config.success_url,
        "cancel_url": config.cancel_url,
    }
    if config.checkout_locale:
        # Omitted rather than sent empty: Stripe rejects locale="" but is
        # happy to auto-detect when the key is absent.
        parameters["locale"] = config.checkout_locale

    try:
        session = stripe.checkout.Session.create(**parameters)
    except Exception as exc:  # stripe raises several unrelated error classes
        log.error("checkout session failed ref=%s: %s", request.customer_ref, exc)
        raise HTTPException(status_code=502, detail=f"stripe error: {exc}") from exc

    log.info("checkout session created ref=%s id=%s", request.customer_ref, session.id)
    return {"session_id": session.id, "url": session.url}


@app.get("/api/checkout/success")
def checkout_success() -> Dict[str, str]:
    # Deliberately says nothing about entitlement. See the module docstring.
    return {"status": "payment submitted", "note": "unlock is confirmed by webhook"}


@app.get("/api/checkout/cancel")
def checkout_cancel() -> Dict[str, str]:
    return {"status": "cancelled"}


# ----------------------------------------------------------------------
# Webhook
# ----------------------------------------------------------------------


@app.post("/api/webhook")
async def webhook(request: Request) -> Dict[str, Any]:
    config = _config()

    # The raw bytes, before any parsing. Verifying against a re-serialised
    # body fails every time, because json.dumps does not reproduce the exact
    # whitespace and key order Stripe signed.
    payload = await request.body()
    header = request.headers.get("stripe-signature")

    if not config.webhook_secret:
        log.error("webhook received but STRIPE_WEBHOOK_SECRET is unset")
        raise HTTPException(status_code=503, detail="webhook secret not configured")

    try:
        signature.verify(
            payload,
            header,
            config.webhook_secret,
            tolerance_seconds=config.tolerance_seconds,
        )
    except signature.SignatureError as exc:
        # Log the class, not the header - the header is attacker-controlled.
        log.warning("rejected webhook: %s: %s", type(exc).__name__, exc)
        raise HTTPException(status_code=400, detail=type(exc).__name__) from exc

    try:
        event = json.loads(payload)
    except json.JSONDecodeError as exc:
        # Signed by us but not JSON. Not retryable, so do not ask for a retry.
        log.error("verified webhook body is not JSON: %s", exc)
        raise HTTPException(status_code=400, detail="body is not valid JSON") from exc

    if not isinstance(event, dict):
        log.error("verified webhook body is not a JSON object")
        raise HTTPException(status_code=400, detail="body is not a JSON object")

    try:
        outcome = handle(event, _store())
    except Exception:
        # 500 asks Stripe to redeliver, which is what we want for a transient
        # failure such as the database being briefly unavailable. handle()
        # has already released its claim on the way out, so the redelivery
        # is processed rather than dismissed as a duplicate.
        log.exception("handler failed for event, asking Stripe to retry")
        raise HTTPException(status_code=500, detail="handler failed")

    if outcome.action == "retry":
        # A 2xx would tell Stripe the event is done. This one is not - it is
        # waiting on another event that has not arrived yet, so it has to be
        # redelivered.
        raise HTTPException(status_code=503, detail=outcome.detail)

    return {"received": True, **asdict(outcome)}


# ----------------------------------------------------------------------
# Unlock signal
# ----------------------------------------------------------------------


@app.get("/api/unlock/{customer_ref}")
def unlock(customer_ref: str) -> Dict[str, Any]:
    """The JSON the client app reads. Absent customer is a normal answer."""
    entitlement = _store().get(customer_ref)
    if entitlement is None:
        return {"customer_ref": customer_ref, "unlocked": False, "product": None}
    return {
        "customer_ref": entitlement.customer_ref,
        "unlocked": entitlement.unlocked,
        "product": entitlement.product,
        "updated_at": entitlement.updated_at,
    }
