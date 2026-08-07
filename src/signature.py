"""Verification of the `Stripe-Signature` header.

In production `stripe.Webhook.construct_event` does this for you and that is
what `app.py` uses when the library is installed. This module exists for two
reasons:

1. The test suite can construct signed requests and assert on *which* check
   failed, without a Stripe account, a network connection, or the library.
2. Every failure mode gets its own exception, so a rejected webhook produces a
   log line that says why. "400 Bad Request" on its own is not debuggable at
   3am, and the two common causes - a mismatched signing secret and a proxy
   that rewrote the body - look identical unless you separate them.

`tests/test_signature.py` cross-checks this implementation against the real
library when it is installed, so the two cannot drift apart silently.

The scheme, from Stripe's documentation:

    Stripe-Signature: t=1690000000,v1=<hex>,v1=<hex>

The signed payload is the literal string `{t}.{raw_body}` and the signature is
HMAC-SHA256 keyed with the endpoint's signing secret. Multiple `v1` values
appear while a secret is being rotated - both are valid during the overlap, so
any match is a pass.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import List, Optional

SCHEME = "v1"


class SignatureError(Exception):
    """Base class - callers that do not care why can catch just this."""


class MissingSignature(SignatureError):
    """No Stripe-Signature header at all. Usually a caller that is not Stripe."""


class MalformedSignature(SignatureError):
    """Header present but unparseable, or carrying no v1 signature."""


class TimestampOutOfTolerance(SignatureError):
    """Correctly signed, but too old. This is the replay guard."""


class NoMatchingSignature(SignatureError):
    """Parsed fine, but no v1 value matched.

    Two causes, and they are worth telling apart in your own head: the signing
    secret is from a different endpoint, or something between Stripe and this
    process modified the body.
    """


def _parse_header(header: str) -> tuple[int, List[str]]:
    timestamp: Optional[int] = None
    signatures: List[str] = []

    for part in header.split(","):
        key, _, value = part.strip().partition("=")
        if key == "t":
            try:
                timestamp = int(value)
            except ValueError as exc:
                raise MalformedSignature(f"timestamp is not an integer: {value!r}") from exc
        elif key == SCHEME:
            signatures.append(value)

    if timestamp is None:
        raise MalformedSignature("header carries no t= timestamp")
    if not signatures:
        # A header with only v0 (used by Stripe for a different product) lands
        # here. Rejecting is correct: we cannot verify what we cannot parse.
        raise MalformedSignature(f"header carries no {SCHEME}= signature")

    return timestamp, signatures


def expected_signature(payload: bytes, timestamp: int, secret: str) -> str:
    """The hex digest Stripe should have sent for this exact body."""
    signed_payload = f"{timestamp}.".encode("utf-8") + payload
    return hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()


def verify(
    payload: bytes,
    header: Optional[str],
    secret: str,
    tolerance_seconds: int = 300,
    now: Optional[int] = None,
) -> int:
    """Verify a webhook. Returns the header timestamp, or raises SignatureError.

    `payload` MUST be the raw request body as received. Parsing the JSON and
    re-serialising it changes key order and whitespace, which changes the
    digest - this is the single most common reason a correct integration
    rejects every event it is sent.

    `now` is injectable so the tolerance check is testable without sleeping.
    """
    if not header:
        raise MissingSignature("no Stripe-Signature header")
    if not secret:
        # Guard rather than compute: with an empty secret every HMAC still
        # produces a digest, so a misconfigured deployment would happily
        # "verify" whatever an attacker signed with the same empty key.
        raise SignatureError("no signing secret configured")

    timestamp, signatures = _parse_header(header)

    current = int(time.time()) if now is None else now
    age = current - timestamp
    if abs(age) > tolerance_seconds:
        # abs() also rejects timestamps from the future, which a valid Stripe
        # delivery never has and a forged one might.
        raise TimestampOutOfTolerance(
            f"timestamp is {age}s away from now, tolerance is {tolerance_seconds}s"
        )

    expected = expected_signature(payload, timestamp, secret)
    # compare_digest, not ==. String equality returns early on the first
    # differing byte, which leaks the correct prefix through timing.
    if not any(hmac.compare_digest(expected, candidate) for candidate in signatures):
        raise NoMatchingSignature(
            "no v1 signature matched - wrong signing secret, or the body was "
            "modified in transit"
        )

    return timestamp
