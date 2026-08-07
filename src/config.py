"""Configuration from the environment.

Secrets are read from environment variables and never written to disk, echoed
in a response, or included in a log line. `describe()` exists so the service
can report what it is missing at startup instead of failing on the first real
request from Stripe - a webhook that 500s because a variable was unset looks
identical to a webhook that is broken.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class Config:
    # sk_test_... - only ever used server side.
    secret_key: str
    # whsec_... - the signing secret for ONE endpoint. Each endpoint you add in
    # the Stripe dashboard gets its own secret; they are not interchangeable.
    webhook_secret: str
    price_id: str
    success_url: str
    cancel_url: str
    # Checkout's own language. Empty means let Stripe pick from the browser's
    # Accept-Language, which is the right default for a consumer product and
    # the wrong one for a demo recorded on a non-English machine.
    checkout_locale: str = ""
    database_path: str = "unlocks.db"
    # Stripe's own libraries default to 300s. Anything older is treated as a
    # replay even when the signature is valid, because a valid signature stays
    # valid forever - the timestamp is what expires.
    tolerance_seconds: int = 300

    def missing(self) -> List[str]:
        """Names of the required variables that are not set."""
        required = {
            "STRIPE_SECRET_KEY": self.secret_key,
            "STRIPE_WEBHOOK_SECRET": self.webhook_secret,
            "STRIPE_PRICE_ID": self.price_id,
        }
        return [name for name, value in required.items() if not value]


def load_config() -> Config:
    """Build a Config from the environment. Never raises - see `missing()`.

    Loading must not raise, because the webhook endpoint has to be able to
    return a clear 503 rather than crash the worker when a variable is absent.
    """
    return Config(
        secret_key=os.environ.get("STRIPE_SECRET_KEY", ""),
        webhook_secret=os.environ.get("STRIPE_WEBHOOK_SECRET", ""),
        price_id=os.environ.get("STRIPE_PRICE_ID", ""),
        success_url=os.environ.get("SUCCESS_URL", "http://localhost:8000/api/checkout/success"),
        cancel_url=os.environ.get("CANCEL_URL", "http://localhost:8000/api/checkout/cancel"),
        checkout_locale=os.environ.get("CHECKOUT_LOCALE", ""),
        database_path=os.environ.get("DATABASE_PATH", "unlocks.db"),
        tolerance_seconds=int(os.environ.get("WEBHOOK_TOLERANCE_SECONDS", "300")),
    )
