"""End to end through HTTP: a signed request in, an unlock signal out.

Environment variables are set before `app` is imported, because the config is
read at startup. No Stripe account and no network are involved - the requests
are signed locally with the same secret the service is configured with, which
is exactly what Stripe does.
"""

import json
import os
import time
import unittest

SECRET = "whsec_test_secret"

# Assigned, not setdefault. A developer with STRIPE_WEBHOOK_SECRET already
# exported - which is the normal state while running the service - would
# otherwise have the suite sign with one secret and verify with another, and
# the failure reads as a broken signature check rather than a dirty
# environment. Tests own their configuration.
os.environ["STRIPE_SECRET_KEY"] = "sk_test_dummy"
os.environ["STRIPE_WEBHOOK_SECRET"] = SECRET
os.environ["STRIPE_PRICE_ID"] = "price_dummy"
os.environ["DATABASE_PATH"] = ":memory:"

from fastapi.testclient import TestClient  # noqa: E402

import app as application  # noqa: E402
from src import signature  # noqa: E402


def event_body(
    event_id="evt_1",
    event_type="checkout.session.completed",
    customer_ref="user_1",
    created=None,
    payment_status="paid",
    payment_intent="pi_1",
):
    """A checkout.session event. Sessions carry client_reference_id."""
    return json.dumps(
        {
            "id": event_id,
            "object": "event",
            "type": event_type,
            "created": int(time.time()) if created is None else created,
            "data": {
                "object": {
                    "object": "checkout.session",
                    "client_reference_id": customer_ref,
                    "payment_status": payment_status,
                    "payment_intent": payment_intent,
                }
            },
        }
    ).encode()


def charge_event_body(
    event_id="evt_2",
    event_type="charge.refunded",
    created=None,
    payment_intent="pi_1",
):
    """A charge event, shaped the way Stripe actually sends one.

    Deliberately has **no** client_reference_id - a Charge is a different
    object from a Checkout Session and never carries one. Writing this fixture
    the convenient way, with the field the code already reads, is what hid a
    real bug until a real refund was issued.
    """
    return json.dumps(
        {
            "id": event_id,
            "object": "event",
            "type": event_type,
            "created": int(time.time()) if created is None else created,
            "data": {
                "object": {
                    "object": "charge",
                    "id": "ch_1",
                    "payment_intent": payment_intent,
                    "amount_refunded": 1900,
                    "refunded": True,
                }
            },
        }
    ).encode()


def signed_headers(payload, timestamp=None, secret=SECRET):
    timestamp = int(time.time()) if timestamp is None else timestamp
    digest = signature.expected_signature(payload, timestamp, secret)
    return {"stripe-signature": f"t={timestamp},v1={digest}", "content-type": "application/json"}


class WebhookTests(unittest.TestCase):
    def setUp(self):
        # A fresh client per test rebuilds the in-memory database via lifespan,
        # so no test can be affected by rows another one wrote.
        self.client = TestClient(application.app)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    def post(self, payload, headers=None):
        return self.client.post(
            "/api/webhook", content=payload, headers=headers or signed_headers(payload)
        )

    def unlocked(self, customer_ref="user_1"):
        return self.client.get(f"/api/unlock/{customer_ref}").json()["unlocked"]

    # -- the path that has to work ------------------------------------

    def test_a_paid_session_unlocks_the_customer(self):
        response = self.post(event_body())

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["action"], "granted")
        self.assertTrue(self.unlocked())

    def test_an_unknown_customer_is_locked_rather_than_an_error(self):
        response = self.client.get("/api/unlock/never-seen")

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["unlocked"])

    def test_delayed_payment_success_also_unlocks(self):
        # Bank debits complete hours later under a different event type. An
        # integration that only listens for checkout.session.completed never
        # unlocks these customers.
        self.post(event_body(event_type="checkout.session.async_payment_succeeded"))

        self.assertTrue(self.unlocked())

    # -- the paths that have to fail ----------------------------------

    def test_the_same_event_twice_unlocks_once(self):
        payload = event_body()
        headers = signed_headers(payload)

        first = self.post(payload, headers)
        second = self.post(payload, headers)

        self.assertEqual(first.json()["action"], "granted")
        # 200, not an error: a redelivery is normal traffic, and a non-2xx
        # would make Stripe retry it forever.
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.json()["action"], "duplicate")

    def test_a_tampered_body_is_rejected(self):
        payload = event_body()
        headers = signed_headers(payload)
        tampered = payload.replace(b"user_1", b"user_9")

        response = self.post(tampered, headers)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "NoMatchingSignature")
        self.assertFalse(self.unlocked("user_9"))

    def test_an_unsigned_request_is_rejected(self):
        response = self.client.post(
            "/api/webhook", content=event_body(), headers={"content-type": "application/json"}
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "MissingSignature")

    def test_a_request_signed_with_another_secret_is_rejected(self):
        payload = event_body()
        headers = signed_headers(payload, secret="whsec_attacker")

        self.assertEqual(self.post(payload, headers).status_code, 400)
        self.assertFalse(self.unlocked())

    def test_a_replayed_request_is_rejected(self):
        # Captured off the wire and sent again an hour later. The signature is
        # still genuine; only the timestamp catches it.
        payload = event_body()
        headers = signed_headers(payload, timestamp=int(time.time()) - 3600)

        response = self.post(payload, headers)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "TimestampOutOfTolerance")
        self.assertFalse(self.unlocked())

    def test_an_unpaid_session_does_not_unlock(self):
        response = self.post(event_body(payment_status="unpaid"))

        self.assertEqual(response.json()["action"], "incomplete")
        self.assertFalse(self.unlocked())

    def test_a_refund_locks_the_customer_again(self):
        # The refund is a Charge with no client_reference_id, so the customer
        # can only be found through the payment_intent recorded at purchase.
        now = int(time.time())
        self.post(event_body(event_id="evt_1", created=now, payment_intent="pi_9"))
        response = self.post(charge_event_body(created=now + 60, payment_intent="pi_9"))

        self.assertEqual(response.json()["action"], "revoked")
        self.assertFalse(self.unlocked())

    def test_a_refund_for_an_unknown_payment_asks_for_a_retry(self):
        # The purchase has not been processed yet, so there is nobody to
        # revoke. Guessing would revoke the wrong customer or silently nobody;
        # a 503 makes Stripe redeliver once the purchase has landed.
        response = self.post(charge_event_body(payment_intent="pi_never_seen"))

        self.assertEqual(response.status_code, 503)

    def test_a_retried_refund_succeeds_once_the_purchase_has_landed(self):
        now = int(time.time())
        first = self.post(charge_event_body(created=now + 60, payment_intent="pi_9"))
        self.assertEqual(first.status_code, 503)

        self.post(event_body(event_id="evt_1", created=now, payment_intent="pi_9"))
        # Stripe redelivers the same event id - the release must have let go
        # of the claim, or this would be dismissed as a duplicate.
        second = self.post(charge_event_body(created=now + 60, payment_intent="pi_9"))

        self.assertEqual(second.json()["action"], "revoked")
        self.assertFalse(self.unlocked())

    def test_a_purchase_arriving_after_its_refund_does_not_unlock(self):
        now = int(time.time())
        self.post(event_body(event_id="evt_0", created=now - 120, payment_intent="pi_9"))
        self.post(charge_event_body(created=now, payment_intent="pi_9"))
        # A second, older purchase event for the same customer arrives late.
        response = self.post(event_body(event_id="evt_1", created=now - 60, payment_intent="pi_9"))

        self.assertEqual(response.json()["action"], "stale")
        self.assertFalse(self.unlocked())

    def test_an_event_with_no_handler_is_acknowledged(self):
        response = self.post(event_body(event_type="customer.created"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["action"], "ignored")

    def test_valid_signature_over_a_non_json_body_is_rejected(self):
        payload = b"this is signed, but it is not JSON"

        response = self.post(payload)

        self.assertEqual(response.status_code, 400)
        self.assertIn("JSON", response.json()["detail"])


class HealthTests(unittest.TestCase):
    def test_health_reports_configuration_without_leaking_it(self):
        with TestClient(application.app) as client:
            body = client.get("/api/health").json()

        self.assertTrue(body["ok"])
        self.assertEqual(body["missing_configuration"], [])
        # The keys themselves must never appear in a response.
        self.assertNotIn(SECRET, json.dumps(body))


if __name__ == "__main__":
    unittest.main()
