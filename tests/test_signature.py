"""Signature verification, including the failures.

Every test here runs offline. There is no Stripe account, no network, and no
API key involved - a signature is an HMAC, so a correct implementation can be
exercised completely from fixtures.
"""

import time
import unittest

from src import signature

SECRET = "whsec_test_secret"
# A real event body. The "object":"event" field matters: stripe-python reads
# it after verifying, to tell v1 events from v2 ones, so a fixture without it
# verifies fine and then fails to parse.
PAYLOAD = b'{"id":"evt_1","object":"event","type":"checkout.session.completed"}'
NOW = 1_800_000_000


def header_for(payload=PAYLOAD, timestamp=NOW, secret=SECRET):
    return f"t={timestamp},v1={signature.expected_signature(payload, timestamp, secret)}"


class ValidSignatureTests(unittest.TestCase):
    def test_accepts_a_correct_signature(self):
        returned = signature.verify(PAYLOAD, header_for(), SECRET, now=NOW)
        self.assertEqual(returned, NOW)

    def test_accepts_within_tolerance(self):
        # 299s old, tolerance 300s.
        header = header_for(timestamp=NOW - 299)
        signature.verify(PAYLOAD, header, SECRET, tolerance_seconds=300, now=NOW)

    def test_accepts_any_matching_signature_during_secret_rotation(self):
        # Stripe sends one v1 per active secret while a rotation is in flight.
        # Refusing because the *first* one does not match would drop live
        # traffic for the length of the overlap window.
        old = signature.expected_signature(PAYLOAD, NOW, "whsec_old")
        new = signature.expected_signature(PAYLOAD, NOW, SECRET)
        header = f"t={NOW},v1={old},v1={new}"

        signature.verify(PAYLOAD, header, SECRET, now=NOW)

    def test_ignores_unknown_fields_in_the_header(self):
        # Stripe has added fields before. An unknown key must not be fatal.
        header = header_for() + ",v0=somethingelse"
        signature.verify(PAYLOAD, header, SECRET, now=NOW)


class RejectionTests(unittest.TestCase):
    def test_missing_header(self):
        with self.assertRaises(signature.MissingSignature):
            signature.verify(PAYLOAD, None, SECRET, now=NOW)

    def test_empty_header(self):
        with self.assertRaises(signature.MissingSignature):
            signature.verify(PAYLOAD, "", SECRET, now=NOW)

    def test_header_without_timestamp(self):
        with self.assertRaises(signature.MalformedSignature):
            signature.verify(PAYLOAD, "v1=abc", SECRET, now=NOW)

    def test_header_without_v1(self):
        with self.assertRaises(signature.MalformedSignature):
            signature.verify(PAYLOAD, f"t={NOW}", SECRET, now=NOW)

    def test_non_integer_timestamp(self):
        with self.assertRaises(signature.MalformedSignature):
            signature.verify(PAYLOAD, "t=not-a-number,v1=abc", SECRET, now=NOW)

    def test_wrong_secret(self):
        header = header_for(secret="whsec_someone_elses_endpoint")
        with self.assertRaises(signature.NoMatchingSignature):
            signature.verify(PAYLOAD, header, SECRET, now=NOW)

    def test_tampered_body(self):
        # The signature is valid for the original body. Changing one digit of
        # the amount after signing must not survive.
        header = header_for(payload=b'{"amount":100}')
        with self.assertRaises(signature.NoMatchingSignature):
            signature.verify(b'{"amount":900}', header, SECRET, now=NOW)

    def test_replayed_old_event(self):
        # Correctly signed, captured, and sent again an hour later. The
        # signature still verifies - only the timestamp catches this.
        header = header_for(timestamp=NOW - 3600)
        with self.assertRaises(signature.TimestampOutOfTolerance):
            signature.verify(PAYLOAD, header, SECRET, tolerance_seconds=300, now=NOW)

    def test_timestamp_from_the_future(self):
        header = header_for(timestamp=NOW + 3600)
        with self.assertRaises(signature.TimestampOutOfTolerance):
            signature.verify(PAYLOAD, header, SECRET, tolerance_seconds=300, now=NOW)

    def test_empty_secret_is_refused_rather_than_used(self):
        # An unset STRIPE_WEBHOOK_SECRET must not silently become a valid key
        # that anyone can sign with.
        header = header_for(secret="")
        with self.assertRaises(signature.SignatureError):
            signature.verify(PAYLOAD, header, "", now=NOW)

    def test_reserialised_body_fails(self):
        # Documents the most common real integration bug: verifying against
        # json.dumps(json.loads(body)) instead of the bytes as received.
        import json

        reserialised = json.dumps(json.loads(PAYLOAD)).encode()
        self.assertNotEqual(reserialised, PAYLOAD)
        with self.assertRaises(signature.NoMatchingSignature):
            signature.verify(reserialised, header_for(), SECRET, now=NOW)


class OfficialLibraryAgreementTests(unittest.TestCase):
    """Cross-check against stripe-python so the two cannot drift apart.

    Skipped when the package is absent, which keeps the rest of the suite
    dependency-free while still proving equivalence wherever it is installed.
    """

    def setUp(self):
        try:
            import stripe
        except ImportError:
            self.skipTest("stripe package not installed")
        self.stripe = stripe
        # The exception moved out of stripe.error in v8, so accept either.
        self.verification_error = getattr(
            stripe, "SignatureVerificationError", None
        ) or stripe.error.SignatureVerificationError

    def test_a_header_this_module_produces_is_accepted_by_stripe(self):
        # Signed with a current timestamp because the library uses the real
        # clock and has no injection point for it.
        now = int(time.time())
        event = self.stripe.Webhook.construct_event(
            PAYLOAD.decode(), header_for(timestamp=now), SECRET
        )

        self.assertEqual(event["id"], "evt_1")
        signature.verify(PAYLOAD, header_for(timestamp=now), SECRET, now=now)

    def test_a_header_stripe_rejects_is_rejected_here_too(self):
        bad = f"t={NOW},v1=deadbeef"

        with self.assertRaises(self.verification_error):
            self.stripe.Webhook.construct_event(PAYLOAD.decode(), bad, SECRET)
        with self.assertRaises(signature.SignatureError):
            signature.verify(PAYLOAD, bad, SECRET, now=NOW)


if __name__ == "__main__":
    unittest.main()
