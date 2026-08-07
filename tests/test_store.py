"""Idempotency and ordering, tested at the storage layer."""

import unittest

from src.store import Store

NOW = 1_800_000_000


class ClaimTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.addCleanup(self.store.close)

    def test_first_claim_wins_and_the_second_does_not(self):
        first = self.store.claim_event("evt_1", "checkout.session.completed", NOW)
        second = self.store.claim_event("evt_1", "checkout.session.completed", NOW)

        self.assertTrue(first)
        self.assertFalse(second)

    def test_different_events_both_claim(self):
        self.assertTrue(self.store.claim_event("evt_1", "t", NOW))
        self.assertTrue(self.store.claim_event("evt_2", "t", NOW))

    def test_release_allows_a_retry_to_succeed(self):
        self.store.claim_event("evt_1", "t", NOW)
        self.store.release_event("evt_1")

        self.assertFalse(self.store.has_processed("evt_1"))
        self.assertTrue(self.store.claim_event("evt_1", "t", NOW))


class PaymentOwnerTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.addCleanup(self.store.close)

    def test_the_owner_of_a_payment_is_recoverable(self):
        self.store.link_payment("pi_1", "user_1")

        self.assertEqual(self.store.owner_of("pi_1"), "user_1")

    def test_an_unlinked_payment_has_no_owner(self):
        self.assertIsNone(self.store.owner_of("pi_never_seen"))

    def test_relinking_keeps_the_first_owner(self):
        # A redelivered purchase must not reassign a payment to someone else.
        self.store.link_payment("pi_1", "user_1")
        self.store.link_payment("pi_1", "user_2")

        self.assertEqual(self.store.owner_of("pi_1"), "user_1")


class OrderingTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.addCleanup(self.store.close)

    def test_grant_then_refund_leaves_the_customer_locked(self):
        self.store.grant("user_1", "app_pro", NOW, "evt_purchase")
        self.store.revoke("user_1", "app_pro", NOW + 60, "evt_refund")

        entitlement = self.store.get("user_1")
        self.assertIsNotNone(entitlement)
        self.assertFalse(entitlement.unlocked)
        self.assertEqual(entitlement.source_event, "evt_refund")

    def test_a_purchase_delivered_after_its_refund_does_not_unlock(self):
        # Deliveries are not ordered. If the refund lands first and the older
        # purchase is applied afterwards, the customer keeps a product they
        # were refunded for - and nothing in the logs looks wrong.
        self.store.revoke("user_1", "app_pro", NOW + 60, "evt_refund")
        written = self.store.grant("user_1", "app_pro", NOW, "evt_purchase")

        self.assertFalse(written)
        self.assertFalse(self.store.get("user_1").unlocked)

    def test_same_timestamp_is_applied_rather_than_refused(self):
        # Two events can share a created second. Refusing on equality would
        # silently drop the second one, so only strictly older is refused.
        self.store.grant("user_1", "app_pro", NOW, "evt_purchase")
        written = self.store.revoke("user_1", "app_pro", NOW, "evt_refund")

        self.assertTrue(written)
        self.assertFalse(self.store.get("user_1").unlocked)

    def test_unknown_customer_reads_as_absent(self):
        self.assertIsNone(self.store.get("nobody"))


if __name__ == "__main__":
    unittest.main()
