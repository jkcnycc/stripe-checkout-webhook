"""Persistence for processed events and unlocked entitlements.

SQLite, because the correctness this file is responsible for is a database
constraint rather than application logic, and a file-backed database makes
that visible in ten lines instead of hiding it behind an ORM.

Two guarantees live here, and both are enforced by the schema rather than by
an `if` statement:

1. **Idempotency.** `processed_events.event_id` is the primary key, so
   `claim_event` either inserts or does not. Two concurrent deliveries of the
   same event cannot both win - one gets the row, the other gets a no-op. An
   `if not exists: insert` in Python has a race between the check and the
   insert; this does not.

2. **Ordering.** Webhook deliveries are not ordered. A refund that arrives
   before the purchase it refunds must not leave the customer unlocked, so
   every write carries the originating `event.created` and a write is refused
   when it is older than what is already recorded.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

log = logging.getLogger("store")

SCHEMA = """
CREATE TABLE IF NOT EXISTS processed_events (
    event_id     TEXT PRIMARY KEY,
    event_type   TEXT NOT NULL,
    created      INTEGER NOT NULL,
    processed_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS payment_owners (
    payment_intent TEXT PRIMARY KEY,
    customer_ref   TEXT NOT NULL,
    recorded_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS entitlements (
    customer_ref  TEXT PRIMARY KEY,
    product       TEXT NOT NULL,
    unlocked      INTEGER NOT NULL,
    event_created INTEGER NOT NULL,
    source_event  TEXT NOT NULL,
    updated_at    INTEGER NOT NULL
);
"""


@dataclass(frozen=True)
class Entitlement:
    customer_ref: str
    product: str
    unlocked: bool
    source_event: str
    updated_at: int


class Store:
    def __init__(self, path: str = "unlocks.db") -> None:
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: uvicorn serves requests from a thread pool.
        # Safe here because every method below is a single autocommitted
        # statement or an explicit transaction, and SQLite serialises writers.
        self._connection = sqlite3.connect(path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.executescript(SCHEMA)
        self._connection.commit()

    def close(self) -> None:
        self._connection.close()

    # ------------------------------------------------------------------
    # Idempotency
    # ------------------------------------------------------------------

    def claim_event(self, event_id: str, event_type: str, created: int) -> bool:
        """Claim an event for processing. True the first time, False after.

        Call this before doing any work. Stripe delivers at least once - a
        network blip on our side means the same event arrives again - so the
        second delivery must be a no-op rather than a second unlock.
        """
        cursor = self._connection.execute(
            "INSERT OR IGNORE INTO processed_events "
            "(event_id, event_type, created, processed_at) VALUES (?, ?, ?, ?)",
            (event_id, event_type, created, int(time.time())),
        )
        self._connection.commit()

        claimed = cursor.rowcount == 1
        if claimed:
            log.info("claimed event id=%s type=%s", event_id, event_type)
        else:
            log.info("duplicate delivery ignored id=%s type=%s", event_id, event_type)
        return claimed

    def release_event(self, event_id: str) -> None:
        """Undo a claim so a redelivery can try again.

        Called only when processing failed *after* claiming. Without this, a
        transient failure - the database briefly unavailable, a downstream
        call timing out - would leave the event marked processed while nothing
        was applied, and Stripe's retry would be swallowed as a duplicate. The
        event is then lost silently, which is the worst of the failure modes
        because nothing looks wrong.
        """
        self._connection.execute(
            "DELETE FROM processed_events WHERE event_id = ?", (event_id,)
        )
        self._connection.commit()
        log.warning("claim released for retry id=%s", event_id)

    def has_processed(self, event_id: str) -> bool:
        row = self._connection.execute(
            "SELECT 1 FROM processed_events WHERE event_id = ?", (event_id,)
        ).fetchone()
        return row is not None

    # ------------------------------------------------------------------
    # Payment ownership
    #
    # A Checkout Session carries client_reference_id - your own user id. A
    # Charge does not: it is a different object, and the refund and dispute
    # events deliver a Charge. Without a recorded mapping there is no way to
    # tell whose access to revoke, so the purchase writes one down and the
    # refund reads it back. payment_intent is the id both objects share.
    # ------------------------------------------------------------------

    def link_payment(self, payment_intent: str, customer_ref: str) -> None:
        self._connection.execute(
            "INSERT INTO payment_owners (payment_intent, customer_ref, recorded_at) "
            "VALUES (?, ?, ?) ON CONFLICT(payment_intent) DO NOTHING",
            (payment_intent, customer_ref, int(time.time())),
        )
        self._connection.commit()
        log.info("payment linked %s -> %s", payment_intent, customer_ref)

    def owner_of(self, payment_intent: str) -> Optional[str]:
        row = self._connection.execute(
            "SELECT customer_ref FROM payment_owners WHERE payment_intent = ?",
            (payment_intent,),
        ).fetchone()
        return row["customer_ref"] if row else None

    # ------------------------------------------------------------------
    # Entitlements
    # ------------------------------------------------------------------

    def _write(
        self,
        customer_ref: str,
        product: str,
        unlocked: bool,
        event_created: int,
        source_event: str,
    ) -> bool:
        """Write an entitlement unless an equally new or newer one exists."""
        with self._connection:  # one transaction: the read and the write
            row = self._connection.execute(
                "SELECT event_created FROM entitlements WHERE customer_ref = ?",
                (customer_ref,),
            ).fetchone()

            if row is not None and event_created < row["event_created"]:
                log.info(
                    "stale write refused ref=%s event=%s created=%d < stored=%d",
                    customer_ref,
                    source_event,
                    event_created,
                    row["event_created"],
                )
                return False

            self._connection.execute(
                "INSERT INTO entitlements "
                "(customer_ref, product, unlocked, event_created, source_event, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(customer_ref) DO UPDATE SET "
                "product=excluded.product, unlocked=excluded.unlocked, "
                "event_created=excluded.event_created, source_event=excluded.source_event, "
                "updated_at=excluded.updated_at",
                (
                    customer_ref,
                    product,
                    1 if unlocked else 0,
                    event_created,
                    source_event,
                    int(time.time()),
                ),
            )

        log.info(
            "entitlement written ref=%s product=%s unlocked=%s event=%s",
            customer_ref,
            product,
            unlocked,
            source_event,
        )
        return True

    def grant(
        self, customer_ref: str, product: str, event_created: int, source_event: str
    ) -> bool:
        return self._write(customer_ref, product, True, event_created, source_event)

    def revoke(
        self, customer_ref: str, product: str, event_created: int, source_event: str
    ) -> bool:
        return self._write(customer_ref, product, False, event_created, source_event)

    def get(self, customer_ref: str) -> Optional[Entitlement]:
        row = self._connection.execute(
            "SELECT customer_ref, product, unlocked, source_event, updated_at "
            "FROM entitlements WHERE customer_ref = ?",
            (customer_ref,),
        ).fetchone()
        if row is None:
            return None
        return Entitlement(
            customer_ref=row["customer_ref"],
            product=row["product"],
            unlocked=bool(row["unlocked"]),
            source_event=row["source_event"],
            updated_at=row["updated_at"],
        )
