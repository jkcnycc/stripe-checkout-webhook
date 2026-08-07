"""Send a signed event to a running instance, without Stripe.

Useful when you want to see the failure paths in the server log rather than in
a test runner, and when you have no Stripe account to hand.

    python tools/send_event.py --ref user_1
    python tools/send_event.py --ref user_1 --repeat 2      # idempotency
    python tools/send_event.py --ref user_1 --tamper        # body modified
    python tools/send_event.py --ref user_1 --age 3600      # replay
    python tools/send_event.py --ref user_1 --secret wrong  # wrong endpoint
    python tools/send_event.py --ref user_1 --type charge.refunded

The signing secret is read from STRIPE_WEBHOOK_SECRET, so this signs requests
exactly the way Stripe does - the server cannot tell the difference, which is
the point.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import signature  # noqa: E402


def build_payload(args) -> bytes:
    """Build an event body shaped the way Stripe actually sends that type.

    Charge and dispute events carry **no** `client_reference_id` - that field
    only exists on a Checkout Session. Emitting it anyway would make this tool
    exercise a code path real Stripe never takes, which is exactly how the
    refund handler was wrong for a while.
    """
    if args.type.startswith(("charge.", "refund.")):
        obj = {
            "object": "charge",
            "id": "ch_demo",
            "payment_intent": args.payment_intent,
            "refunded": True,
        }
    else:
        obj = {
            "object": "checkout.session",
            "client_reference_id": args.ref,
            "payment_status": args.payment_status,
            "payment_intent": args.payment_intent,
        }

    return json.dumps(
        {
            "id": args.event_id,
            "object": "event",
            "type": args.type,
            "created": int(time.time()) - args.age,
            "data": {"object": obj},
        }
    ).encode("utf-8")


def send(url: str, payload: bytes, header: str) -> None:
    request = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "Stripe-Signature": header},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            print(f"  {response.status}  {response.read().decode()}")
    except urllib.error.HTTPError as exc:
        # Expected for every deliberate-failure flag, so print it as a result
        # rather than a crash.
        print(f"  {exc.code}  {exc.read().decode()}")
    except urllib.error.URLError as exc:
        print(f"  could not reach {url}: {exc.reason}")
        print("  is the server running?  uvicorn app:app --port 8000")
        raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description="Send a signed webhook event.")
    parser.add_argument("--url", default="http://127.0.0.1:8000/api/webhook")
    parser.add_argument("--ref", default="user_1", help="your app's user id")
    parser.add_argument("--type", default="checkout.session.completed")
    parser.add_argument("--event-id", default=None, help="defaults to a fresh id")
    parser.add_argument("--payment-status", default="paid")
    parser.add_argument(
        "--payment-intent",
        default="pi_demo",
        help="ties a purchase to its refund, the way Stripe does",
    )
    parser.add_argument("--secret", default=None, help="override the signing secret")
    parser.add_argument("--age", type=int, default=0, help="seconds to backdate the signature")
    parser.add_argument("--repeat", type=int, default=1, help="send the same event N times")
    parser.add_argument("--tamper", action="store_true", help="modify the body after signing")
    args = parser.parse_args()

    secret = args.secret if args.secret is not None else os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    if not secret:
        print("STRIPE_WEBHOOK_SECRET is not set, and --secret was not given.")
        return 1

    args.event_id = args.event_id or f"evt_{int(time.time() * 1000)}"
    payload = build_payload(args)

    timestamp = int(time.time()) - args.age
    header = f"t={timestamp},v1={signature.expected_signature(payload, timestamp, secret)}"

    if args.tamper:
        # Signed as user_1, delivered as user_9: the exact attack the
        # signature check exists to stop.
        payload = payload.replace(b'"' + args.ref.encode() + b'"', b'"user_9"')
        print("body modified after signing")

    print(f"POST {args.url}  id={args.event_id} type={args.type}")
    for attempt in range(args.repeat):
        if args.repeat > 1:
            print(f"delivery {attempt + 1} of {args.repeat}")
        send(args.url, payload, header)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
