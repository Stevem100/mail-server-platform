"""Webhooks: signed events for your app.

Events: message.received, message.delivered, message.deferred, message.bounced,
message.complained, domain.status_changed.

Delivery: HTTP POST with the event JSON; the body is signed with HMAC-SHA256 and the
hex digest goes in the X-Signature header. A dispatcher worker retries up to 5 times
with backoff, then marks the attempt failed.
"""

import hashlib
import hmac
import json
import logging
import time

import httpx

from .config import settings
from .models import Webhook

log = logging.getLogger("webhooks")

QUEUE = "q:webhooks"
EVENTS = [
    "message.received",
    "message.delivered",
    "message.deferred",
    "message.bounced",
    "message.complained",
    "domain.status_changed",
]


def sign(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def enqueue_for_account(redis_client, account_id: str, event: str, data: dict) -> int:
    """Push one job per registered webhook. Snapshot url/secret so later edits cannot
    break in-flight deliveries."""
    import json as _json

    from .db import SessionLocal

    db = SessionLocal()
    try:
        hooks = (
            db.query(Webhook)
            .filter(Webhook.account_id == account_id, Webhook.active.is_(True))
            .all()
        )
        pushed = 0
        for h in hooks:
            if h.events and event not in h.events:
                continue
            job = {
                "webhook_id": h.id,
                "url": h.url,
                "secret": h.secret,
                "event": event,
                "data": data,
            }
            redis_client.lpush(QUEUE, _json.dumps(job))
            pushed += 1
        return pushed
    finally:
        db.close()


def deliver_job(job: dict) -> bool:
    """Single delivery attempt. Returns True on 2xx."""
    payload = {
        "event": job["event"],
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "data": job["data"],
    }
    body = json.dumps(payload).encode()
    headers = {
        "Content-Type": "application/json",
        "X-Signature": sign(job["secret"], body),
        "X-Event": job["event"],
    }
    try:
        resp = httpx.post(job["url"], content=body, headers=headers, timeout=10)
        return 200 <= resp.status_code < 300
    except httpx.HTTPError as exc:
        log.warning("webhook %s -> %s failed: %s", job["webhook_id"], job["url"], exc)
        return False


def backoff_seconds(attempt: int) -> int:
    return min(2**attempt, 60)
