"""Webhook dispatcher: POSTs signed events, 5 attempts with backoff, then failed."""

import asyncio
import json
import logging

from .. import webhooks
from ..config import settings
from ..db import init_db

log = logging.getLogger("webhook-worker")


def get_redis():
    import redis

    return redis.Redis.from_url(settings.redis_url, decode_responses=True)


async def worker_loop() -> None:
    redis_client = get_redis()
    log.info("webhook worker running")
    while True:
        try:
            job = await asyncio.to_thread(redis_client.brpop, webhooks.QUEUE, timeout=5)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.error("queue error: %s", exc)
            await asyncio.sleep(2)
            continue
        if not job:
            continue

        _, raw = job
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            log.error("dropping malformed webhook job")
            continue

        # 5 attempts with exponential backoff, then marked failed
        for attempt in range(1, settings.webhook_max_attempts + 1):
            ok = await asyncio.to_thread(webhooks.deliver_job, payload)
            if ok:
                break
            if attempt < settings.webhook_max_attempts:
                await asyncio.sleep(webhooks.backoff_seconds(attempt))
        else:
            log.error(
                "webhook %s -> %s marked failed after %d attempts",
                payload.get("webhook_id"), payload.get("url"), settings.webhook_max_attempts,
            )


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    init_db()
    try:
        asyncio.run(worker_loop())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
