"""Scheduler: hourly active-domain re-checks (flag drifting DNS records) and the
retention sweep (objects deleted past retention_days, message rows marked purged)."""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from .. import dns, storage, webhooks
from ..config import settings
from ..db import SessionLocal, init_db
from ..models import Account, Attachment, Domain, Message, MessageEvent

log = logging.getLogger("scheduler")


def recheck_domains() -> int:
    """Hourly job: re-run live DNS lookups for verified/active domains."""
    db = SessionLocal()
    redis_client = None
    changed = 0
    try:
        from ..workers.send_worker import get_redis

        redis_client = get_redis()
        domains = db.query(Domain).filter(Domain.status.in_(["verified", "active"])).all()
        for domain in domains:
            old = domain.status
            new, _ = dns.verify_domain_sync(domain, domain.records)
            if new != old:
                domain.status = new
                db.commit()
                changed += 1
                webhooks.enqueue_for_account(
                    redis_client,
                    domain.account_id,
                    "domain.status_changed",
                    {"domain": domain.name, "from": old, "to": new},
                )
            else:
                db.commit()
        log.info("domain re-check done: %d checked, %d changed", len(domains), changed)
        return changed
    finally:
        db.close()


def retention_sweep() -> int:
    """Per-account retention: delete bucket objects past retention_days, mark purged."""
    db = SessionLocal()
    purged = 0
    try:
        accounts = db.query(Account).all()
        now = datetime.now(timezone.utc)
        for account in accounts:
            days = account.plan.retention_days or settings.retention_default_days
            cutoff = now - timedelta(days=days)
            rows = (
                db.query(Message)
                .filter(
                    Message.account_id == account.id,
                    Message.status != "purged",
                    Message.created_at < cutoff,
                )
                .all()
            )
            for m in rows:
                for key in [m.object_key] + [
                    a.object_key for a in db.query(Attachment).filter(Attachment.message_id == m.id)
                ]:
                    if key:
                        try:
                            storage.delete_object(key)
                        except Exception:  # noqa: BLE001
                            log.warning("could not delete object %s", key)
                m.status = "purged"
                db.add(MessageEvent(message_id=m.id, event="purged", detail=f"retention {days}d"))
                purged += 1
            if rows:
                db.commit()
        log.info("retention sweep done: %d messages purged", purged)
        return purged
    finally:
        db.close()


async def verify_loop() -> None:
    while True:
        await asyncio.sleep(settings.verify_interval_s)
        try:
            await asyncio.to_thread(recheck_domains)
        except Exception:  # noqa: BLE001
            log.exception("domain re-check failed")


async def retention_loop() -> None:
    while True:
        await asyncio.sleep(settings.retention_sweep_interval_s)
        try:
            await asyncio.to_thread(retention_sweep)
        except Exception:  # noqa: BLE001
            log.exception("retention sweep failed")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    init_db()
    log.info("scheduler running (verify every %ds, retention sweep every %ds)",
             settings.verify_interval_s, settings.retention_sweep_interval_s)

    async def runner():
        # one sweep shortly after start, then on the interval
        try:
            await asyncio.to_thread(retention_sweep)
        except Exception:  # noqa: BLE001
            log.exception("initial retention sweep failed")
        await asyncio.gather(verify_loop(), retention_loop())

    try:
        asyncio.run(runner())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
