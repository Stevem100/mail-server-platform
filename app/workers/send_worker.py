"""Send worker: DKIM-signs queued messages and delivers them.

Every API send and every authenticated submission ends in the same Postfix-queue
equivalent: Redis list "q:send". This worker:

1. Loads the message, signs it with the sending domain's DKIM key (Rspamd step),
   and stores the final signed copy back under outbound/ ("final signed message
   as sent").
2. Delivers to the smarthost (SMTP_RELAY_HOST) or straight to each recipient's MX,
   with opportunistic STARTTLS.
3. Updates the message to delivered / deferred / bounced and fires the matching
   webhook: message.delivered, message.deferred, message.bounced.

Soft failures follow the retry schedule from the design doc: 5 min, 30 min, 2 h,
then every 4 h up to 3 days, after which the message is marked bounced.
Hard 5xx failures bounce immediately.
"""

import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone

import aiosmtplib

from .. import mail, storage, webhooks
from ..config import settings
from ..db import SessionLocal, init_db
from ..models import Account, Domain, Message, MessageEvent
from ..security import decrypt_secret
from ..services.outbound import SEND_QUEUE, next_retry_delay

log = logging.getLogger("send-worker")

SCHED_ZSET = "q:send_sched"  # members: message ids, score: due epoch seconds


def get_redis():
    import redis

    return redis.Redis.from_url(settings.redis_url, decode_responses=True)


# --- Step 1: load, DKIM-sign, store the final copy (sync, DB + bucket) -----------------


def load_for_delivery(message_id: str) -> dict | None:
    db = SessionLocal()
    try:
        m = db.get(Message, message_id)
        if m is None or m.status != "queued":
            return None
        domain = db.get(Domain, m.domain_id)
        if domain is None:
            return None
        raw = storage.get_object(m.object_key)
        priv = decrypt_secret(domain.dkim_private_enc)
        signed = mail.dkim_sign(raw, domain.name, domain.dkim_selector, priv)
        storage.put_object(m.object_key, signed, content_type="message/rfc822")
        return {
            "id": m.id,
            "account_id": m.account_id,
            "from": m.from_addr,
            "rcpts": list(m.to_addrs or []),
            "raw": signed,
        }
    finally:
        db.close()


def resolve_mx(recipient_domain: str) -> list[str]:
    import dns.resolver

    try:
        answers = dns.resolver.resolve(recipient_domain, "MX")
        hosts = sorted(
            ((int(r.preference), str(r.exchange).rstrip(".")) for r in answers), key=lambda p: p[0]
        )
        return [h for _, h in hosts]
    except Exception:  # noqa: BLE001
        # RFC 5321 fallback: no MX -> the A record
        return [recipient_domain]


# --- Step 2: deliver --------------------------------------------------------------------
# results: {rcpt: {"ok": bool, "permanent": bool, "detail": str}}


async def _send_transaction(host: str, port: int, payload: dict, rcpts: list[str]) -> dict:
    """One SMTP transaction; returns per-recipient result map. Raises on connection issues."""
    out = {}
    async with aiosmtplib.SMTP(
        hostname=host, port=port, local_hostname=settings.mail_hostname, timeout=30
    ) as client:
        if port == 25:  # opportunistic TLS for direct MX; relay ports are configured by the operator
            try:
                await client.starttls()
            except Exception:  # noqa: BLE001
                pass
        try:
            refused = await client.sendmail(payload["from"], rcpts, payload["raw"])
            for rcpt in rcpts:
                if refused and rcpt in refused:
                    code, msg = refused[rcpt]
                    out[rcpt] = {
                        "ok": str(code).startswith("2"),
                        "permanent": str(code).startswith("5"),
                        "detail": f"{code} {msg}",
                    }
                else:
                    out[rcpt] = {"ok": True, "permanent": False, "detail": f"via {host}:{port}"}
        except aiosmtplib.SMTPRecipientsRefused as exc:
            for rcpt in rcpts:
                code, msg = (exc.recipients or {}).get(rcpt, (550, "refused"))
                out[rcpt] = {
                    "ok": False,
                    "permanent": str(code).startswith("5"),
                    "detail": f"{code} {msg}",
                }
    return out


async def deliver(payload: dict) -> dict:
    results: dict = {}
    relay = settings.smtp_relay_host
    if relay:
        try:
            return await _send_transaction(relay, settings.smtp_relay_port, payload, payload["rcpts"])
        except Exception as exc:  # noqa: BLE001
            permanent = isinstance(
                exc, (aiosmtplib.SMTPAuthenticationError, aiosmtplib.SMTPHeloError)
            )
            detail = f"relay {type(exc).__name__}: {exc}"
            return {
                r: {"ok": False, "permanent": permanent, "detail": detail} for r in payload["rcpts"]
            }

    # Direct MX delivery, one transaction per recipient domain
    groups: dict[str, list[str]] = {}
    for rcpt in payload["rcpts"]:
        groups.setdefault(rcpt.rpartition("@")[-1], []).append(rcpt)

    for rdomain, rcpts in groups.items():
        hosts = await asyncio.to_thread(resolve_mx, rdomain)
        settled = False
        for host in hosts[:3]:  # first three MX preferences
            try:
                group_results = await _send_transaction(host, 25, payload, rcpts)
                results.update(group_results)
                settled = True
                break
            except aiosmtplib.SMTPResponseException as exc:
                # Early permanent rejection of the whole transaction: no point trying other MX
                permanent = str(exc.code).startswith("5")
                for rcpt in rcpts:
                    results[rcpt] = {
                        "ok": False,
                        "permanent": permanent,
                        "detail": f"mx={host} {exc.code} {exc.message}",
                    }
                settled = True
                break
            except Exception as exc:  # noqa: BLE001
                log.info("mx %s for %s failed: %s", host, rdomain, exc)
                continue
        if not settled:  # temporary: no MX reachable — defer, do not bounce
            for rcpt in rcpts:
                results[rcpt] = {
                    "ok": False,
                    "permanent": False,
                    "detail": f"no reachable MX for {rdomain}",
                }
    return results


# --- Step 3: record the outcome ------------------------------------------------------------


def record_outcome(message_id: str, results: dict, redis_client) -> None:
    db = SessionLocal()
    try:
        m = db.get(Message, message_id)
        if m is None:
            return
        ok = [r for r, res in results.items() if res["ok"]]
        failed = {r: res["detail"] for r, res in results.items() if not res["ok"]}

        if ok:
            m.status = "delivered"
            m.next_retry_at = None
            if failed:
                m.last_error = "; ".join(f"{r}: {d}" for r, d in failed.items())[:500]
            db.add(
                MessageEvent(
                    message_id=m.id,
                    event="delivered",
                    detail=(f"ok={ok}" + (f" failed={failed}" if failed else ""))[:500],
                )
            )
            db.commit()
            webhooks.enqueue_for_account(
                redis_client, m.account_id, "message.delivered", _payload(m)
            )
            return

        detail = next(iter(failed.values()))
        if not any(res["permanent"] for res in results.values()):
            m.retry_count += 1
            delay = next_retry_delay(m.retry_count)
            if delay is None:
                _bounce(db, m, detail, redis_client)
            else:
                m.status = "deferred"
                m.last_error = detail[:500]
                due = datetime.now(timezone.utc) + timedelta(seconds=delay)
                m.next_retry_at = due
                db.add(
                    MessageEvent(
                        message_id=m.id, event="deferred", detail=f"retry in {delay}s: {detail}"
                    )
                )
                db.commit()
                redis_client.zadd(SCHED_ZSET, {m.id: due.timestamp()})
                webhooks.enqueue_for_account(
                    redis_client, m.account_id, "message.deferred", _payload(m)
                )
        else:
            _bounce(db, m, detail, redis_client)
    finally:
        db.close()


def _bounce(db, m: Message, detail: str, redis_client) -> None:
    m.status = "bounced"
    m.last_error = detail[:500]
    m.next_retry_at = None
    db.add(MessageEvent(message_id=m.id, event="bounced", detail=detail))
    db.commit()
    webhooks.enqueue_for_account(redis_client, m.account_id, "message.bounced", _payload(m))


def _payload(m: Message) -> dict:
    return {
        "id": m.id,
        "from": m.from_addr,
        "to": m.to_addrs,
        "subject": m.subject,
        "status": m.status,
    }


# --- Loops -----------------------------------------------------------------------------------


async def process_one(message_id: str, redis_client) -> None:
    payload = await asyncio.to_thread(load_for_delivery, message_id)
    if payload is None:
        return
    results = await deliver(payload)
    await asyncio.to_thread(record_outcome, message_id, results, redis_client)


async def worker_loop() -> None:
    redis_client = get_redis()
    log.info("send worker running (relay=%s)", settings.smtp_relay_host or "direct MX")
    while True:
        try:
            job = await asyncio.to_thread(redis_client.brpop, SEND_QUEUE, timeout=5)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.error("queue error: %s", exc)
            await asyncio.sleep(2)
            continue
        if not job:
            continue
        _, message_id = job
        try:
            await process_one(message_id, redis_client)
        except Exception:  # noqa: BLE001
            log.exception("processing %s failed", message_id)


async def retry_mover_loop() -> None:
    """Moves due deferred messages from the zset back onto the main queue."""
    redis_client = get_redis()
    while True:
        try:
            due = redis_client.zrangebyscore(SCHED_ZSET, "-inf", time.time(), start=0, num=50)
            for message_id in due:
                if not redis_client.zrem(SCHED_ZSET, message_id):
                    continue
                db = SessionLocal()
                try:
                    m = db.get(Message, message_id)
                    if m and m.status == "deferred":
                        m.status = "queued"
                        db.commit()
                        redis_client.lpush(SEND_QUEUE, message_id)
                finally:
                    db.close()
        except Exception as exc:  # noqa: BLE001
            log.error("retry mover error: %s", exc)
        await asyncio.sleep(5)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    init_db()

    async def runner():
        await asyncio.gather(worker_loop(), retry_mover_loop())

    try:
        asyncio.run(runner())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
