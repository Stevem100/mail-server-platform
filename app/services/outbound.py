"""Outbound path shared by the HTTP API and SMTP submission ("two doors, one queue").

1. Validate the sender domain is active and owned by the caller  -> else 422
2. Check rate limits in Redis                                    -> 429 (SMTP: 452)
3. Check recipient count and message size                        -> 422 (SMTP: 552)
4. Build the final MIME message, store it + attachments under outbound/
5. Insert a messages row with status queued and push to the Redis send queue
6. The send worker signs with DKIM and hands the message to the relay / recipient MX
"""

import base64
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .. import mail, storage
from ..errors import ApiError
from ..limits import check_rate, ensure_account_active
from ..models import Account, Attachment, Domain, Message, MessageEvent
from ..security import object_id

log = logging.getLogger("outbound")

SEND_QUEUE = "q:send"


def parse_from(from_value: str) -> tuple[str, str]:
    """'Billing <billing@example.com>' -> ('Billing', 'billing@example.com')."""
    from email.utils import parseaddr

    name, addr = parseaddr(from_value or "")
    addr = addr or (from_value or "").strip()
    if "@" not in addr:
        raise ApiError(422, "invalid_sender", f"Invalid from address: {from_value!r}")
    return name, addr.lower()


def resolve_sender_domain(db: Session, account: Account, sender_addr: str) -> Domain:
    domain_name = sender_addr.split("@")[-1]
    domain = (
        db.query(Domain)
        .filter(Domain.account_id == account.id, Domain.name == domain_name)
        .first()
    )
    if domain is None:
        raise ApiError(
            422, "invalid_sender_domain", "The from domain must be active in your account"
        )
    if domain.status != "active" or account.status == "suspended":
        raise ApiError(
            422, "inactive_sender_domain", f"Domain {domain_name} is not active ({domain.status})"
        )
    return domain


def create_outgoing_message(
    db: Session,
    redis_client,
    account: Account,
    *,
    from_value: str,
    to: list[str],
    cc: list[str] | None,
    bcc: list[str] | None,
    subject: str,
    text: str | None,
    html: str | None,
    attachments: list[dict] | None,
    idempotency_key: str | None,
    source: str = "api",
) -> tuple[Message, bool]:
    """Returns (message, replayed). Raises ApiError on any plan/validation failure."""
    ensure_account_active(account)

    # Idempotent retries return the original message
    if idempotency_key:
        existing = (
            db.query(Message)
            .filter(Message.account_id == account.id, Message.idempotency_key == idempotency_key)
            .first()
        )
        if existing:
            return existing, True

    plan = account.plan

    # Recipient count check -> 422
    to = [t.strip().lower() for t in (to or []) if t and t.strip()]
    cc = [t.strip().lower() for t in (cc or []) if t and t.strip()]
    bcc = [t.strip().lower() for t in (bcc or []) if t and t.strip()]
    rcpt_count = len(set(to + cc + bcc))
    if rcpt_count == 0:
        raise ApiError(422, "no_recipients", "At least one recipient is required")
    if rcpt_count > plan.max_recipients_per_message:
        raise ApiError(
            422,
            "too_many_recipients",
            f"Message has {rcpt_count} recipients, plan allows {plan.max_recipients_per_message}",
        )

    # Sender domain check -> 422 (the doc checks the domain first, then rate limits)
    _, sender_addr = parse_from(from_value)
    domain = resolve_sender_domain(db, account, sender_addr)

    # Rate limits -> 429 (Redis counters, per-minute and per-day)
    check_rate(redis_client, account)

    # Attachment size check (base64 decoded bytes, streamed to the bucket)
    att_meta = []
    total_att_bytes = 0
    for att in attachments or []:
        try:
            data = base64.b64decode(att.get("content_base64") or "", validate=False)
        except Exception as exc:  # noqa: BLE001
            raise ApiError(422, "invalid_attachment", f"Attachment is not valid base64: {att.get('filename')}") from exc
        total_att_bytes += len(data)
        att_meta.append({**att, "_data": data})

    size_cap = plan.max_message_size_mb * 1024 * 1024
    body_bytes = len((text or "").encode()) + len((html or "").encode())
    total_size = total_att_bytes + body_bytes
    if total_size > size_cap:
        raise ApiError(
            422,
            "message_too_large",
            f"Message is {total_size} bytes, plan allows {size_cap} (max_message_size_mb)",
        )

    # Build final MIME (the bucket stores the exact message the receiver sees)
    msg, _ = mail.build_mime(
        sender_addr, to + cc, cc, subject, text, html,
        [
            {
                "filename": a["filename"],
                "content_type": a.get("content_type") or "application/octet-stream",
                "content_base64": a["content_base64"],
            }
            for a in (attachments or [])
        ],
    )
    raw = msg.as_bytes()
    if len(raw) > size_cap:
        raise ApiError(422, "message_too_large", f"Encoded message exceeds {size_cap} bytes")

    # Persist: metadata row + bucket objects under outbound/ and attachments/
    message = Message(
        account_id=account.id,
        domain_id=domain.id,
        direction="outbound",
        status="queued",
        from_addr=sender_addr,
        to_addrs=to + cc + bcc,
        subject=subject or "",
        size_bytes=len(raw),
        object_key=storage.outbound_key(domain.name, "pending", datetime.now(timezone.utc)),
        idempotency_key=idempotency_key,
    )
    db.add(message)
    db.flush()

    message.object_key = storage.outbound_key(domain.name, message.id)
    storage.put_object(message.object_key, raw, content_type="message/rfc822")

    for item, decoded in zip(attachments or [], att_meta):
        att_id = object_id()
        key = storage.attachment_key(message.id, att_id)
        storage.put_object(
            key,
            decoded["_data"],
            content_type=item.get("content_type") or "application/octet-stream",
        )
        db.add(
            Attachment(
                id=att_id,
                message_id=message.id,
                filename=item.get("filename") or "attachment.bin",
                content_type=item.get("content_type") or "application/octet-stream",
                size_bytes=len(decoded["_data"]),
                object_key=key,
            )
        )

    db.add(MessageEvent(message_id=message.id, event="queued", detail=f"source={source}"))
    db.commit()

    redis_client.lpush(SEND_QUEUE, message.id)
    log.info("queued message %s from %s (%d bytes, source=%s)", message.id, sender_addr, len(raw), source)
    return message, False


# Retry schedule for soft failures: 5 min, 30 min, 2 h, then every 4 h up to 3 days
RETRY_SCHEDULE = [300, 1800, 7200] + [14400] * 15


def next_retry_delay(retry_count: int) -> int | None:
    if retry_count >= len(RETRY_SCHEDULE):
        return None
    return RETRY_SCHEDULE[retry_count]
