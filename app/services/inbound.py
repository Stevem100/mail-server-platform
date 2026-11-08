"""Inbound path: recipient validation (no backscatter) + LMTP storage worker.

Port 25 handler (the Postfix role):
  1. RCPT TO: domain must be active + account active, else 550 during the SMTP
     conversation, so the server never creates backscatter.
  2. Mailbox/alias/catch-all must exist, else 550.
  3. Mailbox quota, then account total storage, else 552 "mailbox full".
LMTP worker on :2424 (the inbound worker):
  4. Write the raw .eml to inbound/, parse headers/body, store each attachment
     as its own object.
  5. Insert the messages row (sender, recipients, subject, size, spam score, keys).
  6. Queue a message.received webhook with metadata + a signed link to the raw message.
If the worker or bucket is down the port-25 handler returns 451 and the sending
side retries (aiosmtpd has no spool, so the remote MTA's retry schedule covers us).
"""

import logging
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser

from sqlalchemy.orm import Session

from .. import mail, storage
from ..config import settings
from ..db import SessionLocal
from ..limits import mailbox_used_bytes, storage_used_bytes
from ..models import Account, Attachment, Domain, Mailbox, Message, MessageEvent
from ..security import object_id

log = logging.getLogger("inbound")


def find_mailbox(db: Session, domain: Domain, local_part: str) -> Mailbox | None:
    mb = (
        db.query(Mailbox)
        .filter(Mailbox.domain_id == domain.id, Mailbox.local_part == local_part, Mailbox.active.is_(True))
        .first()
    )
    if mb:
        return mb
    # aliases may use arbitrary local parts is NOT supported; catch-all is:
    return (
        db.query(Mailbox)
        .filter(Mailbox.domain_id == domain.id, Mailbox.type == "catch_all", Mailbox.active.is_(True))
        .first()
    )


def accept_rcpt(db: Session, address: str) -> tuple[Domain, Mailbox]:
    """Validate one RCPT TO during the SMTP conversation. Raises SmtpReject."""
    from ..errors import SmtpReject

    if "@" not in address:
        raise SmtpReject(501, "Malformed recipient address")
    local, _, dom = address.strip().lower().rpartition("@")
    if not local or not dom:
        raise SmtpReject(501, "Malformed recipient address")

    domain = db.query(Domain).filter(Domain.name == dom).first()
    if domain is None:
        raise SmtpReject(550, f"<{address}>: Recipient domain not hosted here")
    account = db.get(Account, domain.account_id)
    if account is None or account.status == "suspended" or domain.status != "active":
        raise SmtpReject(550, f"<{address}>: Domain not accepting mail")

    mb = find_mailbox(db, domain, local)
    if mb is None:
        raise SmtpReject(550, f"<{address}>: No such mailbox")

    # Quota: per-mailbox first, then the account's total storage
    plan = account.plan
    quota_mb = mb.quota_mb or plan.mailbox_quota_mb
    if mailbox_used_bytes(db, mb.id) >= quota_mb * 1024 * 1024:
        raise SmtpReject(552, "mailbox full")
    if storage_used_bytes(db, account.id) >= plan.total_storage_gb * 1024**3:
        raise SmtpReject(552, "mailbox full")

    return domain, mb


def match_mailbox(db: Session, domain: Domain, address: str) -> Mailbox | None:
    local, _, dom = address.strip().lower().rpartition("@")
    return (
        db.query(Mailbox)
        .filter(Mailbox.domain_id == domain.id, Mailbox.local_part == local, Mailbox.active.is_(True))
        .first()
        or (
            db.query(Mailbox)
            .filter(Mailbox.domain_id == domain.id, Mailbox.type == "catch_all", Mailbox.active.is_(True))
            .first()
        )
    )


def store_inbound(redis_client, raw: bytes, mail_from: str, rcpt_tos: list[str]) -> list[str]:
    """LMTP worker body: store .eml + attachments, insert rows, queue webhooks.

    Manages its own DB session (it runs inside the inbound worker process)."""
    parsed = BytesParser(policy=policy.default).parsebytes(raw)
    subject = str(parsed.get("Subject") or "")
    size = len(raw)
    dkim_ok = mail.dkim_verify(raw)
    spam_note = f"dkim={'pass' if dkim_ok else 'fail'}; rspamd=not-integrated"

    message_ids = []
    db = SessionLocal()
    try:
        for rcpt in rcpt_tos:
            local, _, dom = rcpt.strip().lower().rpartition("@")
            domain = db.query(Domain).filter(Domain.name == dom).first()
            if domain is None:
                continue
            mb = match_mailbox(db, domain, rcpt)
            when = datetime.now(timezone.utc)
            msg_id = object_id()
            key = storage.inbound_key(dom, msg_id, when)

            message = Message(
                id=msg_id,
                account_id=domain.account_id,
                domain_id=domain.id,
                mailbox_id=mb.id if mb else None,
                direction="inbound",
                status="received",
                from_addr=mail_from,
                to_addrs=[r.strip().lower() for r in rcpt_tos],
                subject=subject,
                size_bytes=size,
                spam_score=0.0,
                spam_result=spam_note,
                object_key=key,
            )
            db.add(message)
            db.flush()

            storage.put_object(key, raw, content_type="message/rfc822")

            for part in parsed.iter_attachments():
                data = part.get_payload(decode=True) or b""
                att_id = object_id()
                att_key = storage.attachment_key(message.id, att_id)
                storage.put_object(att_key, data, content_type=part.get_content_type())
                db.add(
                    Attachment(
                        id=att_id,
                        message_id=message.id,
                        filename=part.get_filename() or "unnamed",
                        content_type=part.get_content_type(),
                        size_bytes=len(data),
                        object_key=att_key,
                    )
                )

            db.add(MessageEvent(message_id=message.id, event="received", detail=f"from {mail_from}"))

            webhook_data = {
                "id": message.id,
                "from": mail_from,
                "to": rcpt,
                "subject": subject,
                "size_bytes": size,
                "spam_score": 0.0,
                "raw_url": storage.presign_get(key),
            }
            try:
                from .. import webhooks

                webhooks.enqueue_for_account(redis_client, domain.account_id, "message.received", webhook_data)
            except Exception as exc:  # noqa: BLE001
                log.warning("could not queue webhook: %s", exc)

            message_ids.append(message.id)

        db.commit()
        log.info("stored inbound message(s): %s", message_ids)
        return message_ids
    finally:
        db.close()
