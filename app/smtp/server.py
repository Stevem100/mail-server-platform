"""SMTP edge — the Postfix/Dovecot roles from the design doc, in Python (aiosmtpd).

Three listeners, usually started together (`python -m app.smtp.server`):

  :25   inbound from the world. Accepts a message only when the recipient's domain
        is active and the mailbox/alias exists; everything else is rejected during
        the SMTP conversation, so the server never creates backscatter.
        Quota overage answers 552 "mailbox full"; platform trouble answers 451 so
        the sending MTA keeps the message in its queue and retries.
  :587  authenticated submission. AUTH (PLAIN/LOGIN) checks smtp_credentials
        (Argon2), the MAIL FROM must belong to a domain the credential owns,
        per-minute/day rate limits answer 452, oversize answers 552. Accepted
        mail is stored in the bucket and queued exactly like an API send.
  :2424 LMTP inbound worker. Stores the raw .eml under inbound/, parses and
        stores attachments, inserts the messages row, queues message.received.

DKIM verification of inbound mail runs in the worker (Rspamd equivalent hook);
a spam_score/spam_result is recorded on the message row.
"""

import asyncio
import logging
import ssl
from datetime import datetime, timezone

import aiosmtplib
from aiosmtpd.controller import Controller
from aiosmtpd.lmtp import LMTP
from aiosmtpd.smtp import AuthResult, Envelope, LoginPassword, Session, SMTP

from .. import webhooks
from ..config import settings
from ..db import SessionLocal, init_db
from ..errors import SmtpReject
from ..limits import check_rate
from ..models import Account, Attachment, Domain, Message, MessageEvent, SmtpCredential, utcnow
from ..security import verify_password
from ..services import inbound as inbound_svc
from ..services.outbound import SEND_QUEUE, parse_from, resolve_sender_domain

log = logging.getLogger("smtp")


# --- Port 25: inbound from the world ------------------------------------------------


def _check_rcpt_sync(address: str) -> tuple[int, str] | None:
    db = SessionLocal()
    try:
        inbound_svc.accept_rcpt(db, address)
        return None
    except SmtpReject as rej:
        return rej.code, rej.message
    finally:
        db.close()


class InboundHandler:
    """Postfix role: recipient checks in the conversation, then relay to the worker."""

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        result = await asyncio.to_thread(_check_rcpt_sync, str(address))
        if result is None:
            envelope.rcpt_tos.append(str(address))
            return "250 OK"
        code, message = result
        return f"{code} {message}"

    async def handle_DATA(self, server, session, envelope) -> str:
        def _relay():
            # Internal hop to the inbound worker; smtplib.LMTP speaks LHLO/per-recipient DATA
            import smtplib

            with smtplib.LMTP("127.0.0.1", settings.lmtp_port, timeout=30) as client:
                client.sendmail(envelope.mail_from, list(envelope.rcpt_tos), envelope.content)

        try:
            await asyncio.to_thread(_relay)
            return "250 Message accepted for delivery"
        except Exception as exc:  # noqa: BLE001
            # Worker/bucket down: temporary failure, the sender's MTA will retry.
            log.error("LMTP relay failed: %s", exc)
            return "451 4.3.0 Temporary local failure, try again later"


# --- Port 2424: LMTP inbound worker --------------------------------------------------


class InboundWorkerHandler:
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        envelope.rcpt_tos.append(str(address))
        return "250 OK"

    async def handle_DATA(self, server, session, envelope) -> str:
        try:
            await asyncio.to_thread(
                inbound_svc.store_inbound,
                get_redis(),
                envelope.content,
                envelope.mail_from,
                list(envelope.rcpt_tos),
            )
            return "250 OK"
        except Exception as exc:  # noqa: BLE001
            log.error("inbound storage failed: %s", exc)
            return "451 4.3.0 Storage temporarily unavailable"


class LMTPController(Controller):
    def factory(self):
        return LMTP(self.handler)


# --- Port 587: authenticated submission ----------------------------------------------


def _authenticate(server, session, envelope, mechanism, auth_data) -> AuthResult:
    """Check submission credentials against the database (Argon2), honouring the
    plan's smtp_submission feature flag."""
    if mechanism not in ("PLAIN", "LOGIN") or not isinstance(auth_data, LoginPassword):
        return AuthResult(success=False, message="535 5.7.8 Authentication mechanism not supported")

    login = auth_data.login or b""
    password = auth_data.password or b""
    username = login.decode(errors="replace").strip().lower()

    db = SessionLocal()
    try:
        cred = (
            db.query(SmtpCredential)
            .filter(SmtpCredential.username == username, SmtpCredential.active.is_(True))
            .first()
        )
        if cred is None or not verify_password(cred.password_hash, password.decode(errors="replace")):
            return AuthResult(success=False, message="535 5.7.8 Authentication credentials invalid")
        account = db.get(Account, cred.account_id)
        if account is None or account.status == "suspended":
            return AuthResult(success=False, message="535 5.7.8 Account suspended")
        if "smtp_submission" not in (account.plan.features or []):
            return AuthResult(success=False, message="535 5.7.8 smtp_submission not in plan")

        cred.last_used_at = utcnow()
        db.commit()
        return AuthResult(
            success=True,
            auth_data={
                "credential_id": cred.id,
                "account_id": cred.account_id,
                "domain_id": cred.domain_id,
                "username": username,
            },
        )
    finally:
        db.close()


class SubmissionHandler:
    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        if not getattr(session, "authenticated", False):
            return "530 5.7.0 Authentication required"
        cred = getattr(session, "auth_data", {}) or {}

        db = SessionLocal()
        try:
            sender = str(address).strip().lower()
            cred_domain = db.get(Domain, cred.get("domain_id")) if cred.get("domain_id") else None
            # The MAIL FROM address must belong to a domain the credential owns.
            if cred_domain is None or sender.rpartition("@")[-1] != cred_domain.name:
                return "553 5.7.1 Sender address not owned by this credential"

            account = db.get(Account, cred.get("account_id"))
            if account is None or account.status == "suspended":
                return "553 5.7.1 Account not available for sending"
            if cred_domain.status != "active":
                return "553 5.7.1 Sender domain is not active"

            # Per-account limits, stored in Redis -> 452 over SMTP
            try:
                check_rate(get_redis(), account)
            except Exception:  # noqa: BLE001
                return "452 4.7.1 Sending rate exceeded, slow down"

            session.sender_domain_id = cred_domain.id
            envelope.mail_from = sender
            return "250 OK"
        finally:
            db.close()

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if not getattr(session, "authenticated", False):
            return "530 5.7.0 Authentication required"
        envelope.rcpt_tos.append(str(address))
        return "250 OK"

    async def handle_DATA(self, server, session, envelope) -> str:
        if not getattr(session, "authenticated", False):
            return "530 5.7.0 Authentication required"
        cred = getattr(session, "auth_data", {}) or {}
        try:
            message_id = await asyncio.to_thread(
                _store_submission_sync,
                envelope.content,
                list(envelope.rcpt_tos),
                cred.get("account_id"),
                getattr(session, "sender_domain_id", None),
            )
            return f"250 2.0.0 Queued as {message_id}"
        except SmtpReject as rej:
            return f"{rej.code} {rej.message}"
        except Exception as exc:  # noqa: BLE001
            log.error("submission store failed: %s", exc)
            return "451 4.3.0 Temporary local failure, try again later"


def get_redis():
    import redis

    return redis.Redis.from_url(settings.redis_url, decode_responses=True)


def _store_submission_sync(raw: bytes, rcpt_tos: list[str], account_id: str | None, domain_id: str | None) -> str:
    """Submission path: copy to the bucket, insert the row, queue the send."""
    import email as email_lib

    from .. import storage
    from ..security import object_id

    if account_id is None:
        raise SmtpReject(530, "5.7.0 Authentication required")

    db = SessionLocal()
    try:
        account = db.get(Account, account_id)
        if account is None:
            raise SmtpReject(451, "4.3.0 Unknown account")

        plan = account.plan
        if len(raw) > plan.max_message_size_mb * 1024 * 1024:
            raise SmtpReject(552, "5.3.4 Message too big for this plan")
        if len(rcpt_tos) > plan.max_recipients_per_message:
            raise SmtpReject(552, "5.5.3 Too many recipients")

        parsed = email_lib.message_from_bytes(raw)
        from_addr = parsed.get("From", "")
        _, sender_addr = parse_from(from_addr)
        try:
            domain = resolve_sender_domain(db, account, sender_addr)
        except Exception as exc:  # noqa: BLE001
            raise SmtpReject(553, "5.7.1 Sender domain is not active or not owned by you") from exc

        msg_id = object_id()
        key = storage.outbound_key(domain.name, msg_id, datetime.now(timezone.utc))

        message = Message(
            id=msg_id,
            account_id=account.id,
            domain_id=domain.id,
            direction="outbound",
            status="queued",
            from_addr=sender_addr,
            to_addrs=[r.strip().lower() for r in rcpt_tos],
            subject=parsed.get("Subject", ""),
            size_bytes=len(raw),
            object_key=key,
        )
        db.add(message)
        db.flush()

        storage.put_object(key, raw, content_type="message/rfc822")

        for part in parsed.walk():
            if part.get_content_maintype() == "multipart" or part.get("Content-Disposition") is None:
                continue
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

        db.add(MessageEvent(message_id=message.id, event="queued", detail="source=submission"))
        db.commit()
        get_redis().lpush(SEND_QUEUE, message.id)
        return message.id
    finally:
        db.close()


def _tls_context() -> ssl.SSLContext | None:
    cert = getattr(settings, "submission_tls_cert", None)
    key = getattr(settings, "submission_tls_key", None)
    if not cert or not key:
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return ctx


# --- Runner ---------------------------------------------------------------------------


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    init_db()
    try:
        from .. import storage

        storage.ensure_bucket()
    except Exception as exc:  # noqa: BLE001
        log.warning("bucket not available yet (%s) — run scripts.storage_init", exc)

    controllers = []

    lmtp_ctl = LMTPController(
        InboundWorkerHandler(), hostname="127.0.0.1", port=settings.lmtp_port, ident="platform-lmtp"
    )
    controllers.append(("lmtp:" + str(settings.lmtp_port), lmtp_ctl))

    controllers.append(
        (
            "inbound:" + str(settings.inbound_port),
            Controller(
                InboundHandler(), hostname="0.0.0.0", port=settings.inbound_port, ident="platform-inbound"
            ),
        )
    )

    tls_ctx = _tls_context()
    controllers.append(
        (
            "submission:" + str(settings.submission_port),
            Controller(
                SubmissionHandler(),
                hostname="0.0.0.0",
                port=settings.submission_port,
                ident="platform-submission",
                authenticator=_authenticate,
                auth_required=True,
                auth_require_tls=tls_ctx is not None,  # require STARTTLS once certs are wired
                tls_context=tls_ctx,
                decode_data=False,
            ),
        )
    )

    for name, ctl in controllers:
        ctl.start()
        log.info("%s listening", name)

    log.info("SMTP edge running — Ctrl+C to stop")
    try:
        asyncio.run(asyncio.Event().wait())  # sleep until interrupted
    except KeyboardInterrupt:
        pass
    finally:
        for _, ctl in controllers:
            ctl.stop()


if __name__ == "__main__":
    main()
