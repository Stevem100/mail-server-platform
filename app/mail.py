"""MIME building and DKIM signing (dkimpy stands in for Rspamd's signing step)."""

import base64
import logging
from email.message import EmailMessage
from email import policy
from email.utils import formatdate, make_msgid

import dkim

from .config import settings

log = logging.getLogger("mail")

DKIM_HEADERS = [b"from", b"to", b"cc", b"subject", b"date", b"message-id"]


def build_mime(
    from_addr: str,
    to: list[str],
    cc: list[str] | None,
    subject: str,
    text: str | None,
    html: str | None,
    attachments: list[dict] | None,
) -> tuple[EmailMessage, list[dict]]:
    """Build the final message; returns (EmailMessage, attachments_meta).

    attachments: [{"filename", "content_type", "content_base64"}]
    """
    msg = EmailMessage(policy=policy.SMTP)
    msg["From"] = from_addr
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Subject"] = subject or ""
    msg["Date"] = formatdate(localtime=False)
    domain = from_addr.split("@")[-1]
    msg["Message-ID"] = make_msgid(domain=domain)

    body = text if text is not None else "(empty message)"
    msg.set_content(body)
    if html:
        msg.add_alternative(html, subtype="html")

    meta = []
    for att in attachments or []:
        data = base64.b64decode(att["content_base64"])
        maintype, _, subtype = att.get("content_type", "application/octet-stream").partition("/")
        msg.add_attachment(
            data, maintype=maintype or "application", subtype=subtype or "octet-stream",
            filename=att["filename"],
        )
        meta.append(
            {"filename": att["filename"], "content_type": att.get("content_type"), "size": len(data)}
        )
    return msg, meta


def split_address_headers(msg: EmailMessage) -> tuple[str, list[str]]:
    from_addr = str(msg["From"] or "")
    to_addrs = [str(a) for a in (msg["To"] or "").split(",") if str(a).strip()]
    if msg.get("Cc"):
        to_addrs += [str(a) for a in str(msg["Cc"]).split(",") if str(a).strip()]
    return from_addr, [a.strip() for a in to_addrs]


def dkim_sign(raw: bytes, domain: str, selector: str, private_pem: str) -> bytes:
    """Prepend a DKIM-Signature header; returns the final signed message bytes."""
    try:
        sig = dkim.DKIM(raw).sign(
            selector.encode(),
            domain.encode(),
            private_pem.encode(),
            include_headers=DKIM_HEADERS,
        )
        return sig + raw
    except Exception as exc:  # noqa: BLE001
        # Signing failure should not lose mail; deliver unsigned and log loudly.
        log.error("DKIM signing failed for %s: %s", domain, exc)
        return raw


def dkim_verify(raw: bytes) -> bool:
    try:
        return bool(dkim.verify(raw))
    except Exception:  # noqa: BLE001
        return False


# Total per-message cap used by the API (25 MB default receiver limit per the doc)
MAX_API_MESSAGE_BYTES = 25 * 1024 * 1024
