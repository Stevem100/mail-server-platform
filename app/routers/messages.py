"""Message endpoints: send (202 Accepted), list with filters + cursor pagination,
detail with delivery events, pre-signed raw .eml and attachment links (5 minutes)."""

import base64
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from .. import storage
from ..config import settings
from ..db import get_db
from ..deps import current_account, get_redis, require_account_key
from ..errors import ApiError
from ..models import Account, ApiKey, Attachment, Domain, Message
from ..schemas import MessageDetail, MessageSend, RawLink
from ..services.outbound import create_outgoing_message

router = APIRouter(prefix="/v1/messages", tags=["messages"])


@router.post("", status_code=202)
def send_message(
    body: MessageSend,
    account: Account = Depends(current_account),
    db: Session = Depends(get_db),
):
    """Send a message. Response: 202 Accepted with {"id": ..., "status": "queued"}."""
    message, _replayed = create_outgoing_message(
        db,
        get_redis(),
        account,
        from_value=body.from_,
        to=[str(t) for t in body.to],
        cc=[str(t) for t in (body.cc or [])],
        bcc=[str(t) for t in (body.bcc or [])],
        subject=body.subject,
        text=body.text,
        html=body.html,
        attachments=[a.model_dump() for a in (body.attachments or [])],
        idempotency_key=body.idempotency_key,
        source="api",
    )
    return {"id": message.id, "status": message.status}


def _decode_cursor(cursor: str) -> tuple[datetime, str]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        iso, mid = raw.split("|", 1)
        return datetime.fromisoformat(iso), mid
    except Exception as exc:  # noqa: BLE001
        raise ApiError(422, "invalid_cursor", "cursor is not valid") from exc


def _encode_cursor(created_at: datetime, mid: str) -> str:
    raw = f"{created_at.isoformat()}|{mid}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


@router.get("")
def list_messages(
    domain: str | None = Query(None, description="filter by domain name"),
    status: str | None = Query(None),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
    cursor: str | None = Query(None),
    limit: int = Query(25, ge=1, le=100),
    account: Account = Depends(current_account),
    key: ApiKey = Depends(require_account_key),
    db: Session = Depends(get_db),
):
    """List sent and received messages, filter by domain, status, date."""
    q = db.query(Message).filter(Message.account_id == account.id)
    if domain:
        d = db.query(Domain).filter(Domain.account_id == account.id, Domain.name == domain.lower()).first()
        q = q.filter(Message.domain_id == (d.id if d else "__none__"))
    if status:
        q = q.filter(Message.status == status)
    if since:
        q = q.filter(Message.created_at >= since)
    if until:
        q = q.filter(Message.created_at <= until)
    if cursor:
        t, mid = _decode_cursor(cursor)
        q = q.filter((Message.created_at < t) | ((Message.created_at == t) & (Message.id < mid)))

    rows = q.order_by(Message.created_at.desc(), Message.id.desc()).limit(limit + 1).all()
    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        last = rows[-1]
        next_cursor = _encode_cursor(last.created_at, last.id)
    from ..schemas import MessageOut

    return {"data": [MessageOut.model_validate(m) for m in rows], "next_cursor": next_cursor}


@router.get("/{message_id}")
def get_message(
    message_id: str,
    account: Account = Depends(current_account),
    key: ApiKey = Depends(require_account_key),
    db: Session = Depends(get_db),
):
    """Message metadata, delivery events and attachments."""
    m = _own_message(db, account, key, message_id)
    out = MessageDetail.model_validate(m)
    out.events = sorted(m_events(db, m.id), key=lambda e: e.created_at)
    out.attachments = db.query(Attachment).filter(Attachment.message_id == m.id).all()
    return out


def m_events(db: Session, message_id: str):
    from ..models import MessageEvent

    return db.query(MessageEvent).filter(MessageEvent.message_id == message_id).all()


def _own_message(db: Session, account: Account, key: ApiKey, message_id: str) -> Message:
    m = db.get(Message, message_id)
    if m is None or m.account_id != account.id:
        raise ApiError(404, "message_not_found", "No such message in this account")
    if key.scope_domain_id and m.domain_id and m.domain_id != key.scope_domain_id:
        raise ApiError(403, "key_scoped_to_domain", "This key is scoped to a single domain")
    return m


@router.get("/{message_id}/raw")
def raw_message(
    message_id: str,
    account: Account = Depends(current_account),
    key: ApiKey = Depends(require_account_key),
    db: Session = Depends(get_db),
):
    """Short-lived signed URL (5 minutes) for the original .eml."""
    m = _own_message(db, account, key, message_id)
    if not m.object_key:
        raise ApiError(404, "raw_unavailable", "No stored message body for this row")
    return RawLink(url=storage.presign_get(m.object_key), expires_in=settings.presign_expires_s)


@router.get("/{message_id}/attachments/{attachment_id}")
def attachment_link(
    message_id: str,
    attachment_id: str,
    account: Account = Depends(current_account),
    key: ApiKey = Depends(require_account_key),
    db: Session = Depends(get_db),
):
    """Short-lived signed URL for one attachment."""
    _own_message(db, account, key, message_id)
    att = (
        db.query(Attachment)
        .filter(Attachment.id == attachment_id, Attachment.message_id == message_id)
        .first()
    )
    if att is None:
        raise ApiError(404, "attachment_not_found", "No such attachment")
    return RawLink(url=storage.presign_get(att.object_key), expires_in=settings.presign_expires_s)
