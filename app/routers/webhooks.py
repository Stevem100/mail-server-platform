"""Webhook endpoints: register URLs for signed platform events."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import current_account, require_account_key
from ..errors import ApiError
from ..limits import ensure_account_active, ensure_within
from ..models import Account, ApiKey, Webhook
from ..schemas import WebhookCreate, WebhookCreated, WebhookOut
from ..security import webhook_secret
from ..webhooks import EVENTS

router = APIRouter(prefix="/v1/webhooks", tags=["webhooks"])


@router.post("", status_code=201)
def create_webhook(
    body: WebhookCreate,
    account: Account = Depends(current_account),
    key: ApiKey = Depends(require_account_key),
    db: Session = Depends(get_db),
):
    ensure_account_active(account)
    ensure_within(db, account, "webhooks")
    if body.events:
        unknown = [e for e in body.events if e not in EVENTS]
        if unknown:
            raise ApiError(422, "unknown_event", f"Unknown events: {', '.join(unknown)}", events=EVENTS)
    hook = Webhook(
        account_id=account.id,
        url=str(body.url),
        secret=webhook_secret(),
        events=body.events or None,
    )
    db.add(hook)
    db.commit()
    db.refresh(hook)
    return WebhookCreated(
        **WebhookOut.model_validate(hook).model_dump(), secret=hook.secret
    )


@router.get("")
def list_webhooks(
    account: Account = Depends(current_account),
    key: ApiKey = Depends(require_account_key),
    db: Session = Depends(get_db),
):
    return [WebhookOut.model_validate(h) for h in db.query(Webhook).filter(Webhook.account_id == account.id)]


@router.delete("/{webhook_id}", status_code=204)
def delete_webhook(
    webhook_id: str,
    account: Account = Depends(current_account),
    key: ApiKey = Depends(require_account_key),
    db: Session = Depends(get_db),
):
    hook = (
        db.query(Webhook)
        .filter(Webhook.id == webhook_id, Webhook.account_id == account.id)
        .first()
    )
    if hook is None:
        raise ApiError(404, "webhook_not_found", "No such webhook")
    hook.active = False
    db.commit()
