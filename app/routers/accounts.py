"""Account endpoints.

Admin key: create accounts (returns the first account key), move plan, suspend,
activate, read usage. Account key: GET /v1/account returns plan, limits, live usage.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import current_account, get_redis, require_admin
from ..errors import ApiError
from ..limits import usage_report
from ..models import Account, ApiKey, Plan
from ..schemas import AccountCreate, AccountOut, AccountPlanSet, PlanOut, UsageOut
from ..security import generate_api_key

router = APIRouter(prefix="/v1", tags=["accounts"])


@router.post("/accounts", status_code=201)
def create_account(
    body: AccountCreate, db: Session = Depends(get_db), _: ApiKey = Depends(require_admin)
):
    plan = db.get(Plan, body.plan_id)
    if plan is None:
        raise ApiError(404, "plan_not_found", "No such plan")
    account = Account(name=body.name, plan_id=plan.id)
    db.add(account)
    db.flush()
    key, key_hash = generate_api_key(is_admin=False)
    db.add(ApiKey(account_id=account.id, key_hash=key_hash, label="first key"))
    db.commit()
    db.refresh(account)
    return {**AccountOut.model_validate(account).model_dump(), "api_key": key}


@router.put("/accounts/{account_id}/plan")
def move_plan(
    account_id: str, body: AccountPlanSet, db: Session = Depends(get_db), _: ApiKey = Depends(require_admin)
):
    account = db.get(Account, account_id)
    if account is None:
        raise ApiError(404, "account_not_found", "No such account")
    plan = db.get(Plan, body.plan_id)
    if plan is None:
        raise ApiError(404, "plan_not_found", "No such plan")
    # Nothing is deleted when the plan shrinks; new additions are blocked until
    # usage fits because every limit is checked against live counts.
    account.plan_id = plan.id
    db.commit()
    return AccountOut.model_validate(account)


@router.post("/accounts/{account_id}/suspend")
def suspend_account(account_id: str, db: Session = Depends(get_db), _: ApiKey = Depends(require_admin)):
    account = db.get(Account, account_id)
    if account is None:
        raise ApiError(404, "account_not_found", "No such account")
    account.status = "suspended"
    db.commit()
    return AccountOut.model_validate(account)


@router.post("/accounts/{account_id}/activate")
def activate_account(account_id: str, db: Session = Depends(get_db), _: ApiKey = Depends(require_admin)):
    """Convenience addition to the design: undo a suspend."""
    account = db.get(Account, account_id)
    if account is None:
        raise ApiError(404, "account_not_found", "No such account")
    account.status = "active"
    db.commit()
    return AccountOut.model_validate(account)


def _usage_payload(db: Session, account: Account) -> dict:
    redis = get_redis()
    return {
        "account": AccountOut.model_validate(account).model_dump(),
        "plan": PlanOut.model_validate(account.plan).model_dump(),
        "usage": usage_report(db, redis, account),
    }


@router.get("/account")
def my_account(account: Account = Depends(current_account), db: Session = Depends(get_db)):
    """Current plan, limits and live usage for the key's own account."""
    return _usage_payload(db, account)


@router.get("/accounts/{account_id}/usage")
def account_usage(account_id: str, db: Session = Depends(get_db), _: ApiKey = Depends(require_admin)):
    account = db.get(Account, account_id)
    if account is None:
        raise ApiError(404, "account_not_found", "No such account")
    return _usage_payload(db, account)


@router.get("/accounts/{account_id}")
def get_account(account_id: str, db: Session = Depends(get_db), _: ApiKey = Depends(require_admin)):
    account = db.get(Account, account_id)
    if account is None:
        raise ApiError(404, "account_not_found", "No such account")
    return AccountOut.model_validate(account)


@router.get("/accounts")
def list_accounts(db: Session = Depends(get_db), _: ApiKey = Depends(require_admin)):
    return [AccountOut.model_validate(a) for a in db.query(Account).order_by(Account.created_at).all()]
