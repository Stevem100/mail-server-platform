"""Plan endpoints (admin key): create, list, change limits, delete.

Changing a plan applies to all its accounts at once because limits are read live.
Deleting is refused with 409 while any account still uses the plan.
"""

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_admin
from ..errors import ApiError
from ..models import Account, ApiKey, Plan
from ..schemas import PlanCreate, PlanOut, PlanUpdate

router = APIRouter(prefix="/v1/plans", tags=["plans"])


def plan_out(db: Session, plan: Plan) -> PlanOut:
    count = db.scalar(select(func.count()).select_from(Account).where(Account.plan_id == plan.id)) or 0
    out = PlanOut.model_validate(plan)
    out.account_count = int(count)
    return out


@router.post("", status_code=201)
def create_plan(body: PlanCreate, db: Session = Depends(get_db), _: ApiKey = Depends(require_admin)):
    if db.query(Plan).filter(Plan.name == body.name).first():
        raise ApiError(409, "plan_exists", f"Plan {body.name!r} already exists")
    plan = Plan(**body.model_dump())
    db.add(plan)
    db.commit()
    db.refresh(plan)
    return plan_out(db, plan)


@router.get("")
def list_plans(db: Session = Depends(get_db), _: ApiKey = Depends(require_admin)):
    return [plan_out(db, p) for p in db.query(Plan).order_by(Plan.created_at).all()]


@router.patch("/{plan_id}")
def update_plan(
    plan_id: str, body: PlanUpdate, db: Session = Depends(get_db), _: ApiKey = Depends(require_admin)
):
    plan = db.get(Plan, plan_id)
    if plan is None:
        raise ApiError(404, "plan_not_found", "No such plan")
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(plan, field, value)
    db.commit()
    db.refresh(plan)
    return plan_out(db, plan)


@router.delete("/{plan_id}", status_code=204)
def delete_plan(plan_id: str, db: Session = Depends(get_db), _: ApiKey = Depends(require_admin)):
    plan = db.get(Plan, plan_id)
    if plan is None:
        raise ApiError(404, "plan_not_found", "No such plan")
    in_use = db.scalar(select(func.count()).select_from(Account).where(Account.plan_id == plan.id))
    if in_use:
        raise ApiError(409, "plan_in_use", "Plan is used by accounts; move them first")
    db.delete(plan)
    db.commit()
