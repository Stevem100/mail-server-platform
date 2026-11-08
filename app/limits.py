"""Plan limits: where they are enforced (the 'Where limits are enforced' table).

- Add domain/mailbox/alias/API key/webhook -> count vs max_*   -> 403 plan_limit_exceeded
- Send by API or SMTP                      -> Redis counters   -> 429 (SMTP translates to 452)
- Message size / recipient count           -> 422 (SMTP: 552)
- IMAP / catch-all / SMTP submission       -> features flag    -> 403 feature_not_in_plan
- Retention                                -> scheduler deletes objects past retention_days

Smaller-plan note: moving an account to a smaller plan deletes nothing; new additions
are simply blocked until usage fits, because every check runs against live counts.
"""

import time

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .errors import ApiError, feature_not_in_plan, plan_limit_exceeded, rate_limited
from .models import Account, ApiKey, Domain, Mailbox, Message, Plan, Webhook

RECENT_STATUSES = ("queued", "sending", "delivered", "deferred", "received", "bounced", "failed")


def ensure_account_active(account: Account, *, writing: bool = True) -> None:
    if writing and account.status == "suspended":
        raise ApiError(403, "account_suspended", "This account is suspended")


def ensure_feature(account: Account, feature: str) -> None:
    if feature not in (account.plan.features or []):
        raise feature_not_in_plan(feature)


def _count(db: Session, stmt) -> int:
    return int(db.scalar(stmt) or 0)


def ensure_within(db: Session, account: Account, kind: str) -> None:
    """kind: domains | mailboxes | aliases | api_keys | webhooks -> 403 when over."""
    plan: Plan = account.plan
    limits = {
        "domains": (plan.max_domains, lambda: _count(db, select(func.count()).select_from(Domain).where(Domain.account_id == account.id))),
        "mailboxes": (plan.max_mailboxes, lambda: _count(db, select(func.count()).select_from(Mailbox).where(Mailbox.account_id == account.id, Mailbox.type == "mailbox"))),
        "aliases": (plan.max_aliases, lambda: _count(db, select(func.count()).select_from(Mailbox).where(Mailbox.account_id == account.id, Mailbox.type.in_(["alias", "catch_all"])))),
        "api_keys": (plan.max_api_keys, lambda: _count(db, select(func.count()).select_from(ApiKey).where(ApiKey.account_id == account.id, ApiKey.revoked_at.is_(None)))),
        "webhooks": (plan.max_webhooks, lambda: _count(db, select(func.count()).select_from(Webhook).where(Webhook.account_id == account.id))),
    }
    if kind not in limits:
        raise ValueError(f"unknown limit kind {kind}")
    limit, counter = limits[kind]
    used = counter()
    limit_name = {
        "domains": "max_domains",
        "mailboxes": "max_mailboxes",
        "aliases": "max_aliases",
        "api_keys": "max_api_keys",
        "webhooks": "max_webhooks",
    }[kind]
    if used >= limit:
        raise plan_limit_exceeded(limit_name)


# --- Redis rate counters ---------------------------------------------------------

def _redis():
    import redis

    from .config import settings

    return redis.Redis.from_url(settings.redis_url, decode_responses=True)


def check_rate(redis_client, account: Account) -> None:
    """Per-minute and per-day counters in Redis -> 429 when over."""
    plan: Plan = account.plan
    now = int(time.time())
    minute_key = f"rl:min:{account.id}:{now // 60}"
    day_key = f"rl:day:{account.id}:{now // 86400}"

    minute_count = redis_client.incr(minute_key)
    if minute_count == 1:
        redis_client.expire(minute_key, 70)
    day_count = redis_client.incr(day_key)
    if day_count == 1:
        redis_client.expire(day_key, 90000)

    if minute_count > plan.max_sends_per_minute:
        raise rate_limited("minute")
    if day_count > plan.max_sends_per_day:
        raise rate_limited("day")


def current_rates(redis_client, account: Account) -> tuple[int, int]:
    now = int(time.time())
    minute = int(redis_client.get(f"rl:min:{account.id}:{now // 60}") or 0)
    day = int(redis_client.get(f"rl:day:{account.id}:{now // 86400}") or 0)
    return minute, day


# --- Storage usage ----------------------------------------------------------------

def storage_used_bytes(db: Session, account_id: str) -> int:
    return int(
        db.scalar(
            select(func.coalesce(func.sum(Message.size_bytes), 0)).where(
                Message.account_id == account_id, Message.status != "purged"
            )
        )
        or 0
    )


def mailbox_used_bytes(db: Session, mailbox_id: str) -> int:
    return int(
        db.scalar(
            select(func.coalesce(func.sum(Message.size_bytes), 0)).where(
                Message.mailbox_id == mailbox_id, Message.status != "purged"
            )
        )
        or 0
    )


def usage_report(db: Session, redis_client, account: Account) -> dict:
    """Live usage against every limit (GET /v1/account, GET /v1/accounts/{id}/usage)."""
    plan: Plan = account.plan
    minute, day = current_rates(redis_client, account)

    def lu(used, limit, unit="count"):
        return {"used": used, "limit": limit, "unit": unit}

    return {
        "domains": lu(_count(db, select(func.count()).select_from(Domain).where(Domain.account_id == account.id)), plan.max_domains),
        "mailboxes": lu(_count(db, select(func.count()).select_from(Mailbox).where(Mailbox.account_id == account.id, Mailbox.type == "mailbox")), plan.max_mailboxes),
        "aliases": lu(_count(db, select(func.count()).select_from(Mailbox).where(Mailbox.account_id == account.id, Mailbox.type.in_(["alias", "catch_all"]))), plan.max_aliases),
        "api_keys": lu(_count(db, select(func.count()).select_from(ApiKey).where(ApiKey.account_id == account.id, ApiKey.revoked_at.is_(None))), plan.max_api_keys),
        "webhooks": lu(_count(db, select(func.count()).select_from(Webhook).where(Webhook.account_id == account.id)), plan.max_webhooks),
        "storage": lu(storage_used_bytes(db, account.id), plan.total_storage_gb * 1024**3, unit="bytes"),
        "sends_today": lu(day, plan.max_sends_per_day),
        "sends_this_minute": lu(minute, plan.max_sends_per_minute),
    }
