"""One-time bootstrap: create the example plans from the design doc and the first
admin key. Idempotent — safe to run again (prints existing values where possible).

    python -m scripts.seed

Prints the admin key ONCE — store it in your password manager.
"""

import sys

sys.path.insert(0, ".")

from sqlalchemy import select  # noqa: E402

from app.db import SessionLocal, init_db  # noqa: E402
from app.models import Account, ApiKey, Plan  # noqa: E402
from app.security import generate_api_key  # noqa: E402

STARTER = dict(
    name="starter",
    max_domains=1,
    max_mailboxes=5,
    max_aliases=20,
    mailbox_quota_mb=1024,
    total_storage_gb=5,
    max_sends_per_day=500,
    max_sends_per_minute=20,
    max_recipients_per_message=20,
    max_message_size_mb=15,
    max_api_keys=2,
    max_webhooks=1,
    retention_days=30,
    features=["smtp_submission"],
)

BUSINESS = dict(
    name="business",
    max_domains=10,
    max_mailboxes=100,
    max_aliases=500,
    mailbox_quota_mb=5120,
    total_storage_gb=200,
    max_sends_per_day=20000,
    max_sends_per_minute=200,
    max_recipients_per_message=100,
    max_message_size_mb=25,
    max_api_keys=20,
    max_webhooks=10,
    retention_days=365,
    features=["smtp_submission", "imap", "catch_all"],
)


def create_default_plans(db) -> list[Plan]:
    out = []
    for fields in (STARTER, BUSINESS):
        plan = db.query(Plan).filter(Plan.name == fields["name"]).first()
        if plan is None:
            plan = Plan(**fields)
            db.add(plan)
            db.flush()
        out.append(plan)
    db.commit()
    return out


def create_admin_key(db, label="bootstrap admin key") -> tuple[ApiKey, str]:
    key, key_hash = generate_api_key(is_admin=True)
    row = ApiKey(key_hash=key_hash, is_admin=True, label=label)
    db.add(row)
    db.commit()
    return row, key


def main() -> None:
    init_db()
    db = SessionLocal()
    try:
        plans = create_default_plans(db)
        admin_keys = db.query(ApiKey).filter(ApiKey.is_admin.is_(True), ApiKey.revoked_at.is_(None)).count()
        accounts = db.query(Account).count()

        print("Plans:")
        for p in plans:
            print(f"  - {p.name}: domains={p.max_domains} mailboxes={p.max_mailboxes} "
                  f"sends/day={p.max_sends_per_day} storage={p.total_storage_gb}GB "
                  f"retention={p.retention_days}d features={p.features}")
        print(f"Existing admin keys: {admin_keys}, accounts: {accounts}")

        if accounts == 0 and admin_keys == 0:
            _, key = create_admin_key(db)
            print("\nAdmin key (shown ONCE — store it now):")
            print(f"  {key}")
            print("\nNext: create an account with this key:")
            print('  curl -X POST http://localhost:8080/v1/accounts \\')
            print('    -H "Authorization: Bearer <admin key>" -H "Content-Type: application/json" \\')
            print('    -d \'{"name": "acme", "plan_id": "<plan id from above>"}\'')
        else:
            print("\nAdmin key not regenerated (already exists). Use mk_ key from first run.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
