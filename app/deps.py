"""API key authentication.

Authorization: Bearer <api key>. Keys are stored hashed (SHA-256) and are either
admin keys (mk_, platform operator) or account keys (ak_); an account key can also
be scoped to a single domain.
"""

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from .db import get_db
from .errors import ApiError
from .models import Account, ApiKey
from .security import hash_api_key


def get_redis():
    import redis

    from .config import settings

    return redis.Redis.from_url(settings.redis_url, decode_responses=True)


def load_key(request: Request, db: Session = Depends(get_db)) -> ApiKey:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise ApiError(401, "missing_api_key", "Send Authorization: Bearer <api key>")
    token = auth.removeprefix("Bearer ").strip()
    key = db.query(ApiKey).filter(ApiKey.key_hash == hash_api_key(token)).first()
    if key is None or key.revoked_at is not None:
        raise ApiError(401, "invalid_api_key", "API key is invalid or revoked")
    return key


def require_admin(key: ApiKey = Depends(load_key)) -> ApiKey:
    if not key.is_admin:
        raise ApiError(403, "admin_key_required", "This endpoint requires an admin key")
    return key


def require_account_key(key: ApiKey = Depends(load_key)) -> ApiKey:
    if key.is_admin or key.account_id is None:
        raise ApiError(403, "account_key_required", "This endpoint requires an account key")
    return key


def current_account(
    key: ApiKey = Depends(require_account_key), db: Session = Depends(get_db)
) -> Account:
    account = db.get(Account, key.account_id)
    if account is None:
        raise ApiError(404, "account_not_found", "Account for this key no longer exists")
    return account


def domain_for_key(
    domain_id: str, key: ApiKey, db: Session
):
    """Load a domain the key may touch: same account, and inside the key's scope."""
    from .models import Domain

    domain = db.get(Domain, domain_id)
    if domain is None or domain.account_id != key.account_id:
        raise ApiError(404, "domain_not_found", "No such domain in this account")
    if key.scope_domain_id and key.scope_domain_id != domain.id:
        raise ApiError(403, "key_scoped_to_domain", "This key is scoped to a single domain")
    return domain
