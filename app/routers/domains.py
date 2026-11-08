"""Domain endpoints: add (DKIM keygen + DNS records), list, detail, verify, delete,
mailboxes/aliases, SMTP submission credentials."""

import logging

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import dns, storage
from ..db import get_db
from ..deps import current_account, domain_for_key, require_account_key
from ..errors import ApiError
from ..limits import ensure_account_active, ensure_feature, ensure_within
from ..models import Account, ApiKey, Domain, DomainRecord, Mailbox, SmtpCredential, utcnow
from ..schemas import (
    DomainCreate,
    DomainDetail,
    DomainOut,
    DomainRecordOut,
    MailboxCreate,
    MailboxCreated,
    MailboxOut,
    SmtpCredentialCreate,
    SmtpCredentialOut,
)
from ..security import (
    encrypt_secret,
    generate_password,
    hash_password,
    verification_token,
)

log = logging.getLogger("domains")
router = APIRouter(prefix="/v1/domains", tags=["domains"])


def detail(db: Session, domain: Domain) -> dict:
    """Domain + per-record check results (built explicitly: ORM columns are rtype/rname)."""
    base = DomainOut.model_validate(domain).model_dump(mode="json")
    base["records"] = [
        DomainRecordOut.from_record(r).model_dump(mode="json")
        for r in sorted(domain.records, key=lambda r: r.purpose)
    ]
    return base


@router.post("", status_code=201)
def add_domain(
    body: DomainCreate,
    account: Account = Depends(current_account),
    key: ApiKey = Depends(require_account_key),
    db: Session = Depends(get_db),
):
    ensure_account_active(account)
    ensure_within(db, account, "domains")

    if db.query(Domain).filter(Domain.name == body.name).first():
        raise ApiError(409, "domain_exists", f"Domain {body.name} already exists")

    # 2048-bit DKIM key pair; private key stored encrypted
    priv_pem, pub_b64 = dns.generate_dkim_keypair()
    token = verification_token()
    domain = Domain(
        account_id=account.id,
        name=body.name,
        dkim_selector=account_dkim_selector(),
        dkim_private_enc=encrypt_secret(priv_pem),
        dkim_public_b64=pub_b64,
        verification_token=token,
    )
    db.add(domain)
    db.flush()

    for rec in dns.build_records(body.name, token, pub_b64, domain.dkim_selector):
        db.add(DomainRecord(domain_id=domain.id, **rec))
    db.commit()
    db.refresh(domain)

    # Managed DNS option: when the zone lives on PowerDNS the platform writes the
    # records itself; otherwise the user publishes them at their DNS host.
    if dns.apply_to_pdns(body.name, domain.records):
        log.info("records written to PowerDNS for %s", body.name)

    return detail(db, domain)


def account_dkim_selector() -> str:
    from ..config import settings

    return settings.dkim_selector


@router.get("")
def list_domains(
    status: str | None = None,
    account: Account = Depends(current_account),
    key: ApiKey = Depends(require_account_key),
    db: Session = Depends(get_db),
):
    q = db.query(Domain).filter(Domain.account_id == account.id)
    if key.scope_domain_id:
        q = q.filter(Domain.id == key.scope_domain_id)
    if status:
        q = q.filter(Domain.status == status)
    return [DomainOut.model_validate(d) for d in q.order_by(Domain.created_at).all()]


@router.get("/{domain_id}")
def get_domain(
    domain_id: str,
    account: Account = Depends(current_account),
    key: ApiKey = Depends(require_account_key),
    db: Session = Depends(get_db),
):
    return detail(db, domain_for_key(domain_id, key, db))


@router.post("/{domain_id}/verify")
def verify_domain(
    domain_id: str,
    account: Account = Depends(current_account),
    key: ApiKey = Depends(require_account_key),
    db: Session = Depends(get_db),
):
    """Re-run live DNS lookups now and update per-record status."""
    domain = domain_for_key(domain_id, key, db)
    new_status, old_status = dns.verify_domain_sync(domain, domain.records)
    if new_status != old_status:
        domain.status = new_status
        db.commit()
        from .. import webhooks

        webhooks.enqueue_for_account(
            get_redis(),
            account.id,
            "domain.status_changed",
            {"domain": domain.name, "from": old_status, "to": new_status},
        )
    else:
        db.commit()
    return detail(db, domain)


def get_redis():
    from ..deps import get_redis as _gr

    return _gr()


@router.delete("/{domain_id}", status_code=204)
def delete_domain(
    domain_id: str,
    account: Account = Depends(current_account),
    key: ApiKey = Depends(require_account_key),
    db: Session = Depends(get_db),
):
    domain = domain_for_key(domain_id, key, db)
    # dkim-backup objects live until the domain is deleted
    try:
        storage.delete_object(storage.dkim_backup_key(domain.name))
    except Exception:  # noqa: BLE001
        log.debug("no dkim backup object for %s", domain.name)
    db.delete(domain)  # records/mailboxes/credentials cascade
    db.commit()


# --- Mailboxes, aliases, catch-all ------------------------------------------------


@router.post("/{domain_id}/mailboxes", status_code=201)
def create_mailbox(
    domain_id: str,
    body: MailboxCreate,
    account: Account = Depends(current_account),
    key: ApiKey = Depends(require_account_key),
    db: Session = Depends(get_db),
):
    ensure_account_active(account)
    domain = domain_for_key(domain_id, key, db)

    kind = body.type
    if kind in ("alias", "catch_all"):
        ensure_within(db, account, "aliases")
    else:
        ensure_within(db, account, "mailboxes")
    if kind == "catch_all":
        ensure_feature(account, "catch_all")
    if kind == "alias" and not body.destination:
        raise ApiError(422, "alias_destination_required", "Aliases need destination addresses")

    address = f"{body.local_part.lower()}@{domain.name}"
    if db.query(Mailbox).filter(Mailbox.address == address).first():
        raise ApiError(409, "mailbox_exists", f"{address} already exists")

    plain_password = None
    if kind == "mailbox":
        plain_password = body.password or generate_password()

    mailbox = Mailbox(
        account_id=account.id,
        domain_id=domain.id,
        address=address,
        local_part=body.local_part.lower(),
        type=kind,
        password_hash=hash_password(plain_password) if plain_password else None,
        quota_mb=body.quota_mb,
        destination=[str(d).lower() for d in body.destination] if body.destination else None,
    )
    db.add(mailbox)
    db.commit()
    db.refresh(mailbox)

    out = MailboxCreated.model_validate(mailbox)
    out.password = plain_password if kind == "mailbox" else None
    return out


@router.get("/{domain_id}/mailboxes")
def list_mailboxes(
    domain_id: str,
    account: Account = Depends(current_account),
    key: ApiKey = Depends(require_account_key),
    db: Session = Depends(get_db),
):
    """Convenience addition to the design (the admin UI needs the list too)."""
    domain = domain_for_key(domain_id, key, db)
    return [
        MailboxOut.model_validate(m)
        for m in db.query(Mailbox).filter(Mailbox.domain_id == domain.id).order_by(Mailbox.address)
    ]


@router.delete("/{domain_id}/mailboxes/{mailbox_id}", status_code=204)
def delete_mailbox(
    domain_id: str,
    mailbox_id: str,
    account: Account = Depends(current_account),
    key: ApiKey = Depends(require_account_key),
    db: Session = Depends(get_db),
):
    domain = domain_for_key(domain_id, key, db)
    mailbox = db.query(Mailbox).filter(Mailbox.id == mailbox_id, Mailbox.domain_id == domain.id).first()
    if mailbox is None:
        raise ApiError(404, "mailbox_not_found", "No such mailbox")
    db.delete(mailbox)
    db.commit()


# --- SMTP submission credentials ----------------------------------------------------


@router.post("/{domain_id}/smtp-credentials", status_code=201)
def create_smtp_credential(
    domain_id: str,
    body: SmtpCredentialCreate,
    account: Account = Depends(current_account),
    key: ApiKey = Depends(require_account_key),
    db: Session = Depends(get_db),
):
    ensure_account_active(account)
    ensure_feature(account, "smtp_submission")
    domain = domain_for_key(domain_id, key, db)

    import secrets

    local = (body.local_part or f"smtp-{secrets.token_hex(4)}").lower()
    username = f"{local}@{domain.name}"
    if db.query(SmtpCredential).filter(SmtpCredential.username == username).first():
        raise ApiError(409, "credential_exists", f"{username} already exists")

    password = generate_password()
    cred = SmtpCredential(
        account_id=account.id,
        domain_id=domain.id,
        username=username,
        password_hash=hash_password(password),
    )
    db.add(cred)
    db.commit()
    db.refresh(cred)
    return SmtpCredentialOut(
        id=cred.id, username=username, password=password, domain_id=domain.id, created_at=cred.created_at
    )
