"""Metadata schema. All state lives here + Redis counters + the S3 bucket (objects only).

Tables:
  plans, accounts, api_keys, domains, domain_records, mailboxes,
  smtp_credentials, messages, message_events, attachments, webhooks
"""

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    import uuid

    return uuid.uuid4().hex


# --- Plans and accounts ------------------------------------------------------

class Plan(Base):
    __tablename__ = "plans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120), unique=True)

    # "What a plan controls" table from the design doc
    max_domains: Mapped[int] = mapped_column(Integer, default=1)
    max_mailboxes: Mapped[int] = mapped_column(Integer, default=5)
    max_aliases: Mapped[int] = mapped_column(Integer, default=20)
    mailbox_quota_mb: Mapped[int] = mapped_column(Integer, default=1024)
    total_storage_gb: Mapped[int] = mapped_column(Integer, default=5)
    max_sends_per_day: Mapped[int] = mapped_column(Integer, default=500)
    max_sends_per_minute: Mapped[int] = mapped_column(Integer, default=20)
    max_recipients_per_message: Mapped[int] = mapped_column(Integer, default=20)
    max_message_size_mb: Mapped[int] = mapped_column(Integer, default=15)
    max_api_keys: Mapped[int] = mapped_column(Integer, default=2)
    max_webhooks: Mapped[int] = mapped_column(Integer, default=1)
    retention_days: Mapped[int] = mapped_column(Integer, default=30)
    # Feature flags: imap, catch_all, smtp_submission
    features: Mapped[list] = mapped_column(JSON, default=list)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    accounts: Mapped[list["Account"]] = relationship(back_populates="plan")


class Account(Base):
    __tablename__ = "accounts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200))
    plan_id: Mapped[str] = mapped_column(ForeignKey("plans.id"))
    # active | suspended  (suspend stops all sending and receiving)
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    plan: Mapped[Plan] = relationship(back_populates="accounts")
    api_keys: Mapped[list["ApiKey"]] = relationship(back_populates="account")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    account_id: Mapped[str | None] = mapped_column(
        ForeignKey("accounts.id"), nullable=True, index=True
    )
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    label: Mapped[str] = mapped_column(String(120), default="")
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    # Optional: restrict an account key to a single domain
    scope_domain_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    account: Mapped[Account | None] = relationship(back_populates="api_keys")


# --- Domains and DNS ----------------------------------------------------------

class Domain(Base):
    __tablename__ = "domains"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), index=True)
    name: Mapped[str] = mapped_column(String(253), unique=True, index=True)
    # pending -> verified -> active; suspended stops everything
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    dkim_selector: Mapped[str] = mapped_column(String(63), default="s1")
    dkim_private_enc: Mapped[str] = mapped_column(Text)  # Fernet-encrypted PEM
    dkim_public_b64: Mapped[str] = mapped_column(Text)   # PKCS#1 DER, base64 (goes into DNS TXT)
    verification_token: Mapped[str] = mapped_column(String(64))
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    records: Mapped[list["DomainRecord"]] = relationship(
        back_populates="domain", cascade="all, delete-orphan"
    )


class DomainRecord(Base):
    __tablename__ = "domain_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    domain_id: Mapped[str] = mapped_column(ForeignKey("domains.id"), index=True)
    purpose: Mapped[str] = mapped_column(String(60))   # Ownership proof / MX / SPF / DKIM / DMARC / MTA-STS
    rtype: Mapped[str] = mapped_column(String(10))     # TXT / MX
    rname: Mapped[str] = mapped_column(String(253))    # record name to publish
    value: Mapped[str] = mapped_column(Text)           # record value to publish
    required: Mapped[bool] = mapped_column(Boolean, default=True)
    # pending | ok | failing (per-record check results)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    detail: Mapped[str] = mapped_column(Text, default="")
    checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    domain: Mapped[Domain] = relationship(back_populates="records")


# --- Mailboxes, aliases, submission credentials -------------------------------

class Mailbox(Base):
    __tablename__ = "mailboxes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), index=True)
    domain_id: Mapped[str] = mapped_column(ForeignKey("domains.id"), index=True)
    address: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    local_part: Mapped[str] = mapped_column(String(64))
    # mailbox | alias | catch_all
    type: Mapped[str] = mapped_column(String(20), default="mailbox")
    password_hash: Mapped[str | None] = mapped_column(String(200), nullable=True)  # for IMAP/webmail
    quota_mb: Mapped[int | None] = mapped_column(Integer, nullable=True)  # per-mailbox override
    destination: Mapped[list | None] = mapped_column(JSON, nullable=True)  # alias targets
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SmtpCredential(Base):
    __tablename__ = "smtp_credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), index=True)
    domain_id: Mapped[str] = mapped_column(ForeignKey("domains.id"), index=True)
    username: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(200))  # Argon2
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# --- Messages ------------------------------------------------------------------

class Message(Base):
    __tablename__ = "messages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), index=True)
    domain_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    mailbox_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    # outbound | inbound
    direction: Mapped[str] = mapped_column(String(10))
    # outbound: queued -> delivered | deferred | bounced
    # inbound:  received -> purged
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    from_addr: Mapped[str] = mapped_column(String(320))
    to_addrs: Mapped[list] = mapped_column(JSON, default=list)
    subject: Mapped[str] = mapped_column(Text, default="")
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    spam_score: Mapped[float] = mapped_column(Float, default=0.0)
    spam_result: Mapped[str] = mapped_column(String(200), default="")
    object_key: Mapped[str] = mapped_column(String(500), default="")  # raw .eml in the bucket
    idempotency_key: Mapped[str | None] = mapped_column(String(200), nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    next_retry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    __table_args__ = (
        UniqueConstraint("account_id", "idempotency_key", name="uq_account_idem"),
        Index("ix_messages_list", "account_id", "created_at"),
    )


class MessageEvent(Base):
    __tablename__ = "message_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    message_id: Mapped[str] = mapped_column(ForeignKey("messages.id"), index=True)
    event: Mapped[str] = mapped_column(String(40))  # queued/received/delivered/deferred/bounced/...
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Attachment(Base):
    __tablename__ = "attachments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    message_id: Mapped[str] = mapped_column(ForeignKey("messages.id"), index=True)
    filename: Mapped[str] = mapped_column(String(500))
    content_type: Mapped[str] = mapped_column(String(200), default="application/octet-stream")
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    object_key: Mapped[str] = mapped_column(String(500))


# --- Webhooks -------------------------------------------------------------------

class Webhook(Base):
    __tablename__ = "webhooks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), index=True)
    url: Mapped[str] = mapped_column(String(500))
    secret: Mapped[str] = mapped_column(String(120))  # HMAC-SHA256 key; shown once
    # Optional filter; empty/null = all events
    events: Mapped[list | None] = mapped_column(JSON, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
