"""Pydantic request/response schemas for the /v1 API."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class AttachmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    filename: str
    content_type: str
    size_bytes: int


# --- Plans -----------------------------------------------------------------

class PlanCreate(BaseModel):
    name: str
    max_domains: int = 1
    max_mailboxes: int = 5
    max_aliases: int = 20
    mailbox_quota_mb: int = 1024
    total_storage_gb: int = 5
    max_sends_per_day: int = 500
    max_sends_per_minute: int = 20
    max_recipients_per_message: int = 20
    max_message_size_mb: int = 15
    max_api_keys: int = 2
    max_webhooks: int = 1
    retention_days: int = 30
    features: list[str] = Field(default_factory=list)  # imap, catch_all, smtp_submission


class PlanUpdate(BaseModel):
    max_domains: int | None = None
    max_mailboxes: int | None = None
    max_aliases: int | None = None
    mailbox_quota_mb: int | None = None
    total_storage_gb: int | None = None
    max_sends_per_day: int | None = None
    max_sends_per_minute: int | None = None
    max_recipients_per_message: int | None = None
    max_message_size_mb: int | None = None
    max_api_keys: int | None = None
    max_webhooks: int | None = None
    retention_days: int | None = None
    features: list[str] | None = None


class PlanOut(PlanCreate):
    model_config = ConfigDict(from_attributes=True)

    id: str
    created_at: datetime
    account_count: int | None = None


# --- Accounts ----------------------------------------------------------------

class AccountCreate(BaseModel):
    name: str
    plan_id: str


class AccountPlanSet(BaseModel):
    plan_id: str


class AccountOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    plan_id: str
    status: str
    created_at: datetime


class AccountCreated(AccountOut):
    api_key: str  # the first account key, shown once


class LimitUsage(BaseModel):
    used: int | float
    limit: int | float
    unit: str = "count"


class UsageOut(BaseModel):
    plan: PlanOut
    usage: dict[str, LimitUsage]


# --- Domains -------------------------------------------------------------------

class DomainCreate(BaseModel):
    name: str

    @field_validator("name")
    @classmethod
    def lowercase(cls, v: str) -> str:
        v = v.strip().lower().rstrip(".")
        if not v or "/" in v or " " in v or "." not in v:
            raise ValueError("must be a valid domain name like example.com")
        return v


class DomainRecordOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    purpose: str
    type: str
    name: str
    value: str
    required: bool
    status: str
    detail: str = ""

    # map DB column rtype -> "type"
    @classmethod
    def from_record(cls, r):
        return cls(
            purpose=r.purpose,
            type=r.rtype,
            name=r.rname,
            value=r.value,
            required=r.required,
            status=r.status,
            detail=r.detail,
        )


class DomainOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    status: str
    dkim_selector: str
    last_verified_at: datetime | None = None
    created_at: datetime


class DomainDetail(DomainOut):
    records: list[DomainRecordOut] = []


# --- Mailboxes / aliases ----------------------------------------------------------

class MailboxCreate(BaseModel):
    type: Literal["mailbox", "alias", "catch_all"] = "mailbox"
    local_part: str = Field(min_length=1, max_length=64)
    password: str | None = None          # for mailbox type; generated when omitted
    quota_mb: int | None = None          # per-mailbox override of plan.mailbox_quota_mb
    destination: list[EmailStr] | None = None  # required for alias


class MailboxOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    address: str
    type: str
    quota_mb: int | None = None
    destination: list | None = None
    active: bool
    created_at: datetime


class MailboxCreated(MailboxOut):
    password: str | None = None  # shown once when auto-generated


class SmtpCredentialCreate(BaseModel):
    local_part: str | None = None  # defaults to a random handle


class SmtpCredentialOut(BaseModel):
    id: str
    username: str
    password: str  # shown once
    domain_id: str
    created_at: datetime


# --- Messages -----------------------------------------------------------------

class AttachmentIn(BaseModel):
    filename: str
    content_type: str = "application/octet-stream"
    content_base64: str


class MessageSend(BaseModel):
    from_: str = Field(alias="from", examples=["Billing <billing@example.com>"])
    to: list[EmailStr]
    cc: list[EmailStr] | None = None
    bcc: list[EmailStr] | None = None
    subject: str = ""
    text: str | None = None
    html: str | None = None
    attachments: list[AttachmentIn] | None = None
    idempotency_key: str | None = None

    model_config = ConfigDict(populate_by_name=True)


class MessageEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event: str
    detail: str
    created_at: datetime


class MessageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    direction: str
    status: str
    from_addr: str
    to_addrs: list
    subject: str
    size_bytes: int
    spam_score: float
    object_key: str
    created_at: datetime


class MessageDetail(MessageOut):
    domain_id: str | None = None
    mailbox_id: str | None = None
    last_error: str
    retry_count: int
    events: list[MessageEventOut] = []
    attachments: list[AttachmentOut] = []


class RawLink(BaseModel):
    url: str
    expires_in: int


# --- Webhooks -----------------------------------------------------------------

class WebhookCreate(BaseModel):
    url: str
    events: list[str] | None = None  # e.g. ["message.received", "message.bounced"]

    @field_validator("url")
    @classmethod
    def valid_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("webhook url must be http(s)")
        return v


class WebhookOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    url: str
    events: list | None = None
    active: bool
    created_at: datetime


class WebhookCreated(WebhookOut):
    secret: str  # shown once; used to verify the X-Signature header
