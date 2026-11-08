"""Object storage via the S3 API (MinIO by default; AWS S3 / R2 / B2 by changing env vars).

One private bucket (mail-data) holds every message body and attachment; the database
keeps only metadata and the object key. Prefix layout from the design doc:

  inbound/{domain}/{yyyy}/{mm}/{msg_id}.eml     raw received message
  outbound/{domain}/{yyyy}/{mm}/{msg_id}.eml    final signed message as sent
  attachments/{msg_id}/{attachment_id}          one attachment, original bytes
  dkim-backup/{domain}.enc                      encrypted copy of the DKIM private key

Clients never get public access; they receive pre-signed GET URLs valid for 5 minutes.
"""

import logging
from datetime import datetime

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

from .config import settings

log = logging.getLogger("storage")


def client():
    return boto3.client(
        "s3",
        endpoint_url=settings.s3_endpoint or None,
        aws_access_key_id=settings.s3_key,
        aws_secret_access_key=settings.s3_secret,
        region_name=settings.s3_region,
        # Short timeouts so a not-yet-up MinIO never blocks startup or requests
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            connect_timeout=3,
            read_timeout=10,
            retries={"total_max_attempts": 2, "mode": "standard"},
        ),
    )


def ensure_bucket() -> None:
    s3 = client()
    try:
        s3.head_bucket(Bucket=settings.s3_bucket)
    except ClientError:
        params = {"Bucket": settings.s3_bucket}
        if settings.s3_region and settings.s3_region != "us-east-1":
            params["CreateBucketConfiguration"] = {"LocationConstraint": settings.s3_region}
        s3.create_bucket(**params)
        log.info("created bucket %s", settings.s3_bucket)


# --- Key layout ----------------------------------------------------------------

def inbound_key(domain: str, msg_id: str, when: datetime | None = None) -> str:
    when = when or datetime.utcnow()
    return f"inbound/{domain}/{when:%Y}/{when:%m}/{msg_id}.eml"


def outbound_key(domain: str, msg_id: str, when: datetime | None = None) -> str:
    when = when or datetime.utcnow()
    return f"outbound/{domain}/{when:%Y}/{when:%m}/{msg_id}.eml"


def attachment_key(msg_id: str, attachment_id: str) -> str:
    return f"attachments/{msg_id}/{attachment_id}"


def dkim_backup_key(domain: str) -> str:
    return f"dkim-backup/{domain}.enc"


# --- Operations -----------------------------------------------------------------

def put_object(key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
    client().put_object(Bucket=settings.s3_bucket, Key=key, Body=data, ContentType=content_type)


def get_object(key: str) -> bytes:
    resp = client().get_object(Bucket=settings.s3_bucket, Key=key)
    return resp["Body"].read()


def delete_object(key: str) -> None:
    client().delete_object(Bucket=settings.s3_bucket, Key=key)


def presign_get(key: str, expires: int | None = None) -> str:
    return client().generate_presigned_url(
        "get_object",
        Params={"Bucket": settings.s3_bucket, "Key": key},
        ExpiresIn=expires or settings.presign_expires_s,
    )
