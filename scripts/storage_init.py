"""Create the mail-data bucket, its lifecycle rule (default 90 days on inbound/ and
outbound/, per the design doc) and print a verification checklist.

    python -m scripts.storage_init

Per-account retention beyond the default is enforced by the scheduler worker
(scheduler.py marks purged rows and deletes objects past the plan's retention_days).
"""

import sys

sys.path.insert(0, ".")

from app.config import settings  # noqa: E402
from app.storage import client, ensure_bucket  # noqa: E402

LIFECYCLE = {
    "Rules": [
        {
            "ID": f"expire-{prefix.rstrip('/')}",
            "Prefix": prefix,
            "Status": "Enabled",
            "Expiration": {"Days": settings.retention_default_days},
        }
        for prefix in ("inbound/", "outbound/")
    ]
}


def main() -> None:
    ensure_bucket()
    s3 = client()
    try:
        s3.put_bucket_lifecycle_configuration(
            Bucket=settings.s3_bucket, LifecycleConfiguration=LIFECYCLE
        )
        print(f"bucket '{settings.s3_bucket}' ready with {settings.retention_default_days}-day "
              "lifecycle rules on inbound/ and outbound/")
    except Exception as exc:  # noqa: BLE001
        print(f"bucket '{settings.s3_bucket}' created, but lifecycle rules were rejected: {exc}")
        print("(some S3 providers manage lifecycle differently; the scheduler worker enforces "
              "retention at the application level regardless)")

    print("\nBefore-first-start checklist (from the design doc):")
    print("  [ ] Host allows outbound port 25 (many cloud providers block it by default)")
    print(f"  [ ] A record: {settings.mail_hostname} -> your server IP ({settings.server_ip} is the placeholder)")
    print("  [ ] Reverse DNS (PTR) at your hosting provider matches the mail hostname")
    print("  [ ] Firewall open for 25, 587, 80, 443 (and 53 if you run pdns)")
    print("  [ ] Back up pg_data, minio_data and the DKIM keys; the other volumes can be rebuilt")


if __name__ == "__main__":
    main()
