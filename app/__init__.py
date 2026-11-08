"""Mail Server Platform — Python implementation of the Mail Server Platform Design.

Components (mirroring the design document):
- FastAPI REST API under /v1 (plans, accounts, domains, mailboxes, messages, webhooks)
- aiosmtpd inbound server on :25, authenticated submission on :587, LMTP worker on :2424
- Send worker with DKIM signing, retry schedule and delivery-event tracking
- Webhook dispatcher (HMAC-SHA256 X-Signature)
- Scheduler: hourly domain re-checks + retention sweeps
- Metadata in PostgreSQL, raw mail in MinIO (S3 API), counters/queues in Redis
"""

__version__ = "1.0.0"
