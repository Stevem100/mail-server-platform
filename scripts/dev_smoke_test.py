"""Offline end-to-end smoke test for the Mail Server Platform.

Runs the whole product loop without PostgreSQL, Redis or MinIO:
  SQLite file DB + fakeredis + in-memory S3 + a local SMTP relay sink
  + a local HTTP webhook sink.

Covered:
  1.  Seed: starter/business plans, admin key
  2.  API: create account (first key returned once), add domain (DKIM + DNS records)
  3.  API: mailbox, SMTP credential, webhook registration
  4.  Send: 422 while domain inactive -> activate -> 202 queued -> idempotency replay
  5.  Limits: 403 plan_limit_exceeded (max_domains), 429 rate_limited, 403 feature_not_in_plan
  6.  Send worker: DKIM-signed delivery through the relay sink, verified with dkim.verify
  7.  Webhook worker: message.delivered delivery + X-Signature HMAC verification
  8.  Read-back: message list/detail/raw/attachment pre-signed links, usage endpoints
  9.  Inbound :25 -> LMTP :2424 -> bucket + message.received webhook; unknown RCPT -> 550
  10. Submission :587: 530 without AUTH, 553 wrong sender domain, AUTH -> queued -> delivered
  11. Suspend: 403 on API send, 550 on inbound RCPT
  12. Retention sweep: objects deleted, message marked purged

Run from the project root:
    python -m scripts.dev_smoke_test
"""

import base64
import hashlib
import hmac
import json
import os
import smtplib
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, HTTPServer

# --- offline environment (must be set before app imports) ------------------------------

if os.path.exists("_smoke.db"):
    os.remove("_smoke.db")

os.environ["DATABASE_URL"] = "sqlite:///./_smoke.db"
os.environ["REDIS_URL"] = "redis://fakeredis/0"
os.environ["INBOUND_PORT"] = "2025"
os.environ["SUBMISSION_PORT"] = "2587"
os.environ["LMTP_PORT"] = "2424"
os.environ["SMTP_RELAY_HOST"] = "127.0.0.1"
os.environ["SMTP_RELAY_PORT"] = "2525"
os.environ["APP_SECRET"] = "smoke-secret"

sys.path.insert(0, ".")

import fakeredis  # noqa: E402
import redis as real_redis  # noqa: E402

fake_server = fakeredis.FakeServer()


def fake_from_url(url, **kwargs):
    kwargs.pop("decode_responses", None)
    return fakeredis.FakeRedis(server=fake_server, decode_responses=True)


real_redis.Redis.from_url = staticmethod(fake_from_url)

from app import storage as storage_mod  # noqa: E402

FAKE_BUCKET: dict[str, bytes] = {}
storage_mod.put_object = lambda key, data, content_type="application/octet-stream": FAKE_BUCKET.__setitem__(key, data)
storage_mod.get_object = lambda key: FAKE_BUCKET[key]
storage_mod.delete_object = lambda key: FAKE_BUCKET.pop(key, None)
storage_mod.presign_get = lambda key, expires=None: f"https://fake.s3.local/{key}"
storage_mod.ensure_bucket = lambda: None

PASS = 0


def check(name: str, condition: bool, extra=""):
    global PASS
    if not condition:
        print(f"FAIL  {name} {extra}")
        raise SystemExit(1)
    PASS += 1
    print(f"ok    {name}")


# --- 1. seed -----------------------------------------------------------------------------

from app.db import SessionLocal, init_db  # noqa: E402
from app.models import Domain, Message  # noqa: E402

init_db()

from scripts.seed import create_admin_key, create_default_plans  # noqa: E402

db = SessionLocal()
plans = create_default_plans(db)
starter = next(p for p in plans if p.name == "starter")
_, admin_key = create_admin_key(db)
db.close()
check("seed: plans + admin key", bool(admin_key.startswith("mk_")))

# --- API client --------------------------------------------------------------------------

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

client = TestClient(app)
H = {"Authorization": f"Bearer {admin_key}"}

r = client.get("/v1/plans", headers=H)
check("GET /v1/plans (admin)", r.status_code == 200 and r.json()[0]["account_count"] == 0)

r = client.get("/v1/plans", headers={"Authorization": "Bearer wrong"})
check("auth: invalid key -> 401", r.status_code == 401)

# --- 2. account + domain ------------------------------------------------------------------

r = client.post("/v1/accounts", headers=H, json={"name": "acme", "plan_id": starter.id})
check("POST /v1/accounts -> 201 + first key", r.status_code == 201 and r.json()["api_key"].startswith("ak_"), r.text)
acct = r.json()
AH = {"Authorization": f"Bearer {acct['api_key']}"}

r = client.post("/v1/domains", headers=AH, json={"name": "example.com"})
check("POST /v1/domains -> 201 with records", r.status_code == 201, r.text)
domain = r.json()
domain_id = domain["id"]
recs = {rec["purpose"]: rec for rec in domain["records"]}
check(
    "DNS records table (MX, SPF, DKIM, DMARC, mailcheck)",
    recs["mx"]["value"] == "10 mail.yourplatform.com."
    and recs["spf"]["value"] == "v=spf1 ip4:203.0.113.10 -all"
    and recs["dkim"]["value"].startswith("v=DKIM1; k=rsa; p=")
    and recs["dmarc"]["value"].startswith("v=DMARC1; p=none; rua=mailto:dmarc@example.com")
    and recs["ownership"]["name"] == "_mailcheck.example.com",
)
check("DKIM selector s1 + domain starts pending", domain["dkim_selector"] == "s1" and domain["status"] == "pending")

# --- 3. mailbox, credential, webhook ---------------------------------------------------------

r = client.post(f"/v1/domains/{domain_id}/mailboxes", headers=AH, json={"type": "mailbox", "local_part": "billing"})
check("create mailbox billing@example.com", r.status_code == 201 and r.json()["address"] == "billing@example.com", r.text)
mailbox_password = r.json()["password"]
check("mailbox password generated (shown once)", bool(mailbox_password))

r = client.post(f"/v1/domains/{domain_id}/smtp-credentials", headers=AH, json={})
check("create SMTP credential (feature smtp_submission)", r.status_code == 201, r.text)
cred = r.json()

r = client.post(f"/v1/domains/{domain_id}/mailboxes", headers=AH,
                json={"type": "alias", "local_part": "finance", "destination": ["billing@example.com"]})
check("create alias finance@ -> billing@", r.status_code == 201, r.text)

r = client.post(f"/v1/domains/{domain_id}/mailboxes", headers=AH,
                json={"type": "catch_all", "local_part": "any"})
check("catch_all blocked -> 403 feature_not_in_plan",
      r.status_code == 403 and r.json()["error"]["code"] == "feature_not_in_plan", r.text)

# webhook sink (local HTTP) + registration
webhook_hits: list[tuple[str, bytes]] = []


class Hook(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        webhook_hits.append((self.headers.get("X-Signature", ""), body))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


hook_srv = HTTPServer(("127.0.0.1", 2600), Hook)
threading.Thread(target=hook_srv.serve_forever, daemon=True).start()

r = client.post("/v1/webhooks", headers=AH, json={"url": "http://127.0.0.1:2600/hook"})
check("POST /v1/webhooks -> 201 + secret", r.status_code == 201 and r.json()["secret"].startswith("whsec_"), r.text)
wh_secret = r.json()["secret"]

# --- 4. send flow -----------------------------------------------------------------------------

payload = {
    "from": "Billing <billing@example.com>",
    "to": ["jane@customer.com"],
    "subject": "Invoice 1042",
    "text": "Your invoice is attached.",
    "html": "<p>Your invoice is attached.</p>",
    "attachments": [{
        "filename": "inv-1042.pdf",
        "content_type": "application/pdf",
        "content_base64": base64.b64encode(b"%PDF-1.4 fake invoice").decode(),
    }],
    "idempotency_key": "inv-1042",
}

r = client.post("/v1/messages", headers=AH, json=payload)
check("send while domain pending -> 422 inactive_sender_domain",
      r.status_code == 422 and r.json()["error"]["code"] == "inactive_sender_domain", r.text)

db = SessionLocal()
d = db.get(Domain, domain_id)
d.status = "active"
for rec in d.records:
    if rec.required:
        rec.status = "ok"
db.commit()
db.close()

r = client.post(f"/v1/domains/{domain_id}/verify", headers=AH)
check("POST /v1/domains/{id}/verify runs live DNS checks -> 200", r.status_code == 200, r.text)
# verification without real DNS flips the domain back; re-activate for the send test
db = SessionLocal()
db.get(Domain, domain_id).status = "active"
db.commit()
db.close()

r = client.post("/v1/messages", headers=AH, json=payload)
check("POST /v1/messages -> 202 {id, queued}", r.status_code == 202 and r.json()["status"] == "queued", r.text)
sent = r.json()

r2 = client.post("/v1/messages", headers=AH, json=payload)
check("idempotency_key replay returns same message", r2.json()["id"] == sent["id"])

# --- 5. limits -------------------------------------------------------------------------------

r = client.post("/v1/domains", headers=AH, json={"name": "second.com"})
check("2nd domain on starter (max 1) -> 403 plan_limit_exceeded",
      r.status_code == 403 and r.json()["error"]["code"] == "plan_limit_exceeded"
      and r.json()["error"]["limit"] == "max_domains", r.text)

r = client.patch(f"/v1/plans/{starter.id}", headers=H, json={"max_sends_per_minute": 0})
check("PATCH plan applies to all its accounts", r.status_code == 200 and r.json()["max_sends_per_minute"] == 0)
r = client.post("/v1/messages", headers=AH,
                json={"from": "billing@example.com", "to": ["x@customer.com"], "subject": "t", "text": "x"})
check("send over per-minute rate -> 429 rate_limited",
      r.status_code == 429 and r.json()["error"]["code"] == "rate_limited", r.text)
client.patch(f"/v1/plans/{starter.id}", headers=H, json={"max_sends_per_minute": 20})

# --- 6. send worker + DKIM ---------------------------------------------------------------------

from aiosmtpd.controller import Controller  # noqa: E402


class Sink:
    def __init__(self):
        self.mail = []

    async def handle_DATA(self, server, session, envelope):
        self.mail.append(envelope)
        return "250 OK"


sink = Sink()
relay_ctl = Controller(sink, hostname="127.0.0.1", port=2525)
relay_ctl.start()
time.sleep(0.3)

from app.deps import get_redis  # noqa: E402
from app.workers.send_worker import process_one  # noqa: E402

redis = get_redis()
import asyncio  # noqa: E402

asyncio.run(process_one(sent["id"], redis))

db = SessionLocal()
m = db.get(Message, sent["id"])
check("send worker: message delivered", m.status == "delivered", (m.status, m.last_error))
signed = sink.mail[0].content if len(sink.mail) == 1 else b""
check("relay sink received exactly one message", len(sink.mail) == 1)
check("message was DKIM-signed (worker stores final copy)", b"DKIM-Signature" in signed)
import dkim  # noqa: E402

# verify against the generated public key (offline stand-in for the DNS TXT record)
db = SessionLocal()
pub_b64 = db.get(Domain, domain_id).dkim_public_b64
db.close()


def fake_get_txt(name, timeout=5):
    n = name.decode() if isinstance(name, (bytes, bytearray)) else str(name)
    if n.rstrip(".") == f"{domain['dkim_selector']}._domainkey.example.com":
        return f"v=DKIM1; k=rsa; p={pub_b64}"
    return None


check("DKIM signature verifies with dkim.verify",
      bool(dkim.DKIM(signed).verify(dnsfunc=fake_get_txt)))
check("outbound .eml in fake bucket", any(f"/{sent['id']}.eml" in k for k in FAKE_BUCKET))
db.close()

# --- 7. webhook delivery + HMAC -----------------------------------------------------------------

import app.webhooks as wh  # noqa: E402


def pop_job(event: str) -> dict:
    """Pop until the expected event arrives (other events may be queued earlier)."""
    for _ in range(20):
        raw = redis.rpop(wh.QUEUE)
        if raw is None:
            raise AssertionError(f"queue empty, expected {event}")
        job = json.loads(raw)
        if job["event"] == event:
            return job
    raise AssertionError(f"{event} not found in queue")


job = pop_job("message.delivered")
check("message.delivered webhook queued", job["event"] == "message.delivered")
check("webhook delivered to sink", wh.deliver_job(job) and webhook_hits)
sig, body = webhook_hits[-1]
expected = hmac.new(wh_secret.encode(), body, hashlib.sha256).hexdigest()
check("X-Signature = HMAC-SHA256(secret, body)", sig == expected)
check("webhook payload has event + data", json.loads(body)["event"] == "message.delivered")

# --- 8. read-back ---------------------------------------------------------------------------------

r = client.get("/v1/messages", headers=AH)
check("GET /v1/messages lists the sent message", r.status_code == 200 and any(x["id"] == sent["id"] for x in r.json()["data"]))
r = client.get("/v1/messages?status=delivered", headers=AH)
check("filter by status", len(r.json()["data"]) == 1)

r = client.get(f"/v1/messages/{sent['id']}", headers=AH)
detail = r.json()
check("detail has delivered event + attachment",
      any(e["event"] == "delivered" for e in detail["events"]) and len(detail["attachments"]) == 1)
att_id = detail["attachments"][0]["id"]

r = client.get(f"/v1/messages/{sent['id']}/raw", headers=AH)
check("raw .eml pre-signed URL (5 min)", r.status_code == 200 and r.json()["expires_in"] == 300
      and r.json()["url"].startswith("https://fake.s3.local/outbound/"))
r = client.get(f"/v1/messages/{sent['id']}/attachments/{att_id}", headers=AH)
check("attachment pre-signed URL", r.status_code == 200)

r = client.get("/v1/account", headers=AH)
usage = r.json()["usage"]
check("GET /v1/account live usage", usage["domains"]["used"] == 1 and usage["sends_today"]["used"] >= 1
      and usage["storage"]["unit"] == "bytes")
r = client.get(f"/v1/accounts/{acct['id']}/usage", headers=H)
check("GET /v1/accounts/{id}/usage (admin)", r.status_code == 200)

# --- 9. inbound :25 -> LMTP :2424 --------------------------------------------------------------------

from app.smtp.server import (  # noqa: E402
    InboundHandler,
    InboundWorkerHandler,
    LMTPController,
    SubmissionHandler,
    _authenticate,
)

lmtp_ctl = LMTPController(InboundWorkerHandler(), hostname="127.0.0.1", port=2424)
inbound_ctl = Controller(InboundHandler(), hostname="127.0.0.1", port=2025)
for ctl in (lmtp_ctl, inbound_ctl):
    ctl.start()
time.sleep(0.3)

inbound_raw = EmailMessage()
inbound_raw["From"] = "Jane <jane@customer.com>"
inbound_raw["To"] = "billing@example.com"
inbound_raw["Subject"] = "Payment received"
inbound_raw.set_content("Thanks! The payment is on its way.")

s = smtplib.SMTP("127.0.0.1", 2025, timeout=15)
s.sendmail("jane@customer.com", ["billing@example.com"], inbound_raw.as_bytes())
s.quit()
check("inbound accepted for existing mailbox (no backscatter path)", True)

s = smtplib.SMTP("127.0.0.1", 2025, timeout=15)
try:
    s.sendmail("jane@customer.com", ["nobody@example.com"], inbound_raw.as_bytes())
    check("unknown recipient rejected", False, "expected 550")
except smtplib.SMTPRecipientsRefused:
    check("unknown recipient rejected 550 during conversation", True)
finally:
    s.quit()

time.sleep(0.5)
db = SessionLocal()
inbound_rows = db.query(Message).filter(Message.direction == "inbound").all()
check("inbound worker stored the message", len(inbound_rows) == 1 and inbound_rows[0].subject == "Payment received")
check("inbound row has spam result (dkim check)", inbound_rows and "dkim=" in (inbound_rows[0].spam_result or ""))
check("raw .eml under inbound/ in bucket", any(k.startswith("inbound/example.com/") for k in FAKE_BUCKET))
db.close()

job2 = pop_job("message.received")
check("message.received webhook queued with raw link",
      job2["event"] == "message.received" and job2["data"]["raw_url"].startswith("https://fake.s3.local/inbound/"))

# --- 10. submission :587 -------------------------------------------------------------------------------

sub_ctl = Controller(SubmissionHandler(), hostname="127.0.0.1", port=2587,
                     authenticator=_authenticate, auth_required=True, auth_require_tls=False)
sub_ctl.start()
time.sleep(0.3)

s = smtplib.SMTP("127.0.0.1", 2587, timeout=15)
s.ehlo()
code, resp = s.docmd("MAIL", "FROM:<billing@example.com>")
s.quit()
check("submission without AUTH -> 530", code == 530, (code, resp))

sub_raw = EmailMessage()
sub_raw["From"] = "billing@example.com"
sub_raw["To"] = "jane@customer.com"
sub_raw["Subject"] = "Via submission"
sub_raw.set_content("Sent over authenticated submission.")

s = smtplib.SMTP("127.0.0.1", 2587, timeout=15)
s.login(cred["username"], cred["password"])
check("AUTH PLAIN with credential", s.does_esmtp)
bad = EmailMessage()
bad["From"] = "evil@other.com"
bad["To"] = "jane@customer.com"
bad["Subject"] = "spoof"
bad.set_content("x")
try:
    s.sendmail("evil@other.com", ["jane@customer.com"], bad.as_bytes())
    check("MAIL FROM domain not owned -> 553", False, "expected 553")
except smtplib.SMTPSenderRefused:
    check("MAIL FROM domain not owned -> 553", True)
s.sendmail("billing@example.com", ["jane@customer.com"], sub_raw.as_bytes())
s.quit()

db = SessionLocal()
sub_rows = db.query(Message).filter(Message.subject == "Via submission").all()
check("submission stored + queued like an API send", len(sub_rows) == 1 and sub_rows[0].status == "queued")
sub_id = sub_rows[0].id
db.close()

asyncio.run(process_one(sub_id, redis))
db = SessionLocal()
m2 = db.get(Message, sub_id)
check("submission delivered through same queue", m2.status == "delivered", (m2.status, m2.last_error))
db.close()
check("relay sink got both outbound messages", len(sink.mail) == 2)

# --- 11. suspend ----------------------------------------------------------------------------------------

r = client.post(f"/v1/accounts/{acct['id']}/suspend", headers=H)
check("suspend account", r.status_code == 200 and r.json()["status"] == "suspended")

r = client.post("/v1/messages", headers=AH,
                json={"from": "billing@example.com", "to": ["j@x.com"], "subject": "x", "text": "x"})
check("API send while suspended -> 403", r.status_code == 403 and r.json()["error"]["code"] == "account_suspended")

s = smtplib.SMTP("127.0.0.1", 2025, timeout=15)
try:
    s.sendmail("jane@customer.com", ["billing@example.com"], inbound_raw.as_bytes())
    check("inbound while suspended -> 550", False, "expected 550")
except smtplib.SMTPRecipientsRefused:
    check("inbound while suspended -> 550", True)
finally:
    s.quit()

r = client.post(f"/v1/accounts/{acct['id']}/activate", headers=H)
check("reactivate account (convenience addition)", r.status_code == 200)

# --- 12. retention sweep ------------------------------------------------------------------------------------

db = SessionLocal()
m = db.get(Message, sent["id"])
m.created_at = datetime.now(timezone.utc) - timedelta(days=45)  # starter retention = 30 days
db.commit()
db.close()

from app.workers.scheduler import retention_sweep  # noqa: E402

purged = retention_sweep()
check("retention sweep purged expired message", purged >= 1)
db = SessionLocal()
check("message row marked purged", db.get(Message, sent["id"]).status == "purged")
db.close()
check("bucket objects deleted for purged message",
      not any(sent["id"] in k for k in FAKE_BUCKET))

# --- summary ---------------------------------------------------------------------------------------------

print(f"\nALL {PASS} CHECKS PASSED")
relay_ctl.stop()
for ctl in (lmtp_ctl, inbound_ctl, sub_ctl, hook_srv):
    try:
        if hasattr(ctl, "stop"):
            ctl.stop()
        else:
            ctl.shutdown()
    except Exception:
        pass
