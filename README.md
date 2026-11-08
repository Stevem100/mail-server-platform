# Mail Server Platform — Python Implementation

A complete Python implementation of the **Mail Server Platform Design**: a self-hosted mail
platform where you add a domain through an API, get back the exact DNS records it needs,
then send and receive mail over SMTP — with all message data kept in S3-compatible object
storage and every process running as a stateless container (all state in PostgreSQL, Redis
and the bucket).

The original design targets Laravel + Postfix + Rspamd + Dovecot. This build keeps the same
architecture, API surface, limits and storage layout, and implements the PHP/Postfix roles
in Python: **FastAPI** for the API, **aiosmtpd** for the SMTP edge, **dkimpy** for DKIM,
**SQLAlchemy + PostgreSQL 16** for metadata, **Redis 7** for queues/counters, **MinIO**
(any S3 API) for raw mail.

---

## 1. What is implemented

| Design doc component | Choice in doc | Python implementation |
| --- | --- | --- |
| SMTP in and out | Postfix | `app/smtp/server.py` — aiosmtpd inbound on **:25**, submission on **:587** |
| LMTP inbound worker | `inbound:serve` | aiosmtpd **LMTP on :2424** (`python -m app.smtp.server` starts all three) |
| API and workers | Laravel + Redis queue | **FastAPI** (`app/main.py`) + Redis-list queues (`q:send`, `q:webhooks`) |
| Send queue / DKIM signing | Rspamd signs via Postfix | `app/workers/send_worker.py` signs with **dkimpy** before delivery, stores the final signed copy under `outbound/` |
| Spam checks | Rspamd SPF/DMARC/spam score | Inbound **DKIM verification** + `spam_score`/`spam_result` recorded; a threshold hook (`SPAM_REJECT_SCORE`) is wired for a future Rspamd integration |
| Metadata database | PostgreSQL | **PostgreSQL 16** via SQLAlchemy (SQLite works for local dev) |
| Object storage | MinIO / any S3 | **boto3** against MinIO: private `mail-data` bucket, 5-minute pre-signed URLs, doc's exact prefix layout |
| DNS | PowerDNS (optional) | Record generation + **live verification with dnspython**; optional PowerDNS HTTP API writes (`PDNS_API_URL`) |
| Retention | lifecycle rules + worker | Bucket lifecycle rule (default 90 days) **plus** scheduler worker enforcing per-account `retention_days` |
| Webhooks | HMAC-SHA256 `X-Signature` | Dispatcher worker: 5 attempts with backoff, then failed |
| Scheduler | hourly re-checks | `app/workers/scheduler.py`: hourly DNS re-check + retention sweep |

Not implemented (deliberately, see §11): Dovecot IMAP storage, Roundcube webmail, the
Blade/Livewire admin UI, and the FBL/DMARC-report processors. The plan feature flags
(`imap`, `catch_all`, `smtp_submission`) and all their API-level enforcement **are** implemented.

## 2. Architecture

```
                      ┌────────────────────────── one host / compose network ─────────────────────────┐
 your app ── HTTPS ──▶ │ FastAPI :8080   POST /v1/messages ─┐                                          │
 (account/admin key)   │  plans/accounts/domains/messages   │ queued (Redis q:send)                    │
                       │                                    ▼                                          │
 users ── SMTP :587 ──▶ │ submission (AUTH, sender check) ──┤   send worker: DKIM sign (dkimpy)        │
       (STARTTLS)       │                                   │   → relay or direct MX :25               │
                       │                                   │   → delivered/deferred/bounced + webhook │
 world ── SMTP :25 ──▶ │ inbound: RCPT checks (550/552) ───┼── LMTP :2424 ── inbound worker:          │
                       │                                   │    .eml → bucket, parse, message.received│
                       │                                   │                                          │
                       │ postgres:16 (metadata)  redis:7 (queues, rate counters)                      │
                       │ minio (mail-data: inbound/, outbound/, attachments/, dkim-backup/)           │
                       │ scheduler: hourly DNS re-check + retention purge                              │
                       └───────────────────────────────────────────────────────────────────────────────┘
```

## 3. Repository layout

```
mail-server-platform/
├── app/
│   ├── main.py               FastAPI app (bearer-key auth, error shape, /healthz)
│   ├── config.py             settings from .env (pydantic-settings)
│   ├── db.py  models.py      SQLAlchemy schema — plans, accounts, api_keys, domains,
│   │                         domain_records, mailboxes, smtp_credentials, messages,
│   │                         message_events, attachments, webhooks
│   ├── schemas.py            request/response models (Pydantic v2)
│   ├── security.py           API keys (hashed, shown once), Argon2, Fernet for DKIM keys
│   ├── limits.py             every plan-limit check + Redis rate counters + usage report
│   ├── storage.py            S3/MinIO client, doc's key layout, pre-signed URLs
│   ├── dns.py                DKIM 2048-bit keygen, DNS record table, live verify, PowerDNS
│   ├── mail.py               MIME building + DKIM sign/verify
│   ├── webhooks.py           event enqueue + HMAC signing + delivery attempt
│   ├── errors.py             ApiError / SmtpReject (plan_limit_exceeded, ...)
│   ├── routers/              plans, accounts, domains, messages, webhooks
│   ├── services/             outbound.py (shared send path), inbound.py (receive path)
│   ├── smtp/server.py        :25 inbound, :587 submission (AUTH), :2424 LMTP worker
│   └── workers/              send_worker (DKIM + retry schedule), webhook_worker, scheduler
├── scripts/
│   ├── seed.py               starter/business plans from the doc + first admin key
│   ├── storage_init.py       bucket + lifecycle rules + before-first-start checklist
│   └── dev_smoke_test.py     offline end-to-end test (no Postgres/Redis/MinIO needed)
├── docker-compose.yml        postgres:16, redis:7, minio, api, smtp, 3 workers
├── Dockerfile  requirements.txt  .env.example
```

## 4. Quickstart

### Option A — full stack with Docker Compose

```bash
cp .env.example .env                 # set APP_SECRET, DB_PASSWORD, S3_KEY/S3_SECRET, MAIL_HOSTNAME, SERVER_IP
docker compose up -d --build         # postgres, redis, minio + api + smtp + 3 workers

docker compose exec api python -m scripts.seed          # plans + admin key (printed once)
docker compose exec api python -m scripts.storage_init  # bucket + lifecycle + checklist

# API on http://localhost:8080  (Swagger UI at /docs)
# SMTP: port 25 inbound, port 587 submission
```

### Option B — run the processes by hand (against local postgres/redis/minio)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env                 # point DATABASE_URL/REDIS_URL/S3_* at your services

python -m scripts.storage_init
python -m scripts.seed

uvicorn app.main:app --port 8080            # REST API
python -m app.smtp.server                   # :25 + :587 + :2424 in one process
python -m app.workers.send_worker           # DKIM sign + deliver + events
python -m app.workers.webhook_worker        # signed webhook deliveries
python -m app.workers.scheduler             # hourly re-checks + retention
```

### Option C — prove it works with zero infrastructure

```bash
python -m scripts.dev_smoke_test
# → ALL 55 CHECKS PASSED
# (SQLite + fakeredis + in-memory S3 + local SMTP sinks; covers API, limits,
#  DKIM sign/verify, inbound :25 → LMTP → bucket, submission AUTH, webhooks, retention)
```

## 5. Configuration (`.env`)

| Variable | Meaning |
| --- | --- |
| `DATABASE_URL` | PostgreSQL 16 DSN (`postgresql+psycopg2://mail:…@host:5432/mail`) |
| `REDIS_URL` | Redis for queues + rate counters |
| `S3_ENDPOINT` / `S3_BUCKET` / `S3_KEY` / `S3_SECRET` | Swap MinIO for AWS S3 / R2 / B2 by changing these four |
| `APP_SECRET` | Derives the Fernet key that encrypts DKIM private keys |
| `MAIL_HOSTNAME` | `mail.yourplatform.com` — needs A record + matching PTR |
| `SERVER_IP` | Placeholder `203.0.113.10` from the doc; set your real sending IP |
| `DKIM_SELECTOR` | `s1` |
| `SMTP_RELAY_HOST` / `SMTP_RELAY_PORT` | Optional smarthost; empty = direct MX delivery on port 25 |
| `PRESIGN_EXPIRES_S` | Pre-signed URL lifetime (300 = 5 minutes, per the doc) |
| `POLL_INTERVALS`, `WEBHOOK_MAX_ATTEMPTS`, `VERIFY_INTERVAL_S`, `RETENTION_DEFAULT_DAYS` | Worker tuning |
| `PDNS_API_URL` / `PDNS_API_KEY` | Optional managed DNS (records written for the user) |

Before first start (from the doc): make sure your host allows **outbound port 25**, set the
A record + reverse DNS (PTR) for `MAIL_HOSTNAME`, open firewall ports 25/587/80/443 (+53 for
pdns), and back up `pg_data`, `minio_data` and the DKIM keys.

## 6. REST API (`/v1`, JSON over HTTPS, `Authorization: Bearer <api key>`)

Two key kinds: an **admin key** (`mk_…`) creates plans/accounts; an **account key** (`ak_…`)
manages its own domains, mailboxes and messages. Keys are stored hashed; an account key can
be scoped to a single domain. Lists are paginated with `?cursor=` and `?limit=`.

| Method | Path | Key | Does |
| --- | --- | --- | --- |
| POST | `/v1/plans` | admin | Create a plan from the fields below |
| GET | `/v1/plans` | admin | List plans with how many accounts use each |
| PATCH | `/v1/plans/{id}` | admin | Change limits; applies to all its accounts at once |
| DELETE | `/v1/plans/{id}` | admin | Remove a plan; **409** while any account uses it |
| POST | `/v1/accounts` | admin | Create an account with a `plan_id` and return its first account key |
| PUT | `/v1/accounts/{id}/plan` | admin | Move an account to another plan |
| POST | `/v1/accounts/{id}/suspend` | admin | Stop all sending and receiving for the account |
| POST | `/v1/accounts/{id}/activate` | admin | *(addition)* undo a suspend |
| GET | `/v1/account` | account | Current plan, limits and live usage |
| GET | `/v1/accounts/{id}/usage` | admin | Usage against every limit for one account |
| POST | `/v1/domains` | account | Add a domain; returns DKIM selector and DNS records |
| GET | `/v1/domains` | account | List domains with status |
| GET | `/v1/domains/{id}` | account | Domain detail and per-record check results |
| POST | `/v1/domains/{id}/verify` | account | Re-run DNS checks now |
| DELETE | `/v1/domains/{id}` | account | Remove a domain and stop accepting its mail |
| POST | `/v1/domains/{id}/mailboxes` | account | Create a mailbox or alias |
| GET | `/v1/domains/{id}/mailboxes` | account | *(addition)* list mailboxes/aliases |
| DELETE | `/v1/domains/{id}/mailboxes/{mb_id}` | account | *(addition)* remove a mailbox/alias |
| POST | `/v1/domains/{id}/smtp-credentials` | account | Create SMTP submission username and password |
| POST | `/v1/messages` | account | Send a message (text, HTML, attachments) → **202** `{id, status:"queued"}` |
| GET | `/v1/messages` | account | List sent and received messages, filter by domain, status, date |
| GET | `/v1/messages/{id}` | account | Message metadata and delivery events |
| GET | `/v1/messages/{id}/raw` | account | Short-lived signed URL for the original `.eml` |
| GET | `/v1/messages/{id}/attachments/{aid}` | account | Short-lived signed URL for one attachment |
| POST | `/v1/webhooks` | account | Register a URL for events (secret shown once) |
| GET/DELETE | `/v1/webhooks` | account | *(addition)* list / deactivate webhooks |

### Plan fields (defaults shown = the doc's Starter example)

| Field | Meaning | Starter | Business |
| --- | --- | --- | --- |
| `max_domains` | Domains the account can add | 1 | 10 |
| `max_mailboxes` | Mailboxes across all domains | 5 | 100 |
| `max_aliases` | Aliases and forwards | 20 | 500 |
| `mailbox_quota_mb` | Default size cap per mailbox | 1024 | 5120 |
| `total_storage_gb` | Combined storage for the account | 5 | 200 |
| `max_sends_per_day` | Outbound messages per day | 500 | 20000 |
| `max_sends_per_minute` | Outbound burst limit | 20 | 200 |
| `max_recipients_per_message` | Recipients on one message | 20 | 100 |
| `max_message_size_mb` | Largest message accepted or sent | 15 | 25 |
| `max_api_keys` | Account keys | 2 | 20 |
| `max_webhooks` | Webhook endpoints | 1 | 10 |
| `retention_days` | How long stored mail is kept | 30 | 365 |
| `features` | `imap`, `catch_all`, `smtp_submission` flags | `["smtp_submission"]` | all three |

A mailbox can override its own `quota_mb` as long as the account total stays inside
`total_storage_gb`. Plans are limits only — no prices or invoices; your billing system just
calls `PUT /v1/accounts/{id}/plan`.

### Where limits are enforced

| Action | Check | Result when over |
| --- | --- | --- |
| Add domain / mailbox / alias / API key / webhook | count vs matching `max_*` | **403** `plan_limit_exceeded` + limit name |
| Send by API or SMTP | per-minute and per-day counters in Redis, recipient count, message size | **429** rates; **422** size and recipients; SMTP gets **452** rates, **552** size |
| Receive mail | mailbox quota, then account total storage | **552** `mailbox full` → sender gets a bounce |
| Use IMAP / catch-all / SMTP submission | `features` flag | **403** `feature_not_in_plan` |
| Retention | `retention_days` drives the lifecycle rule per account | objects deleted, message marked `purged` |

Moving to a smaller plan deletes nothing: existing domains/mailboxes keep working and new
additions are blocked until usage fits (every check runs against live counts).

## 7. Domains and DNS

`POST /v1/domains` generates a **2048-bit DKIM key pair** (private key Fernet-encrypted,
backup uploaded to `dkim-backup/{domain}.enc`) and returns the records to publish:

| Purpose | Type | Name | Value |
| --- | --- | --- | --- |
| Ownership proof | TXT | `_mailcheck.example.com` | `mailcheck=<random token>` |
| Receive mail | MX | `example.com` | `10 mail.yourplatform.com.` |
| Sender policy | TXT | `example.com` | `v=spf1 ip4:203.0.113.10 -all` |
| DKIM public key | TXT | `s1._domainkey.example.com` | `v=DKIM1; k=rsa; p=<public key>` |
| DMARC policy | TXT | `_dmarc.example.com` | `v=DMARC1; p=none; rua=mailto:dmarc@example.com` |
| TLS enforcement (optional) | TXT | `_mta-sts.example.com` | `v=STSv1; id=<timestamp>` |

States: `pending` → (ownership token resolves) `verified` → (MX+SPF+DKIM+DMARC all resolve)
`active`. Sending and receiving only work in `active`. `POST /v1/domains/{id}/verify` runs
live lookups now; the scheduler re-checks every hour and flags drifting records (firing
`domain.status_changed`). One-time server setup outside the flow: A record + PTR for the
mail hostname; start DMARC at `p=none` and tighten once reports look clean.

## 8. Sending

**API path** — `POST /v1/messages`:

```bash
curl -X POST https://api.yourplatform.com/v1/messages \
  -H "Authorization: Bearer ak_..." -H "Content-Type: application/json" \
  -d '{
        "from": "Billing <billing@example.com>",
        "to": ["jane@customer.com"],
        "subject": "Invoice 1042",
        "text": "Your invoice is attached.",
        "html": "<p>Your invoice is attached.</p>",
        "attachments": [{"filename": "inv-1042.pdf", "content_type": "application/pdf",
                         "content_base64": "..."}],
        "idempotency_key": "inv-1042"
      }'
# 202 Accepted  {"id": "msg_...", "status": "queued"}
```

The `from` domain must be `active` in your account (**422** otherwise). The message is
stored under `outbound/`, queued in Redis, then the send worker **DKIM-signs it** and
delivers to the smarthost or straight to each recipient's MX (opportunistic STARTTLS).
A log-tailer-equivalent updates `delivered` / `deferred` / `bounced` and fires the matching
webhook. Retry schedule for soft failures: **5 min, 30 min, 2 h, then every 4 h up to
3 days**, after which the message is `bounced`. Hard 5xx bounces immediately.

**SMTP submission path** — connect to `mail.yourplatform.com:587` (STARTTLS in production;
set `SUBMISSION_TLS_CERT`/`SUBMISSION_TLS_KEY`), authenticate with credentials from
`/v1/domains/{id}/smtp-credentials`. The server checks them (Argon2) against the database,
enforces that `MAIL FROM` belongs to a domain the credential owns (**553** otherwise),
applies the same rate limits (**452**), then queues the message through the identical path —
so the copy appears in `GET /v1/messages`.

## 9. Receiving

Port 25 accepts a message only when the recipient's domain is `active` and the mailbox,
alias, or (plan-permitted) catch-all exists — everything else is rejected during the SMTP
conversation (**550**), so the server never creates backscatter. Quota overage answers
**552 `mailbox full`**. Accepted mail is handed to the inbound worker over **LMTP :2424**,
which writes the raw `.eml` under `inbound/`, stores each attachment as its own object,
inserts the messages row (sender, recipients, subject, size, spam score, object keys) and
queues a `message.received` webhook carrying metadata + a signed link to the raw message.
If the worker or bucket is down, the :25 handler returns **451** and the sending MTA keeps
retrying — nothing is lost.

## 10. Object storage layout

One private bucket `mail-data`; the database keeps only metadata and object keys:

| Prefix | Contents | Written by | Retention |
| --- | --- | --- | --- |
| `inbound/{domain}/{yyyy}/{mm}/{msg_id}.eml` | raw received message | inbound worker | per-account, default 90 days |
| `outbound/{domain}/{yyyy}/{mm}/{msg_id}.eml` | final signed message as sent | send worker | per-account, default 90 days |
| `attachments/{msg_id}/{attachment_id}` | one attachment, original bytes | both workers | same as its message |
| `dkim-backup/{domain}.enc` | encrypted copy of the DKIM private key | API | until the domain is deleted |

Private by default; clients get pre-signed GET URLs valid **5 minutes**, issued only after
the API checks the caller owns the message. Services never share a filesystem — they
exchange object keys through the database and queue.

## 11. Webhooks

Register a URL; every delivery POSTs `{"event", "created_at", "data"}` with
`X-Signature: hex(HMAC-SHA256(secret, body))`. Verify in Python:

```python
import hmac, hashlib
expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
assert hmac.compare_digest(expected, request.headers["X-Signature"])
```

Events: `message.received`, `message.delivered`, `message.deferred`, `message.bounced`,
`message.complained`* , `domain.status_changed`. Delivery retries **5 attempts with
backoff**, then marks the attempt failed.
&nbsp;\* `message.complained` is defined and wired for events; the feedback-loop report
ingestion that triggers it is part of the not-implemented extras (§1).

## 12. Deviations from the design doc

- **Rspamd → dkimpy + hooks.** DKIM signing/verification is done in-process. The spam
  threshold hook and `spam_result` column are in place for a real Rspamd integration.
- **Postfix → aiosmtpd.** The queue is Redis + the send worker (the design's own worker
  pattern); retry schedule and event tracking match the doc.
- **Dovecot/Roundcube/admin UI are out of scope.** The `imap` feature flag exists and is
  enforced everywhere the doc enforces it; actual IMAP storage would need a Dovecot container
  fed by the inbound worker over LMTP. The admin UI pages map 1:1 onto the API endpoints
  above (plans, accounts, usage, domains, mailboxes, credentials, messages, webhooks).
- **Suppression list** is not included (it was an optional feature); hard bounces still mark
  messages `bounced` and fire `message.bounced`.
- Extra endpoints marked *(addition)* above (activate, mailbox list/delete, webhook list,
  `GET /v1/accounts`) exist because operators need them; everything from the doc's endpoint
  table is present unchanged.

## 13. Build phases (doc) → this codebase

| Phase | Where |
| --- | --- |
| 1. Foundation: compose stack, API skeleton, key auth, plans, quota checks | `docker-compose.yml`, `app/main.py`, `app/deps.py`, `routers/plans.py`, `limits.py` |
| 2. Domains and DNS: DKIM generation, records, verify, hourly re-check | `dns.py`, `routers/domains.py`, `workers/scheduler.py` |
| 3. Receiving: recipient lookup, LMTP worker, bucket storage, webhook | `smtp/server.py`, `services/inbound.py`, `storage.py` |
| 4. Sending: queue worker, DKIM signing, delivery events, retry schedule | `services/outbound.py`, `workers/send_worker.py` |
| 5. SMTP submission: SASL-style auth, per-domain credentials, ownership check | `smtp/server.py` (`:587`, `_authenticate`) |
| 6. Hardening: rate limits, retention, backups checklist | `limits.py`, `workers/scheduler.py`, `scripts/storage_init.py` |
| 7. Optional: managed DNS | `dns.apply_to_pdns` (set `PDNS_API_URL`) |

## 14. Security summary (doc's table, as implemented)

- **Transport:** STARTTLS available on :25; TLS for :587 when certificates are configured
  (`SUBMISSION_TLS_CERT`/`SUBMISSION_TLS_KEY`, `auth_require_tls` then enforced).
- **Submission auth:** per-credential passwords hashed with **Argon2**.
- **API keys:** shown once, stored SHA-256 hashed, optionally scoped to a single domain.
- **Open relay:** port 25 accepts mail only for active hosted domains; relaying requires
  authentication on 587.
- **Secrets:** DKIM private keys encrypted (Fernet, key derived from `APP_SECRET`) before
  storage and before the `dkim-backup/` upload.
- **Sender checks:** the from domain must belong to the caller, on both API and SMTP.
- **Inbound abuse:** 550 for unknown recipients in-conversation, 552 on quota; connection
  limits belong in your firewall/LB in front of :25.
- **Webhooks:** HMAC-SHA256 signature, 5 attempts with backoff, then failed.
