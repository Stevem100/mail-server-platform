"""Application settings, loaded from environment / .env (pydantic-settings)."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- App ---
    app_name: str = "Mail Server Platform"
    app_secret: str = "change-me-app-secret"  # derives the encryption key for DKIM private keys
    api_host: str = "0.0.0.0"
    api_port: int = 8080

    # --- Mail identity (one-time server setup in the design doc) ---
    mail_hostname: str = "mail.yourplatform.com"
    server_ip: str = "203.0.113.10"  # placeholder from the doc; set to your real sending IP
    dkim_selector: str = "s1"
    dmarc_rua_local: str = "dmarc"  # rua=mailto:dmarc@{domain}

    # --- Metadata database (PostgreSQL 16; SQLite allowed for local dev) ---
    database_url: str = "postgresql+psycopg2://mail:change-me@localhost:5432/mail"

    # --- Redis (queues + rate-limit counters) ---
    redis_url: str = "redis://localhost:6379/0"

    # --- Object storage (MinIO or any S3 API) ---
    s3_endpoint: str = "http://localhost:9000"
    s3_bucket: str = "mail-data"
    s3_key: str = "change-me"
    s3_secret: str = "change-me-too"
    s3_region: str = "us-east-1"
    presign_expires_s: int = 300  # pre-signed URLs valid for 5 minutes, per the design

    # --- SMTP listeners ---
    inbound_port: int = 25
    submission_port: int = 587
    lmtp_port: int = 2424
    smtp_relay_host: str | None = None  # set to a smarthost for dev; empty = direct MX delivery
    smtp_relay_port: int = 25
    spam_reject_score: float = 999.0  # Rspamd-equivalent hook; high default disables rejection
    # Optional STARTTLS certificate for :587 (required in production)
    submission_tls_cert: str | None = None
    submission_tls_key: str | None = None

    # --- Workers ---
    webhook_max_attempts: int = 5
    verify_interval_s: int = 3600
    retention_sweep_interval_s: int = 3600
    retention_default_days: int = 90

    # --- Optional managed DNS (PowerDNS HTTP API) ---
    pdns_api_url: str | None = None
    pdns_api_key: str | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
