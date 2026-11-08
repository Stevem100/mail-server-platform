"""DNS: record generation, live verification (dnspython), optional PowerDNS writes.

A domain moves pending -> verified -> active; sending/receiving only work in active.
  - pending:  added, ownership not yet proven
  - verified: _mailcheck TXT token resolves
  - active:   MX, SPF, DKIM and DMARC all resolve correctly
An hourly scheduled job re-checks active domains and flags drifting records.
"""

import base64
import logging
from datetime import datetime, timezone

import dns.exception
import dns.resolver

from .config import settings

log = logging.getLogger("dns")

_resolver = dns.resolver.Resolver()
_resolver.lifetime = 5.0
_resolver.timeout = 3.0

REQUIRED_PURPOSES = ["mx", "spf", "dkim", "dmarc"]


def generate_dkim_keypair() -> tuple[str, str]:
    """2048-bit RSA pair -> (private PEM, public key base64 for the TXT record)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_b64 = base64.b64encode(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.PKCS1,
        )
    ).decode()
    return priv_pem, pub_b64


def build_records(domain: str, token: str, dkim_pub_b64: str, selector: str) -> list[dict]:
    """Records to publish for a domain (the table in 'Domains and DNS')."""
    mh = settings.mail_hostname
    return [
        {
            "purpose": "ownership",
            "rtype": "TXT",
            "rname": f"_mailcheck.{domain}",
            "value": f"mailcheck={token}",
            "required": True,
        },
        {"purpose": "mx", "rtype": "MX", "rname": domain, "value": f"10 {mh}.", "required": True},
        {
            "purpose": "spf",
            "rtype": "TXT",
            "rname": domain,
            "value": f"v=spf1 ip4:{settings.server_ip} -all",
            "required": True,
        },
        {
            "purpose": "dkim",
            "rtype": "TXT",
            "rname": f"{selector}._domainkey.{domain}",
            "value": f"v=DKIM1; k=rsa; p={dkim_pub_b64}",
            "required": True,
        },
        {
            "purpose": "dmarc",
            "rtype": "TXT",
            "rname": f"_dmarc.{domain}",
            "value": f"v=DMARC1; p=none; rua=mailto:{settings.dmarc_rua_local}@{domain}",
            "required": True,
        },
        {
            "purpose": "mta_sts",
            "rtype": "TXT",
            "rname": f"_mta-sts.{domain}",
            "value": f"v=STSv1; id={datetime.utcnow():%Y%m%d%H%M%S}",
            "required": False,  # optional TLS enforcement, per the design doc
        },
    ]


def apply_to_pdns(domain: str, records: list[dict]) -> bool:
    """Managed DNS option: create/update records through PowerDNS' HTTP API. Best effort."""
    if not settings.pdns_api_url or not settings.pdns_api_key:
        return False
    import httpx

    rrsets = [
        {
            "name": f"{r['rname']}.",
            "rtype": r["rtype"],
            "ttl": 3600,
            "changetype": "REPLACE",
            "records": [{"content": r["value"] if r["rtype"] != "MX" else r["value"], "disabled": False}],
        }
        for r in records
    ]
    try:
        resp = httpx.patch(
            f"{settings.pdns_api_url}/servers/localhost/zones/{domain}.",
            json={"rrsets": rrsets},
            headers={"X-API-Key": settings.pdns_api_key},
            timeout=10,
        )
        resp.raise_for_status()
        return True
    except Exception as exc:  # noqa: BLE001
        log.warning("PowerDNS update failed for %s: %s", domain, exc)
        return False


# --- Live verification -----------------------------------------------------------

def _txt_values(name: str) -> list[str]:
    out = []
    for rr in _resolver.resolve(name, "TXT"):
        out.append(b"".join(part for part in rr.strings).decode(errors="replace"))
    return out


def _mx_hosts(name: str) -> list[str]:
    return [str(rr.exchange).rstrip(".").lower() for rr in _resolver.resolve(name, "MX")]


def _check(record) -> tuple[str, str]:
    """Return (status, detail) for one record against live DNS."""
    purpose = record.purpose
    try:
        if purpose == "ownership":
            found = _txt_values(record.rname)
            ok = any(record.value in v for v in found)
            return ("ok" if ok else "failing", "" if ok else f"token not found in {found or 'no TXT'}")

        if purpose == "mx":
            hosts = _mx_hosts(record.rname)
            expected = record.value.split()[-1].rstrip(".")
            ok = expected.lower() in hosts
            return ("ok" if ok else "failing", f"MX={hosts}" if hosts else "no MX found")

        if purpose == "spf":
            found = _txt_values(record.rname)
            ok = any(v.startswith("v=spf1") and f"ip4:{settings.server_ip}" in v for v in found)
            return ("ok" if ok else "failing", "" if ok else "no matching v=spf1 record")

        if purpose == "dkim":
            found = _txt_values(record.rname)
            pub = record.value.split("p=")[-1]
            ok = any(v.replace(" ", "").endswith(pub) or pub in v.replace(" ", "") for v in found)
            return ("ok" if ok else "failing", "" if ok else "public key not published (or still cached)")

        if purpose == "dmarc":
            found = _txt_values(record.rname)
            ok = any(v.startswith("v=DMARC1") for v in found)
            return ("ok" if ok else "failing", "" if ok else "no v=DMARC1 record")

        if purpose == "mta_sts":  # optional
            found = _txt_values(record.rname)
            ok = any(v.startswith("v=STSv1") for v in found)
            return ("ok" if ok else "pending", "optional record")

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers) as exc:
        return ("pending" if purpose == "ownership" else "failing", f"DNS: {exc.__class__.__name__}")
    except dns.exception.Timeout:
        return ("failing", "DNS lookup timed out")
    return ("pending", "unknown check")


def verify_domain_sync(domain, records) -> tuple[str, str | None]:
    """Update per-record status; return (new_domain_status, previous_status).

    Caller is responsible for committing and for firing domain.status_changed.
    Safe to run in a thread (pure dnspython, no shared state).
    """
    from .models import utcnow

    old = domain.status
    results = []
    for rec in records:
        status, detail = _check(rec)
        rec.status = status
        rec.detail = detail[:500]
        rec.checked_at = utcnow()
        results.append((rec.purpose, status))

    by_purpose = dict(results)
    if all(by_purpose.get(p) == "ok" for p in REQUIRED_PURPOSES):
        new = "active"
    elif by_purpose.get("ownership") == "ok":
        new = "verified"
    else:
        new = "pending"

    domain.last_verified_at = utcnow()
    return new, old
