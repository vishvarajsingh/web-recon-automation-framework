"""Collect passive SSL/TLS certificate details."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict

import requests
from cryptography import x509

logger = logging.getLogger("web_recon")


def gather_ssl_info(base_url: str) -> Dict[str, Any]:
    """Retrieve certificate details and return a structured payload."""
    try:
        response = requests.get(base_url, timeout=8, verify=True, headers={"User-Agent": "WebReconAutomationFramework/1.0"})
        if not response.url.startswith("https"):
            return {"status": "not_https"}

        cert = response.raw.connection.sock.getpeercert(binary_form=True)
        parsed = x509.load_der_x509_certificate(cert)

        now = datetime.now(timezone.utc)
        not_after = parsed.not_valid_after_utc
        days_remaining = (not_after - now).days
        expired = now > not_after

        subject = parsed.subject.rfc4514_string()
        issuer = parsed.issuer.rfc4514_string()
        san_entries = []
        try:
            extension = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_entries = extension.value.get_values_for_type(x509.DNSName)
        except Exception:
            san_entries = []

        return {
            "status": "ok",
            "issuer": issuer,
            "subject": subject,
            "valid_from": parsed.not_valid_before_utc.isoformat(),
            "valid_until": parsed.not_valid_after_utc.isoformat(),
            "days_remaining": days_remaining,
            "expired": expired,
            "signature_algorithm": parsed.signature_algorithm_oid._name,
            "san_entries": san_entries,
        }
    except Exception as exc:  # pragma: no cover
        logger.warning("SSL inspection failed for %s: %s", base_url, exc)
        return {"status": "error", "error": str(exc)}
