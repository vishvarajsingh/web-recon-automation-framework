"""Perform passive DNS enumeration."""

import logging
from typing import Any, Dict

from dns import resolver as dns_resolver

logger = logging.getLogger("web_recon")


def _safe_answer(answer: Any) -> Dict[str, Any]:
    if answer is None:
        return {"status": "no_answer"}
    values = []
    for item in answer:
        values.append(item.to_text() if hasattr(item, "to_text") else str(item))
    return {"status": "ok", "values": values}


def gather_dns_info(hostname: str) -> Dict[str, Any]:
    """Query common record types and return structured results."""
    result: Dict[str, Any] = {"hostname": hostname, "records": {}}
    for record_type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
        try:
            answers = dns_resolver.resolve(hostname, record_type, lifetime=3)
            result["records"][record_type] = _safe_answer(answers)
        except dns_resolver.NXDOMAIN:
            result["records"][record_type] = {"status": "nxdomain"}
        except dns_resolver.NoAnswer:
            result["records"][record_type] = {"status": "no_answer"}
        except dns_resolver.Timeout:
            result["records"][record_type] = {"status": "timeout"}
        except Exception as exc:  # pragma: no cover
            logger.warning("DNS query %s failed for %s: %s", record_type, hostname, exc)
            result["records"][record_type] = {"status": "error", "error": str(exc)}
    return result
