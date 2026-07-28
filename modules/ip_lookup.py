"""Resolve IP addresses and reverse DNS for a hostname."""

import logging
import socket
from typing import Dict, List

logger = logging.getLogger("web_recon")


def gather_ip_info(hostname: str) -> Dict[str, object]:
    """Collect IPv4/IPv6 and reverse DNS data without crashing."""
    ipv4: List[str] = []
    ipv6: List[str] = []
    ptr: List[str] = []

    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        for info in infos:
            address = info[4][0]
            if ":" in address:
                if address not in ipv6:
                    ipv6.append(address)
            elif address not in ipv4:
                ipv4.append(address)
    except Exception as exc:  # pragma: no cover
        logger.warning("IP resolution failed for %s: %s", hostname, exc)
        return {"status": "error", "error": str(exc)}

    for ip_address in ipv4 + ipv6:
        try:
            reverse_name = socket.gethostbyaddr(ip_address)[0]
            if reverse_name not in ptr:
                ptr.append(reverse_name)
        except Exception:
            continue

    return {"status": "ok", "ipv4": ipv4, "ipv6": ipv6, "reverse_dns": ptr}
