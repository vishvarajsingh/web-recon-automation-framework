import logging
import socket
from typing import Any, Dict

logger = logging.getLogger("web_recon")


def gather_ip_info(hostname: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {"hostname": hostname, "ipv4": [], "ipv6": [], "ptr": []}
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        for info in infos:
            ip_address = info[4][0]
            if ":" in ip_address and ip_address not in result["ipv6"]:
                result["ipv6"].append(ip_address)
            elif ":" not in ip_address and ip_address not in result["ipv4"]:
                result["ipv4"].append(ip_address)
    except Exception as exc:  # pragma: no cover
        logger.warning("Address resolution failed for %s: %s", hostname, exc)
        result["error"] = str(exc)

    for ip_address in result["ipv4"] + result["ipv6"]:
        try:
            ptr = socket.gethostbyaddr(ip_address)[0]
            if ptr not in result["ptr"]:
                result["ptr"].append(ptr)
        except Exception:
            continue

    return result
