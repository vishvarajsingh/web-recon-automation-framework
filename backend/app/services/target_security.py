import ipaddress
import socket
from urllib.parse import urlparse


def validate_target(target: str) -> str:
    cleaned = target.strip()
    if not cleaned or any(character.isspace() for character in cleaned):
        raise ValueError("Target must be a non-empty URL or hostname")
    parsed = urlparse(cleaned if "://" in cleaned else f"https://{cleaned}")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only public http and https targets are allowed")
    if parsed.username or parsed.password:
        raise ValueError("Targets with embedded credentials are not allowed")
    addresses = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    if not addresses:
        raise ValueError("Target hostname did not resolve")
    for address in {item[4][0] for item in addresses}:
        if not ipaddress.ip_address(address).is_global:
            raise ValueError("Private, local, reserved, and link-local targets are not allowed")
    return cleaned