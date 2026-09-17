"""Safety and resource policy for passive outbound HTTP requests."""

import ipaddress
import socket
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

MAX_REDIRECTS = 3
MAX_RESPONSE_CONTENT_BYTES = 1_048_576


def validate_public_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only http and https URLs with a hostname are allowed")
    if parsed.username or parsed.password:
        raise ValueError("URLs with embedded credentials are not allowed")

    addresses = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    if not addresses:
        raise ValueError("Target hostname did not resolve")
    for address in {item[4][0] for item in addresses}:
        if not ipaddress.ip_address(address).is_global:
            raise ValueError("Private, local, reserved, and link-local targets are not allowed")
    return url


def safe_get(url: str, *, max_redirects: int = MAX_REDIRECTS, **kwargs: Any) -> requests.Response:
    current_url = validate_public_url(url)
    for redirect_number in range(max_redirects + 1):
        response = requests.get(current_url, allow_redirects=False, **kwargs)
        if response.status_code not in {301, 302, 303, 307, 308}:
            return response
        location = response.headers.get("Location")
        response.close()
        if not location or redirect_number == max_redirects:
            raise requests.TooManyRedirects("Redirect limit exceeded or redirect location was missing")
        current_url = validate_public_url(urljoin(current_url, location))
    raise requests.TooManyRedirects("Redirect limit exceeded")


def read_response_text(response: requests.Response, *, limit: int = MAX_RESPONSE_CONTENT_BYTES) -> tuple[str, bool]:
    body = bytearray()
    try:
        for chunk in response.iter_content(chunk_size=16_384):
            if not chunk:
                continue
            remaining = limit - len(body)
            body.extend(chunk[:remaining])
            if len(body) >= limit:
                break
    finally:
        response.close()
    encoding = response.encoding or "utf-8"
    return bytes(body).decode(encoding, errors="replace"), len(body) >= limit