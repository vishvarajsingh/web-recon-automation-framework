"""Utility helpers for formatting and safe conversions."""

import json
from datetime import datetime, timezone
from typing import Any, Dict


def iso_timestamp() -> str:
    """Return a UTC timestamp string."""
    return datetime.now(timezone.utc).isoformat()


def safe_json_dump(data: Dict[str, Any], path: str) -> None:
    """Write a dictionary to disk as pretty-printed JSON."""
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)
