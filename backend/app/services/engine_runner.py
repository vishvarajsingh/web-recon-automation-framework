import threading
import time
from pathlib import Path
from typing import Any, Callable

from ..core.config import settings

from main import collect_recon

_scan_slots = threading.BoundedSemaphore(settings.MAX_CONCURRENT_SCANS)


def run_engine(
    target: str,
    output_dir: Path | str = None,
    progress_callback: Callable[[int, str], None] | None = None,
) -> dict[str, Any]:
    if not _scan_slots.acquire(blocking=False):
        raise RuntimeError("Maximum concurrent scan limit reached")
    output_dir = Path(output_dir or settings.OUTPUT_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + settings.SCAN_TIMEOUT_SECONDS

    def guarded_progress(percent: int, message: str) -> None:
        if time.monotonic() > deadline:
            raise TimeoutError("Reconnaissance exceeded the configured scan timeout")
        if progress_callback:
            progress_callback(percent, message)

    try:
        payload = collect_recon(target, output_dir=output_dir, progress_callback=guarded_progress)
        report_path = payload.get("report_paths", {}).get("json")
        return {"report": payload, "report_path": report_path}
    finally:
        _scan_slots.release()
