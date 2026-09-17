from pathlib import Path

from ..core.config import settings


def safe_report_path(path: str | None) -> Path:
    if not path:
        raise FileNotFoundError("Report not available")
    report_path = Path(path).resolve()
    report_root = settings.OUTPUT_DIR.resolve()
    if report_path != report_root and report_root not in report_path.parents:
        raise FileNotFoundError("Report path is outside the configured report directory")
    return report_path