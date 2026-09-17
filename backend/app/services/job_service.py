from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..core.config import settings
from ..core.database import SessionLocal
from .engine_runner import run_engine
from .investigation_service import get_investigation, update_investigation


_executor = ThreadPoolExecutor(max_workers=settings.MAX_CONCURRENT_SCANS, thread_name_prefix="recon-job")


def run_investigation_job(investigation_id: int, target: str) -> None:
    db = SessionLocal()
    try:
        investigation = get_investigation(db, investigation_id)
        if investigation is None:
            return
        update_investigation(db, investigation, status="running", progress=0, progress_message="Scan started")

        def progress_callback(percent: int, message: str) -> None:
            update_investigation(
                db,
                investigation,
                progress=percent,
                progress_message=message,
                status="running",
            )

        result = run_engine(target, output_dir=settings.OUTPUT_DIR, progress_callback=progress_callback)
        report = result["report"]
        report_path = Path(result["report_path"])
        update_investigation(
            db,
            investigation,
            status="completed",
            raw_output=report,
            report_location=str(report_path),
            html_report_location=str(report_path.with_suffix(".html")),
            risk_score=report.get("risk", {}).get("overall_score"),
            risk_rating=report.get("risk", {}).get("overall_rating"),
            progress=100,
            progress_message="Completed",
        )
    except Exception as exc:
        investigation = get_investigation(db, investigation_id)
        if investigation is not None:
            update_investigation(
                db,
                investigation,
                status="failed",
                progress=100,
                progress_message=str(exc),
            )
    finally:
        db.close()


def submit_investigation(investigation_id: int, target: str):
    return _executor.submit(run_investigation_job, investigation_id, target)