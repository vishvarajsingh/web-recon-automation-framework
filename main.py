"""Entry point for the passive web recon automation framework."""

import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from config import OUTPUT_DIRECTORY
from modules.dns_lookup import gather_dns_info
from modules.exposure_engine import ExposureDetectionEngine
from modules.http_headers import gather_http_headers
from modules.input_validator import normalize_target
from modules.ip_lookup import gather_ip_info
from modules.logger import configure_logger
from modules.robots import gather_robots
from modules.risk_engine import RiskEngine
from modules.security_headers import gather_security_headers
from modules.sitemap import gather_sitemap
from modules.ssl_info import gather_ssl_info
from modules.tech_detector import detect_technology
from modules.utils import iso_timestamp, safe_json_dump
from modules.whois_lookup import gather_whois_info
from reporting.report_generator import generate_html_report

OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)
logger = configure_logger()
console = Console()


def run_module(module_name: str, function: Any, *args: Any) -> Tuple[str, Dict[str, Any]]:
    """Execute a module and return its name and result safely."""
    try:
        result = function(*args)
        if not isinstance(result, dict):
            return module_name, {"status": "error", "error": "Module returned a non-dictionary result"}
        return module_name, result
    except Exception as exc:  # pragma: no cover
        return module_name, {"status": "error", "error": str(exc)}


def collect_recon(
    target: str,
    output_dir: Path | str = OUTPUT_DIRECTORY,
    progress_callback: Callable[[int, str], None] | None = None,
) -> Dict[str, Any]:
    """Run all passive modules and aggregate their results."""

    def module_state(result: Dict[str, Any]) -> str:
        status = result.get("status")
        if status == "ok":
            return "SUCCESS"
        if status == "partial":
            return "PARTIAL"
        if status == "not_found":
            return "NOT_FOUND"
        return "FAILED"

    def update_progress(percent: int, message: str) -> None:
        if progress_callback:
            progress_callback(percent, message)

    start_time = time.time()
    update_progress(5, "Validating target")
    normalized = normalize_target(target)
    if not normalized.get("valid"):
        update_progress(100, "Target validation failed")
        return {"status": "invalid", "error": normalized.get("error", "Invalid target")}

    hostname = normalized["hostname"]
    base_url = normalized["base_url"]
    logger.info("Scan started for %s", hostname)

    console.print(Panel.fit(f"[bold cyan]Passive Web Recon Automation Framework[/bold cyan]\nTarget: [green]{hostname}[/green]", border_style="cyan"))

    modules: Dict[str, Dict[str, Any]] = {}
    module_status: Dict[str, str] = {}
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning modules...", total=9)
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [
                executor.submit(run_module, "whois", gather_whois_info, hostname),
                executor.submit(run_module, "dns", gather_dns_info, hostname),
                executor.submit(run_module, "ip", gather_ip_info, hostname),
                executor.submit(run_module, "http", gather_http_headers, base_url),
                executor.submit(run_module, "ssl", gather_ssl_info, base_url),
                executor.submit(run_module, "robots", gather_robots, base_url),
                executor.submit(run_module, "sitemap", gather_sitemap, base_url),
                executor.submit(run_module, "security_headers", gather_security_headers, base_url),
                executor.submit(run_module, "technology", detect_technology, base_url),
            ]
            for idx, future in enumerate(futures):
                name, result = future.result()
                modules[name] = result
                module_status[name] = module_state(result)
                logger.info("Module completed: %s", name)
                progress.advance(task)
                update_progress(10 + int((idx + 1) * 4.5), f"Completed {name}")

    update_progress(50, "Analyzing security risk")
    risk_engine = RiskEngine()
    risk = risk_engine.score({
        "security_headers": modules.get("security_headers", {}),
        "ssl": modules.get("ssl", {}),
        "http": modules.get("http", {}),
    })

    update_progress(65, "Analyzing exposure")
    exposure_engine = ExposureDetectionEngine()
    exposure = exposure_engine.analyze({
        "target": target,
        "normalized_target": normalized,
        "modules": modules,
    })

    duration = round(time.time() - start_time, 2)
    payload = {
        "metadata": {
            "target": target,
            "normalized_url": base_url,
            "resolved_ip": (
                modules.get("ip", {}).get("ipv4", [])
                or modules.get("ip", {}).get("ipv6", [])
                or [None]
            )[0],
            "start_time": datetime.fromtimestamp(start_time).isoformat(),
            "end_time": datetime.now().isoformat(),
            "duration_seconds": duration,
            "tool_version": "1.1",
            "modules_executed": list(module_status.keys()),
            "modules_failed": [name for name, status in module_status.items() if status == "FAILED"],
        },
        "target": target,
        "timestamp": iso_timestamp(),
        "normalized_target": normalized,
        "modules": modules,
        "module_status": module_status,
        "risk": risk,
        "risk_summary": {
            "security_risk": risk["overall_rating"],
            "security_score": f"{risk['overall_score']}/100",
            "exposure_risk": exposure["summary"]["overall_score"],
            "exposed_resources": exposure["summary"]["total_exposed_resources"],
            "critical_findings": exposure["summary"]["critical_findings"],
            "high_findings": exposure["summary"]["high_findings"],
            "medium_findings": exposure["summary"]["medium_findings"],
            "low_findings": exposure["summary"]["low_findings"],
        },
        "exposure": exposure,
        "executive_summary": (
            "Passive reconnaissance completed successfully. Review the report for key observations "
            "including DNS, HTTP, SSL, security headers, and exposed resources."
        ),
    }

    update_progress(80, "Writing reports")
    output_dir = Path(output_dir)
    output_path = output_dir / f"{hostname.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    html_path = output_path.with_suffix(".html")
    payload["report_paths"] = {
        "json": str(output_path),
        "html": str(html_path),
    }
    safe_json_dump(payload, str(output_path))
    html_report = generate_html_report(payload)
    html_path.write_text(html_report, encoding="utf-8")

    update_progress(100, "Recon finished")
    logger.info("Scan finished for %s", hostname)

    severity_styles = {
        "Critical": "red",
        "High": "yellow",
        "Medium": "magenta",
        "Low": "green",
        "Informational": "cyan",
    }
    exposure_style = severity_styles.get(exposure["summary"]["overall_score"], "cyan")
    alert_lines = [f"Overall Exposure Risk: {exposure['summary']['overall_score']}", f"Exposed Resources: {exposure['summary']['total_exposed_resources']}"]
    for finding in exposure.get("findings", [])[:6]:
        severity = finding.get("severity", "Informational")
        alert_lines.append(f"[{severity}] {finding.get('title', 'Finding')} | Source: {finding.get('source', 'Other')}")
    if not exposure.get("findings"):
        alert_lines.append("No exposed resources detected from passive evidence.")

    console.print(Panel.fit("\n".join(alert_lines), title="Exposure Alert Panel", border_style=exposure_style))

    summary_table = Table(title="Execution Summary")
    summary_table.add_column("Metric")
    summary_table.add_column("Value")
    summary_table.add_row("Target", hostname)
    summary_table.add_row("Security Risk", risk["overall_rating"])
    summary_table.add_row("Security Score", f"{risk['overall_score']}/100")
    summary_table.add_row("Exposure Risk", exposure["summary"]["overall_score"])
    summary_table.add_row("Exposed Resources", str(exposure["summary"]["total_exposed_resources"]))
    summary_table.add_row("Critical Findings", str(exposure["summary"]["critical_findings"]))
    summary_table.add_row("High Findings", str(exposure["summary"]["high_findings"]))
    summary_table.add_row("Medium Findings", str(exposure["summary"]["medium_findings"]))
    summary_table.add_row("Low Findings", str(exposure["summary"]["low_findings"]))
    summary_table.add_row("Scan Duration", f"{duration:.2f} seconds")
    try:
        display_json_path = str(output_path.relative_to(Path.cwd()))
    except ValueError:
        display_json_path = str(output_path)
    try:
        display_html_path = str(html_path.relative_to(Path.cwd()))
    except ValueError:
        display_html_path = str(html_path)
    summary_table.add_row("JSON Report", display_json_path)
    summary_table.add_row("HTML Report", display_html_path)
    console.print(summary_table)
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Passive Web Recon Automation Framework")
    parser.add_argument("target", help="Domain or URL to analyze")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    payload = collect_recon(args.target)
    if payload.get("status") == "invalid":
        console.print(f"[bold red]ERROR[/bold red] {payload['error']}")
        return 2

    console.print("[bold green]✔ Reconnaissance completed[/bold green]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
