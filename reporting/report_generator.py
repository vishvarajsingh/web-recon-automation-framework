from html import escape
from typing import Any, Dict


def generate_html_report(payload: Dict[str, Any]) -> str:
    modules = payload.get("modules", {})
    parsed = payload.get("normalized_target", {})
    exposure = payload.get("exposure", {})
    summary = exposure.get("summary", {})
    findings = exposure.get("findings", [])
    risk_summary = payload.get("risk_summary", {})
    metadata = payload.get("metadata", {})

    def render_module(title: str, data: Any) -> str:
        if isinstance(data, dict):
            rows = []
            for key, value in data.items():
                rows.append(f"<tr><th>{escape(str(key))}</th><td>{escape(str(value))}</td></tr>")
            return f"<section><h2>{escape(title)}</h2><table>{''.join(rows)}</table></section>"
        return f"<section><h2>{escape(title)}</h2><pre>{escape(str(data))}</pre></section>"

    severity_colors = {
        "Critical": "#d32f2f",
        "High": "#f57c00",
        "Medium": "#fbc02d",
        "Low": "#388e3c",
        "Informational": "#1976d2",
    }

    cards = []
    for finding in findings:
        severity = finding.get("severity", "Informational")
        cards.append(
            f"<div class='card' style='border-left:5px solid {severity_colors.get(severity, '#999')};'>"
            f"<h3>{escape(str(finding.get('title', 'Finding')))}</h3>"
            f"<p><strong>Resource:</strong> {escape(str(finding.get('resource', 'Unknown')))}</p>"
            f"<p><strong>Category:</strong> {escape(str(finding.get('category', 'Other')))}</p>"
            f"<p><strong>Severity:</strong> <span class='badge' style='background:{severity_colors.get(severity, '#999')};'>{escape(severity)}</span></p>"
            f"<p><strong>Source:</strong> {escape(str(finding.get('source', 'Other')))}</p>"
            f"<p><strong>Status:</strong> {escape(str(finding.get('status_code', 'n/a')))}</p>"
            f"<p><strong>Evidence:</strong> {escape(str(finding.get('evidence', '')))}</p>"
            f"<p><strong>Reason:</strong> {escape(str(finding.get('reason', '')))}</p>"
            f"<p><strong>Recommendation:</strong> {escape(str(finding.get('recommendation', '')))}</p></div>"
        )

    severity_cards = []
    for severity in ["Critical", "High", "Medium", "Low", "Informational"]:
        count = sum(1 for finding in findings if finding.get("severity") == severity)
        severity_cards.append(
            f"<div class='tile'><h3>{escape(severity)}</h3><p>{count}</p></div>"
        )

    sections = [
        "<h1>Web Reconnaissance Report</h1>",
        "<section><h2>Executive Summary</h2>",
        f"<p><strong>Target:</strong> {escape(payload.get('target', ''))}</p>",
        f"<p><strong>Hostname:</strong> {escape(parsed.get('hostname', ''))}</p>",
        f"<p><strong>Scan Date:</strong> {escape(payload.get('timestamp', ''))}</p>",
        f"<p><strong>Scan Duration:</strong> {escape(str(metadata.get('duration_seconds', 'n/a')))} seconds</p>",
        f"<p><strong>Security Score:</strong> {escape(str(risk_summary.get('security_score', 'n/a')))}</p>",
        f"<p><strong>Security Risk:</strong> {escape(str(risk_summary.get('security_risk', 'n/a')))}</p>",
        f"<p><strong>Exposure Risk:</strong> {escape(str(risk_summary.get('exposure_risk', 'n/a')))}</p>",
        f"<p><strong>Total Findings:</strong> {escape(str(summary.get('total_exposed_resources', 0)))}</p></section>",
        "<section><h2>Severity Overview</h2><div class='tiles'>" + "".join(severity_cards) + "</div></section>",
        "<section><h2>Exposed Resources & Alerts</h2>" + "".join(cards) + "</section>",
        "<section><h2>Summary Metrics</h2>"
        f"<p><strong>Overall Exposure Risk:</strong> {escape(str(summary.get('overall_score', 'Informational')))}</p>"
        f"<p><strong>Total Exposed Resources:</strong> {escape(str(summary.get('total_exposed_resources', 0)))}</p>"
        f"<p><strong>Critical Findings:</strong> {escape(str(summary.get('critical_findings', 0)))}</p>"
        f"<p><strong>High Findings:</strong> {escape(str(summary.get('high_findings', 0)))}</p>"
        f"<p><strong>Medium Findings:</strong> {escape(str(summary.get('medium_findings', 0)))}</p>"
        f"<p><strong>Low Findings:</strong> {escape(str(summary.get('low_findings', 0)))}</p></section>",
    ]

    for title, data in modules.items():
        sections.append(render_module(title, data))

    return "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Recon Report</title><style>body{font-family:Arial,sans-serif;padding:2rem;background:#f7f9fc;color:#1f2937;}section{margin-bottom:1.5rem;}table{border-collapse:collapse;width:100%;margin-bottom:1rem;background:white;}th,td{border:1px solid #ccc;padding:0.5rem;text-align:left;}pre{white-space:pre-wrap;background:white;padding:1rem;} .card{background:white;padding:1rem;margin-bottom:1rem;border-radius:6px;box-shadow:0 1px 3px rgba(0,0,0,0.1);} .badge{color:white;padding:0.2rem 0.5rem;border-radius:999px;font-size:0.8rem;} .tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:0.75rem;} .tile{background:white;padding:1rem;border-radius:6px;box-shadow:0 1px 3px rgba(0,0,0,0.1);} .tile h3{margin:0 0 0.25rem 0;} .tile p{font-size:1.2rem;font-weight:bold;margin:0;}</style></head><body>" + "".join(sections) + "</body></html>"
