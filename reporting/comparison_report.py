"""Self-contained HTML output for evidence-based investigation comparisons."""

import json
from html import escape
from typing import Any


def _text(value: Any) -> str:
    if value is None:
        return "Not available"
    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return escape(str(value))


def generate_comparison_html(comparison: dict) -> str:
    summary = comparison.get("summary", {})
    risk = comparison.get("risk", {})
    previous = comparison.get("previous", {})
    current = comparison.get("current", {})
    grouped: dict[str, list[dict]] = {}
    for change in comparison.get("changes", []):
        grouped.setdefault(str(change.get("category", "Other")), []).append(change)

    counts = "".join(
        f"<div class='metric'><span>{escape(label.title())}</span><strong>{int(summary.get(label, 0) or 0)}</strong></div>"
        for label in ("new", "changed", "resolved", "removed", "unchanged", "unknown")
    )
    category_sections = []
    for category, items in grouped.items():
        rows = []
        for item in items:
            rows.append(
                "<tr>"
                f"<td><span class='badge {escape(str(item.get('change_type', '')).lower())}'>{_text(item.get('change_type'))}</span></td>"
                f"<td>{_text(item.get('title'))}</td>"
                f"<td>{_text(item.get('previous'))}</td>"
                f"<td>{_text(item.get('current'))}</td>"
                f"<td>{_text(item.get('confidence'))}</td>"
                f"<td><details><summary>Evidence</summary><pre>{_text(item.get('evidence'))}</pre></details></td>"
                "</tr>"
            )
        category_sections.append(
            f"<section><h2>{escape(category)}</h2><div class='table-wrap'><table><thead><tr>"
            "<th>Classification</th><th>Observation</th><th>Previous</th><th>Current</th><th>Confidence</th><th>Evidence</th>"
            f"</tr></thead><tbody>{''.join(rows)}</tbody></table></div></section>"
        )

    delta = risk.get("delta")
    recommendations = []
    if isinstance(delta, int) and delta > 0:
        recommendations.append("Review newly introduced risk factors and prioritize the observations contributing to the increased score.")
    if summary.get("new", 0):
        recommendations.append("Review new observations and confirm their business context and access controls within the authorized scope.")
    if summary.get("unknown", 0):
        recommendations.append("Repeat the comparison after incomplete modules have completed successfully; unknown changes are not treated as removals or resolutions.")
    if not recommendations:
        recommendations.append("No newly observed priority was identified by the available comparison evidence.")
    recommendation_html = "".join(f"<li>{escape(item)}</li>" for item in recommendations)
    raw = json.dumps(comparison, ensure_ascii=False, indent=2, default=str)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scan Comparison - {_text(comparison.get('target'))}</title>
<style>
body{{margin:0;background:#111820;color:#17212b;font:15px/1.55 Arial,sans-serif}}main{{max-width:1200px;margin:28px auto;padding:0 18px}}header,section{{background:#fff;border:1px solid #d6dce0;border-radius:10px;margin-bottom:18px;padding:22px}}h1{{margin:0 0 8px;font-size:28px}}h2{{font-size:20px}}.muted{{color:#596873}}.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-top:18px}}.metric{{padding:13px;background:#f1f4f5;border:1px solid #d9e0e3;border-radius:7px}}.metric span,.metric strong{{display:block}}.metric span{{color:#596873;text-transform:uppercase;font-size:10px;font-weight:bold;letter-spacing:.1em}}.metric strong{{font-size:24px;margin-top:5px}}.risk{{font-size:18px;font-weight:bold}}.table-wrap{{overflow-x:auto}}table{{width:100%;border-collapse:collapse;min-width:800px}}th,td{{border-bottom:1px solid #dce1e4;padding:10px;text-align:left;vertical-align:top;overflow-wrap:anywhere}}th{{background:#edf1f3;font-size:11px;text-transform:uppercase;letter-spacing:.08em}}.badge{{display:inline-block;padding:4px 7px;border-radius:4px;background:#e8edf0;font-weight:bold;font-size:11px}}.new{{color:#a1242f;background:#fae8e9}}.changed{{color:#835600;background:#fff1cc}}.resolved{{color:#14644d;background:#e2f4ec}}.unknown{{color:#5b6470;background:#e9ecef}}details summary{{cursor:pointer;color:#8f2630;font-weight:bold}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f6f7;padding:10px;border-radius:5px}}@media(max-width:600px){{header,section{{padding:15px}}}}
</style></head><body><main>
<header><p class="muted">PASSIVE ASSESSMENT CHANGE RECORD</p><h1>Scan Comparison</h1>
<p><strong>Target:</strong> {_text(comparison.get('target'))}</p>
<p><strong>Previous scan:</strong> #{_text(previous.get('id'))} · {_text(previous.get('timestamp'))}</p>
<p><strong>Current scan:</strong> #{_text(current.get('id'))} · {_text(current.get('timestamp'))}</p>
<p class="risk">Observed risk points (higher = more observed risk): {_text(previous.get('risk_score'))} → {_text(current.get('risk_score'))} ({'+' if isinstance(delta, int) and delta > 0 else ''}{_text(delta)} points)</p>
<p class="muted">Risk evidence status: {_text(risk.get('evidence_status', 'unknown'))}. A point delta is not a probability.</p>
<div class="metrics">{counts}</div></header>
{''.join(category_sections) if category_sections else '<section><p>No comparable observations were returned.</p></section>'}
<section><h2>Recommended Investigation Priorities</h2><ul>{recommendation_html}</ul></section>
<section><h2>Limitations</h2><p>Comparison uses only data stored in the selected completed investigations. Failed or missing evidence is marked UNKNOWN and does not imply removal or resolution. A changed certificate observation is based on the recorded issuer, subject, expiry, and SAN fields; certificate replacement with identical collected fields may not be distinguishable.</p></section>
<section><details><summary>Expandable raw comparison evidence</summary><pre>{escape(raw)}</pre></details></section>
</main></body></html>"""
