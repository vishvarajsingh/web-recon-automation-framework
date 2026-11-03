"""Evidence-aware comparison of two completed passive investigations."""

import json
from typing import Any

from reporting.report_generator import _extract_exposure_candidates


CHANGE_TYPES = ("NEW", "REMOVED", "CHANGED", "RESOLVED", "UNCHANGED", "UNKNOWN")
KNOWN_MODULE_STATES = {"ok", "partial", "not_found"}
SECURITY_HEADERS = (
    "strict_transport_security",
    "content_security_policy",
    "x_frame_options",
    "x_content_type_options",
    "referrer_policy",
)


def _evidence(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _change(category: str, change_type: str, title: str, previous: Any = None,
            current: Any = None, evidence: Any = None, confidence: str = "High") -> dict:
    return {
        "category": category,
        "change_type": change_type,
        "title": title,
        "previous": previous,
        "current": current,
        "evidence": _evidence(evidence if evidence is not None else {"previous": previous, "current": current}),
        "confidence": confidence,
    }


def _unknown(category: str, title: str, before: Any, after: Any) -> dict:
    return _change(category, "UNKNOWN", title, before, after,
                   {"previous_status": before, "current_status": after}, "Low")


def _module(report: dict, name: str) -> dict:
    modules = report.get("modules")
    value = modules.get(name) if isinstance(modules, dict) else None
    return value if isinstance(value, dict) else {}


def _status(value: dict) -> str | None:
    state = value.get("status")
    return str(state).lower() if state is not None else None


def _compare_dns(previous: dict, current: dict) -> list[dict]:
    old_dns, new_dns = _module(previous, "dns"), _module(current, "dns")
    changes = []
    old_records = old_dns.get("records") if isinstance(old_dns.get("records"), dict) else {}
    new_records = new_dns.get("records") if isinstance(new_dns.get("records"), dict) else {}
    if not old_records or not new_records:
        return [_unknown("DNS", "DNS record data is incomplete", _status(old_dns), _status(new_dns))]
    for record in sorted(set(old_records) | set(new_records)):
        old = old_records.get(record)
        new = new_records.get(record)
        old_state = old.get("status") if isinstance(old, dict) else None
        new_state = new.get("status") if isinstance(new, dict) else None
        valid = {"ok", "no_answer", "nxdomain"}
        if old_state not in valid or new_state not in valid:
            changes.append(_unknown("DNS", f"{record} records could not be compared", old_state, new_state))
            continue
        if (old_state == "ok" and not isinstance(old.get("values"), list)) or (new_state == "ok" and not isinstance(new.get("values"), list)):
            changes.append(_unknown("DNS", f"{record} record values are incomplete", old_state, new_state))
            continue
        old_values = sorted(set(old.get("values", []))) if old_state == "ok" else []
        new_values = sorted(set(new.get("values", []))) if new_state == "ok" else []
        if old_values == new_values:
            changes.append(_change("DNS", "UNCHANGED", f"{record} records unchanged", old_values, new_values))
        elif not old_values:
            changes.append(_change("DNS", "NEW", f"New {record} records", old_values, new_values))
        elif not new_values:
            changes.append(_change("DNS", "REMOVED", f"{record} records removed", old_values, new_values))
        else:
            changes.append(_change("DNS", "CHANGED", f"{record} records changed", old_values, new_values))
    if not old_dns or not new_dns:
        changes.append(_unknown("DNS", "DNS module data is incomplete", _status(old_dns), _status(new_dns)))
    return changes


def _compare_fields(category: str, title_prefix: str, old: dict, new: dict,
                    fields: tuple[str, ...], missing_type: str = "NEW") -> list[dict]:
    changes = []
    for field in fields:
        before, after = old.get(field), new.get(field)
        if before == after:
            changes.append(_change(category, "UNCHANGED", f"{title_prefix}: {field}", before, after))
        elif before in (None, "", [], {}):
            changes.append(_change(category, missing_type, f"{title_prefix}: {field}", before, after))
        elif after in (None, "", [], {}):
            changes.append(_change(category, "REMOVED", f"{title_prefix}: {field}", before, after))
        else:
            changes.append(_change(category, "CHANGED", f"{title_prefix}: {field}", before, after))
    return changes


def _compare_http(previous: dict, current: dict) -> list[dict]:
    old, new = _module(previous, "http"), _module(current, "http")
    if _status(old) != "ok" or _status(new) != "ok":
        return [_unknown("HTTP", "HTTP observations are inconclusive", _status(old), _status(new))]
    changes = []
    for field in ("status_code", "final_url", "redirect_chain", "cookies", "cookie_attributes"):
        if field not in old or field not in new:
            changes.append(_unknown("HTTP", f"HTTP {field} is missing from one scan", field in old, field in new))
        else:
            changes.extend(_compare_fields("HTTP", "HTTP", old, new, (field,)))

    old_h, new_h = _module(previous, "security_headers"), _module(current, "security_headers")
    if _status(old_h) != "ok" or _status(new_h) != "ok":
        changes.append(_unknown("HTTP & Security", "Security headers could not be compared", _status(old_h), _status(new_h)))
        return changes
    old_headers, new_headers = old_h.get("headers"), new_h.get("headers")
    if not isinstance(old_headers, dict) or not isinstance(new_headers, dict):
        changes.append(_unknown("HTTP & Security", "Security header evidence is incomplete", old_headers, new_headers))
        return changes
    for name in SECURITY_HEADERS:
        if name not in old_headers or name not in new_headers:
            changes.append(_unknown("HTTP & Security", f"Security header evidence missing: {name}", name in old_headers, name in new_headers))
            continue
        before, after = old_headers.get(name), new_headers.get(name)
        if before == after:
            state = "UNCHANGED"
        elif before and not after:
            state = "NEW"
        elif after and not before:
            state = "RESOLVED"
        else:
            state = "CHANGED"
        changes.append(_change("HTTP & Security", state, f"Security header: {name}", before, after))
    return changes


def _compare_tls(previous: dict, current: dict) -> list[dict]:
    old, new = _module(previous, "ssl"), _module(current, "ssl")
    if _status(old) not in {"ok", "not_https"} or _status(new) not in {"ok", "not_https"}:
        return [_unknown("TLS", "TLS certificate observations are inconclusive", _status(old), _status(new))]
    if _status(old) != _status(new):
        changes = [_change("TLS", "CHANGED", "TLS availability changed", _status(old), _status(new))]
    else:
        changes = []
    if _status(old) != "ok" or _status(new) != "ok":
        if not changes:
            changes.append(_change("TLS", "UNCHANGED", "TLS availability unchanged", _status(old), _status(new)))
        return changes
    for field in ("issuer", "subject", "valid_until", "san_entries", "expired"):
        if field not in old or field not in new:
            changes.append(_unknown("TLS", f"TLS field unavailable: {field}", field in old, field in new))
            continue
        before, after = old.get(field), new.get(field)
        if before == after:
            state = "UNCHANGED"
        elif field == "expired" and before is False and after is True:
            state = "NEW"
        elif field == "expired" and before is True and after is False:
            state = "RESOLVED"
        elif before in (None, "", []):
            state = "NEW"
        elif after in (None, "", []):
            state = "UNKNOWN"
        else:
            state = "CHANGED"
        changes.append(_change("TLS", state, f"TLS certificate: {field}", before, after,
                               {"previous": before, "current": after}, "Medium" if after is None else "High"))
    return changes


def _compare_technology(previous: dict, current: dict) -> list[dict]:
    old, new = _module(previous, "technology"), _module(current, "technology")
    successful = {"ok", "identified", "no_match"}
    if _status(old) not in successful or _status(new) not in successful:
        return [_unknown("Technology", "Technology observations are inconclusive", _status(old), _status(new))]
    if not isinstance(old.get("technologies"), list) or not isinstance(new.get("technologies"), list):
        return [_unknown("Technology", "Technology list is missing", "technologies" in old, "technologies" in new)]
    before = set(old["technologies"])
    after = set(new["technologies"])
    changes = [_change("Technology", "NEW", f"Technology detected: {name}", None, name) for name in sorted(after - before)]
    changes += [_change("Technology", "REMOVED", f"Technology no longer observed: {name}", name, None) for name in sorted(before - after)]
    if not changes:
        changes.append(_change("Technology", "UNCHANGED", "Technology observations unchanged", sorted(before), sorted(after)))
    return changes


def _source_completeness(report: dict) -> tuple[bool, dict[str, str | None]]:
    robots = _module(report, "robots")
    sitemap = _module(report, "sitemap")
    statuses = {"robots.txt": _status(robots), "sitemap.xml": _status(sitemap)}
    robots_ok = (
        statuses["robots.txt"] == "not_found"
        or (statuses["robots.txt"] == "ok" and isinstance(robots.get("content"), str) and not robots.get("content_truncated", False))
    )
    sitemap_ok = statuses["sitemap.xml"] in {"ok", "not_found", "partial"}
    results = sitemap.get("results", [])
    if statuses["sitemap.xml"] == "partial":
        sitemap_ok = bool(results) and all(isinstance(item, dict) and item.get("status") in {"found", "not_found"} for item in results)
    if statuses["sitemap.xml"] in {"ok", "partial"}:
        sitemap_ok = sitemap_ok and bool(results) and all(
            isinstance(item, dict)
            and item.get("status") in {"found", "not_found"}
            and (item.get("status") == "not_found" or isinstance(item.get("content"), str))
            and not item.get("content_truncated", False)
            for item in results
        )
    return robots_ok and sitemap_ok, statuses


def _compare_exposure(previous: dict, current: dict) -> list[dict]:
    old_items = {item["resource"]: item for item in _extract_exposure_candidates(previous)}
    new_items = {item["resource"]: item for item in _extract_exposure_candidates(current)}
    old_complete, old_status = _source_completeness(previous)
    new_complete, new_status = _source_completeness(current)
    changes = []
    for resource in sorted(new_items.keys() - old_items.keys()):
        item = new_items[resource]
        changes.append(_change("Exposure", "NEW", "Newly referenced resource", None, resource,
                               {"sources": item["sources"], "evidence": item["evidence"]}))
    for resource in sorted(old_items.keys() - new_items.keys()):
        item = old_items[resource]
        state = "REMOVED" if old_complete and new_complete else "UNKNOWN"
        changes.append(_change("Exposure", state, "Previously referenced resource no longer observed", resource, None,
                               {"previous_sources": item["sources"], "previous_evidence": item["evidence"],
                                "current_module_status": new_status}, "High" if state == "REMOVED" else "Low"))
    for resource in sorted(old_items.keys() & new_items.keys()):
        before, after = old_items[resource], new_items[resource]
        if any(before.get(field) != after.get(field) for field in ("sources", "evidence", "category", "http_status")):
            changes.append(_change("Exposure", "CHANGED", "Exposure evidence changed", before, after))
        else:
            changes.append(_change("Exposure", "UNCHANGED", "Exposure reference unchanged", resource, resource))
    if not changes:
        if not old_complete or not new_complete:
            return [_unknown("Exposure", "Exposure comparison is inconclusive", old_status, new_status)]
        return [_change("Exposure", "UNCHANGED", "No exposure candidate changes", [], [])]
    if not old_complete or not new_complete:
        # Add an explicit module-level signal so readers can distinguish partial evidence.
        changes.append(_unknown("Exposure", "Some path sources were incomplete", old_status, new_status))
    return changes


def _finding_source_complete(report: dict, source: str) -> bool:
    modules = {
        "robots.txt": "robots",
        "sitemap.xml": "sitemap",
        "HTTP Header": "http",
        "HTML": "http",
    }
    module = _module(report, modules.get(source, ""))
    if source == "robots.txt":
        return (
            _status(module) == "not_found"
            or (_status(module) == "ok" and isinstance(module.get("content"), str) and not module.get("content_truncated", False))
        )
    if source == "sitemap.xml" and _status(module) in {"ok", "partial"}:
        results = module.get("results", [])
        return bool(results) and all(
            isinstance(item, dict)
            and item.get("status") in {"found", "not_found"}
            and (item.get("status") == "not_found" or isinstance(item.get("content"), str))
            and not item.get("content_truncated", False)
            for item in results
        )
    return _status(module) in {"ok", "not_found"}


def _compare_exposure_findings(previous: dict, current: dict) -> list[dict]:
    old_exposure, new_exposure = previous.get("exposure"), current.get("exposure")
    old_findings = old_exposure.get("findings") if isinstance(old_exposure, dict) else None
    new_findings = new_exposure.get("findings") if isinstance(new_exposure, dict) else None
    if not isinstance(old_findings, list) or not isinstance(new_findings, list):
        return [_unknown("Exposure Observations", "Exposure observation data is missing", isinstance(old_findings, list), isinstance(new_findings, list))]

    def keyed(items):
        return {
            (str(item.get("source", "")), str(item.get("title", "")), str(item.get("resource", ""))): item
            for item in items if isinstance(item, dict)
        }

    old_map, new_map = keyed(old_findings), keyed(new_findings)
    changes = []
    for key in sorted(new_map.keys() - old_map.keys()):
        changes.append(_change("Exposure Observations", "NEW", f"New heuristic observation: {key[1]}", None, new_map[key]))
    for key in sorted(old_map.keys() - new_map.keys()):
        old = old_map[key]
        complete = _finding_source_complete(current, key[0])
        state = "RESOLVED" if complete else "UNKNOWN"
        changes.append(_change("Exposure Observations", state, f"Previously observed heuristic observation no longer returned: {key[1]}", old, None,
                               {"previous": old, "current_source_status": _status(_module(current, {"robots.txt": "robots", "sitemap.xml": "sitemap", "HTTP Header": "http", "HTML": "http"}.get(key[0], "")))},
                               "High" if complete else "Low"))
    for key in sorted(old_map.keys() & new_map.keys()):
        if old_map[key] == new_map[key]:
            changes.append(_change("Exposure Observations", "UNCHANGED", f"Heuristic observation unchanged: {key[1]}", old_map[key], new_map[key]))
        else:
            changes.append(_change("Exposure Observations", "CHANGED", f"Heuristic observation evidence changed: {key[1]}", old_map[key], new_map[key]))
    return changes or [_change("Exposure Observations", "UNCHANGED", "No heuristic observation changes", [], [])]


def _risk_evidence_complete(report: dict) -> tuple[bool, dict[str, str | None]]:
    risk = report.get("risk") if isinstance(report.get("risk"), dict) else {}
    statuses = {name: _status(_module(report, name)) for name in ("security_headers", "ssl", "http")}
    if risk.get("evidence_status") in {"complete", "incomplete"}:
        complete = risk["evidence_status"] == "complete"
    else:
        headers = _module(report, "security_headers").get("headers")
        required_headers = {"strict_transport_security", "content_security_policy", "x_frame_options"}
        http = _module(report, "http")
        ssl = _module(report, "ssl")
        try:
            valid_http = isinstance(http.get("status_code"), (str, int)) and 100 <= int(http["status_code"]) <= 599
        except (TypeError, ValueError):
            valid_http = False
        ssl_complete = statuses["ssl"] == "not_https"
        if statuses["ssl"] == "ok" and isinstance(ssl.get("expired"), bool):
            try:
                ssl_complete = ssl["expired"] or int(ssl.get("days_remaining")) >= 0
            except (TypeError, ValueError):
                ssl_complete = False
        complete = (
            statuses["security_headers"] == "ok"
            and isinstance(headers, dict)
            and required_headers.issubset(headers)
            and statuses["http"] == "ok"
            and valid_http
            and ssl_complete
        )
    return complete, statuses


def _compare_risk(previous: dict, current: dict) -> tuple[list[dict], dict]:
    old, new = previous.get("risk"), current.get("risk")
    old = old if isinstance(old, dict) else {}
    new = new if isinstance(new, dict) else {}
    before, after = old.get("overall_score"), new.get("overall_score")
    old_complete, old_statuses = _risk_evidence_complete(previous)
    new_complete, new_statuses = _risk_evidence_complete(current)
    if isinstance(before, int) and isinstance(after, int) and old_complete and new_complete:
        delta = after - before
        changes = [_change("Risk", "UNCHANGED" if delta == 0 else "CHANGED", "Overall risk score", before, after,
                           {"previous_score": before, "current_score": after, "delta": delta})]
    else:
        delta = None
        changes = [_unknown("Risk", "Risk score comparison is incomplete", old_statuses, new_statuses)]
    old_factors, new_factors = old.get("factors"), new.get("factors")
    if not old_complete or not new_complete:
        changes.append(_unknown("Risk", "Risk factors cannot be resolved from incomplete checks", old_statuses, new_statuses))
    elif not isinstance(old_factors, list) or not isinstance(new_factors, list):
        changes.append(_unknown("Risk", "Risk factor comparison is unavailable", "factors" in old, "factors" in new))
    else:
        old_map = {item.get("factor"): item for item in old_factors if isinstance(item, dict) and item.get("factor")}
        new_map = {item.get("factor"): item for item in new_factors if isinstance(item, dict) and item.get("factor")}
        for name in sorted(new_map.keys() - old_map.keys()):
            changes.append(_change("Risk", "NEW", f"Risk factor introduced: {name}", None, new_map[name]))
        for name in sorted(old_map.keys() - new_map.keys()):
            changes.append(_change("Risk", "RESOLVED", f"Risk factor resolved: {name}", old_map[name], None))
        for name in sorted(old_map.keys() & new_map.keys()):
            old_factor, new_factor = old_map[name], new_map[name]
            if old_factor != new_factor:
                changes.append(_change("Risk", "CHANGED", f"Risk factor changed: {name}", old_factor, new_factor))
    return changes, {
        "previous_score": before,
        "current_score": after,
        "previous_rating": old.get("overall_rating"),
        "current_rating": new.get("overall_rating"),
        "delta": delta,
        "evidence_status": "complete" if old_complete and new_complete else "incomplete",
    }


def compare_reports(previous: dict, current: dict, *, previous_id: int | None = None,
                    current_id: int | None = None, target: str | None = None,
                    previous_at: Any = None, current_at: Any = None) -> dict:
    """Compare observations while reserving removal/resolution for complete source data."""
    changes = []
    changes.extend(_compare_dns(previous, current))
    changes.extend(_compare_http(previous, current))
    changes.extend(_compare_tls(previous, current))
    changes.extend(_compare_technology(previous, current))
    changes.extend(_compare_exposure(previous, current))
    changes.extend(_compare_exposure_findings(previous, current))
    risk_changes, risk = _compare_risk(previous, current)
    changes.extend(risk_changes)
    counts = {kind.lower(): sum(1 for item in changes if item["change_type"] == kind) for kind in CHANGE_TYPES}
    return {
        "target": target or current.get("target") or previous.get("target"),
        "previous": {"id": previous_id, "timestamp": previous_at, "risk_score": risk["previous_score"]},
        "current": {"id": current_id, "timestamp": current_at, "risk_score": risk["current_score"]},
        "risk": risk,
        "summary": counts,
        "changes": changes,
    }
