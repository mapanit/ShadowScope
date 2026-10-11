"""Shared finding summaries and contextual annotations for report formats."""
import json

SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")


def finding_summary(findings: list[dict], diff: dict | None = None) -> dict:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        severity = str(finding.get("severity") or "unknown").lower()
        counts[severity if severity in counts else "unknown"] += 1

    new_items = (diff or {}).get("new_findings") or []
    new_keys = {
        (item.get("kind"), item.get("title"), item.get("asset_id"))
        for item in new_items
    }
    is_first_scan = bool((diff or {}).get("first_scan"))
    annotated = []
    for finding in findings:
        item = dict(finding)
        item["status"] = (
            "baseline" if is_first_scan
            else "new"
            if (item.get("kind"), item.get("title"), item.get("asset_id")) in new_keys
            else "previously observed"
        )
        item["recommendation"] = _recommendation(item)
        annotated.append(item)
    return {"by_severity": counts, "findings": annotated}


def _recommendation(finding: dict) -> str:
    raw = finding.get("data_json") or finding.get("data")
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError:
        data = None

    if isinstance(data, dict):
        info = data.get("info")
        if isinstance(info, dict):
            remediation = info.get("remediation")
            if remediation:
                return str(remediation)
    return "Проверьте находку вручную и устраните первопричину согласно документации компонента."
