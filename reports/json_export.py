"""
JSON-экспорт: машинночитаемый формат для интеграции с H1/Bugcrowd.
"""
import json
from datetime import datetime
from pathlib import Path

from core.storage import Storage
from reports.paths import report_directory, safe_path_component
from reports.summary import finding_summary


def export_json(target: str, scan_id: int, storage: Storage,
                diff: dict | None = None,
                scan_metadata: dict | None = None) -> Path:
    scan = scan_metadata or storage.scan_by_id(scan_id) or {}
    findings = storage.findings_for_scan(scan_id)
    assets = storage.assets_for(target)
    finding_data = finding_summary(findings, diff)

    payload = {
        "tool": "shadowscope",
        "version": "2.0",
        "generated_at": datetime.utcnow().isoformat(),
        "target": target,
        "scan_id": scan_id,
        "scan_status": scan.get("status"),
        "run_summary": (
            json.loads(scan["summary_json"])
            if scan.get("summary_json") else None
        ),
        "previous_scan_id": (diff or {}).get("previous_scan_id"),
        "summary": {
            "assets": len(assets),
            "findings": len(findings),
            "findings_by_severity": finding_data["by_severity"],
            "new_assets": (diff or {}).get("counts", {}).get("new_assets", 0),
            "new_findings": (diff or {}).get("counts", {}).get("new_findings", 0),
        },
        "assets": [
            {"kind": a["kind"], "value": a["value"],
             "first_seen": a["first_seen"], "last_seen": a["last_seen"]}
            for a in assets
        ],
        "findings": [
            {
                "kind": f["kind"],
                "severity": f["severity"],
                "title": f["title"],
                "data": json.loads(f["data_json"]) if f["data_json"] else None,
                "created_at": f["created_at"],
                "status": finding_data["findings"][index]["status"],
                "recommendation": finding_data["findings"][index]["recommendation"],
            }
            for index, f in enumerate(findings)
        ],
        "diff": {
            "new_assets": (diff or {}).get("new_assets", []),
            "removed_assets": (diff or {}).get("removed_assets", []),
            "new_findings_count": (diff or {}).get("counts", {}).get("new_findings", 0),
        },
    }

    output_dir = report_directory(target, f"scan_{scan_id}")
    out = output_dir / f"{safe_path_component(target)}.json"
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                   encoding="utf-8")
    return out