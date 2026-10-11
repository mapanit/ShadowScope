"""
Сравнение двух сканов одной цели.
Возвращает: новые / удалённые / сохранившиеся assets и findings.
"""
from datetime import datetime
from core.storage import Storage


def diff_scans(storage: Storage, target: str, current_scan_id: int) -> dict:
    prev_id = storage.previous_scan_id(target, current_scan_id)
    if prev_id is None:
        return {
            "first_scan": True,
            "previous_scan_id": None,
            "new_assets": [],
            "removed_assets": [],
            "new_findings": [],
            "counts": {
                "new_assets": 0,
                "removed_assets": 0,
                "new_findings": 0,
            },
        }

    # assets целиком по target_root, не по scan_id
    # (assets глобальны, у них first_seen/last_seen)
    prev_marker = storage.conn.execute(
        "SELECT started_at FROM scans WHERE id = ?", (prev_id,)
    ).fetchone()["started_at"]

    new_assets = [dict(r) for r in storage.conn.execute(
        "SELECT * FROM assets WHERE target_root = ? AND first_seen > ?",
        (target, prev_marker),
    ).fetchall()]

    removed_assets = [dict(r) for r in storage.conn.execute(
        "SELECT * FROM assets WHERE target_root = ? AND last_seen <= ? "
        "AND first_seen <= ?",
        (target, prev_marker, prev_marker),
    ).fetchall()]

    # Fingerprints contain scan_id, so compare the stable finding identity instead.
    prev_findings = {
        (r["kind"], r["title"], r["asset_id"])
        for r in storage.conn.execute(
            "SELECT kind, title, asset_id FROM findings WHERE scan_id = ?",
            (prev_id,),
        ).fetchall()
    }

    new_findings = [f for f in storage.findings_for_scan(current_scan_id)
                    if (f["kind"], f["title"], f["asset_id"]) not in prev_findings]

    return {
        "first_scan": False,
        "previous_scan_id": prev_id,
        "new_assets": new_assets,
        "removed_assets": removed_assets,
        "new_findings": new_findings,
        "counts": {
            "new_assets": len(new_assets),
            "removed_assets": len(removed_assets),
            "new_findings": len(new_findings),
        },
    }