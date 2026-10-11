"""
HTML-экспорт: читаемый отчёт, можно открыть в браузере и приложить к багрепорту.
"""
import html
import json
from datetime import datetime
from pathlib import Path

from core.storage import Storage
from reports.paths import report_directory, safe_path_component
from reports.summary import finding_summary

SEV_COLORS = {
    "critical": "#8b0000", "high": "#d9534f",
    "medium": "#f0ad4e", "low": "#5bc0de", "info": "#999",
    "unknown": "#666",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ru"><head>
<meta charset="utf-8">
<title>ShadowScope — {target}</title>
<style>
  body {{ font-family: -apple-system, system-ui, sans-serif; margin: 2rem; color: #222; }}
  h1 {{ border-bottom: 2px solid #333; padding-bottom: .3rem; }}
  .summary {{ display: flex; gap: 1rem; margin: 1rem 0; }}
  .card {{ padding: .8rem 1.2rem; background: #f5f5f5; border-radius: 6px; }}
  .card b {{ font-size: 1.6rem; display: block; }}
  .finding {{ border-left: 6px solid #ccc; padding: .8rem 1rem; margin: .6rem 0;
              background: #fafafa; border-radius: 4px; }}
  .sev {{ font-weight: bold; padding: 2px 8px; color: white; border-radius: 3px;
          font-size: .8rem; margin-right: .5rem; }}
  pre {{ background: #222; color: #eee; padding: 1rem; border-radius: 4px;
         overflow-x: auto; font-size: .85rem; }}
  table {{ border-collapse: collapse; width: 100%; margin: .5rem 0; }}
  th, td {{ border: 1px solid #ddd; padding: .4rem .6rem; text-align: left; }}
  th {{ background: #eee; }}
</style>
</head><body>
<h1>ShadowScope — {target}</h1>
<p>Дата: {date} · Scan ID: {scan_id}{prev_info} · Статус: {run_status} ·
Длительность: {run_duration}</p>

<div class="summary">
  <div class="card"><b>{total_assets}</b>активов</div>
  <div class="card"><b>{new_assets}</b>новых</div>
  <div class="card"><b>{total_findings}</b>находок</div>
  <div class="card"><b>{new_findings}</b>новых</div>
</div>

<h2>Находки</h2>
{severity_summary}
{findings_html}

<h2>Активы</h2>
<table><tr><th>Тип</th><th>Значение</th><th>First seen</th></tr>
{assets_rows}
</table>
</body></html>
"""


def export_html(target: str, scan_id: int, storage: Storage,
                diff: dict | None = None,
                scan_metadata: dict | None = None) -> Path:
    diff = diff or {}
    scan = scan_metadata or storage.scan_by_id(scan_id) or {}
    run_summary = (
        json.loads(scan["summary_json"])
        if scan.get("summary_json") else {}
    )
    assets = storage.assets_for(target)
    findings = storage.findings_for_scan(scan_id)
    finding_data = finding_summary(findings, diff)
    findings = finding_data["findings"]
    severity_summary = "<p>" + " · ".join(
        f"{html.escape(severity)}: {count}"
        for severity, count in finding_data["by_severity"].items()
        if count
    ) + "</p>"
    if not any(finding_data["by_severity"].values()):
        severity_summary = "<p>Находок нет.</p>"

    findings_html = ""
    if not findings:
        findings_html = "<p>Находок нет.</p>"
    for f in findings:
        sev = (f["severity"] or "unknown").lower()
        color = SEV_COLORS.get(sev, "#666")
        data = html.escape(f["data_json"] or "")[:2000]
        findings_html += (
            f'<div class="finding">'
            f'<span class="sev" style="background:{color}">{sev.upper()}</span>'
            f'<b>{html.escape(f["title"] or "")}</b>'
            f'<p>{html.escape(f["status"])}</p>'
            f'<p><strong>Рекомендация:</strong> '
            f'{html.escape(f["recommendation"])}</p>'
            f'<pre>{data}</pre></div>'
        )

    assets_rows = "".join(
        f"<tr><td>{html.escape(a['kind'])}</td>"
        f"<td>{html.escape(str(a['value']))}</td>"
        f"<td>{a['first_seen']}</td></tr>"
        for a in assets
    )

    prev_info = (f" · предыдущий: {diff['previous_scan_id']}"
                 if diff.get("previous_scan_id") else "")

    content = HTML_TEMPLATE.format(
        target=html.escape(target),
        date=datetime.now().strftime("%Y-%m-%d %H:%M"),
        scan_id=scan_id,
        prev_info=prev_info,
        run_status=html.escape(scan.get("status") or "unknown"),
        run_duration=html.escape(
            str(run_summary.get("duration_seconds", "не указана"))
        ),
        total_assets=len(assets),
        new_assets=diff.get("counts", {}).get("new_assets", 0),
        total_findings=len(findings),
        new_findings=diff.get("counts", {}).get("new_findings", 0),
        findings_html=findings_html,
        severity_summary=severity_summary,
        assets_rows=assets_rows,
    )

    output_dir = report_directory(target, f"scan_{scan_id}")
    out = output_dir / f"{safe_path_component(target)}.html"
    out.write_text(content, encoding="utf-8")
    return out