"""
Генерация отчёта в Markdown для HackerOne / GitHub issue.
Использует Jinja2-шаблон, встроенный в код.
"""
import json
from datetime import datetime
from pathlib import Path

from jinja2 import Template

from reports.paths import report_directory, safe_path_component
from reports.summary import finding_summary

# Порядок severity для сортировки
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


def _severity_key(finding: dict) -> int:
    sev = str(finding.get("severity") or "unknown").lower()
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return len(SEVERITY_ORDER)


# Шаблон отчёта для HackerOne / GitHub issue.
MD_TEMPLATE = Template(
    """# ShadowScope report — {{ target }}

**Дата:** {{ date }}
**Scan ID:** {{ scan_id }}{% if previous_scan_id %} (предыдущий: {{ previous_scan_id }}){% endif %}
{% if run_status %}**Статус запуска:** {{ run_status }} · **Длительность:** {{ run_duration }} сек.
{% endif %}

## Сводка

| Метрика | Значение |
|---|---|
| Всего активов | {{ total_assets }} |
| Новых активов | {{ new_assets }} |
| Удалённых активов | {{ removed_assets }} |
| Находок | {{ total_findings }} |
| Новых находок | {{ new_findings }} |

{% if findings_by_severity %}
## Находки по severity

{% for sev, count in findings_by_severity.items() %}
- **{{ sev }}**: {{ count }}
{% endfor %}
{% endif %}
{% if findings %}
## Детали находок

{% for f in findings %}
### [{{ (f.severity or 'unknown')|upper }}] {{ f.title }}

**Статус:** {{ f.status }}  
**Рекомендация:** {{ f.recommendation }}

{% if f.data %}
```json
{{ f.data }}
```
{% endif %}
{% endfor %}
{% endif %}
{% if new_asset_list %}
## Новые активы

{% for a in new_asset_list %}
- **{{ a.kind }}:** {{ a.value }}
{% endfor %}
{% endif %}
{% if removed_asset_list %}
## Удалённые активы

{% for a in removed_asset_list %}
- **{{ a.kind }}:** {{ a.value }}
{% endfor %}
{% endif %}
"""
)


def render_markdown(target: str, scan_id: int, assets: list[dict],
                    findings: list[dict], diff: dict | None = None,
                    scan_metadata: dict | None = None) -> Path:
    diff = diff or {}
    counts = diff.get("counts") or {}
    new_asset_list = diff.get("new_assets") or []
    removed_asset_list = diff.get("removed_assets") or []

    report_findings = finding_summary(findings, diff)["findings"]
    findings_sorted = sorted(report_findings, key=_severity_key)
    findings_view = []
    for finding in findings_sorted:
        raw = finding.get("data_json") or finding.get("data")
        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                pretty = raw
            else:
                pretty = json.dumps(parsed, ensure_ascii=False, indent=2)
        elif raw is None:
            pretty = ""
        else:
            pretty = json.dumps(raw, ensure_ascii=False, indent=2)

        findings_view.append({
            "severity": str(finding.get("severity") or "unknown").lower(),
            "title": finding.get("title") or "(без названия)",
            "data": pretty,
            "status": finding.get("status", "unknown"),
            "recommendation": finding.get("recommendation", ""),
        })

    severity_counts = {}
    for finding in findings_view:
        severity = finding["severity"]
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    content = MD_TEMPLATE.render(
        target=target,
        date=datetime.now().strftime("%Y-%m-%d %H:%M"),
        scan_id=scan_id,
        previous_scan_id=diff.get("previous_scan_id"),
        run_status=(scan_metadata or {}).get("status"),
        run_duration=json.loads(
            (scan_metadata or {}).get("summary_json") or "{}"
        ).get("duration_seconds", "не указана"),
        total_assets=len(assets),
        new_assets=counts.get("new_assets", len(new_asset_list)),
        removed_assets=counts.get("removed_assets", len(removed_asset_list)),
        total_findings=len(findings_view),
        new_findings=counts.get(
            "new_findings", len(diff.get("new_findings") or [])
        ),
        findings_by_severity=severity_counts,
        findings=findings_view,
        new_asset_list=new_asset_list,
        removed_asset_list=removed_asset_list,
    )

    output_dir = report_directory(target, f"scan_{scan_id}")
    out = output_dir / f"{safe_path_component(target)}.md"
    out.write_text(content, encoding="utf-8")
    return out
