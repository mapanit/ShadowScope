"""Generate Markdown, HTML, and JSON reports directly from scan logs."""
import ast
import html
import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from reports.paths import report_directory, safe_path_component

LOG_LINE = re.compile(
    r"^(?P<timestamp>\S+ \S+) - (?P<level>[A-Z]+) - (?P<message>.*)$"
)
SECTION_LINE = re.compile(r"^(?P<section>[^:]+):\s*(?P<data>.*)$")


def _parse_data(raw: str):
    try:
        return ast.literal_eval(raw)
    except (ValueError, SyntaxError):
        return raw


def parse_log(log_path: Path) -> list[dict]:
    """Parse ShadowScope log records while preserving unrecognized lines."""
    entries = []
    for line_number, line in enumerate(
        log_path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
    ):
        match = LOG_LINE.match(line)
        if not match:
            entries.append({
                "timestamp": None,
                "level": "UNKNOWN",
                "section": "Unparsed log line",
                "data": line,
                "line": line_number,
            })
            continue

        message_match = SECTION_LINE.match(match.group("message"))
        if message_match:
            section = message_match.group("section")
            data = _parse_data(message_match.group("data"))
        else:
            section = "Log message"
            data = _parse_data(match.group("message"))

        entries.append({
            "timestamp": match.group("timestamp"),
            "level": match.group("level"),
            "section": section,
            "data": data,
        })
    return entries


def _walk_values(value, parent_key=""):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk_values(child, str(key).lower())
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _walk_values(child, parent_key)
    elif isinstance(value, str):
        yield parent_key, value


def _infer_target(entries: list[dict], log_path: Path) -> str:
    for entry in entries:
        for key, value in _walk_values(entry["data"]):
            if key in {"target", "domain", "hostname"} and value.strip():
                return value.strip()

    for entry in entries:
        for _, value in _walk_values(entry["data"]):
            if value.startswith(("http://", "https://")):
                parsed = urlsplit(value)
                if parsed.netloc:
                    return parsed.netloc

    return log_path.stem


def _render_value(value) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, indent=2, default=str)


def generate_reports_from_log(log_path: Path) -> dict[str, Path]:
    """Parse a scan log and write equivalent Markdown, HTML, and JSON reports."""
    log_path = Path(log_path)
    if not log_path.is_file():
        raise FileNotFoundError(f"Файл лога не найден: {log_path}")

    entries = parse_log(log_path)
    target = _infer_target(entries, log_path)
    generated_at = datetime.now().astimezone().isoformat(timespec="seconds")
    errors = sum(entry["level"] == "ERROR" for entry in entries)
    payload = {
        "tool": "shadowscope",
        "version": "2.0",
        "source_log": log_path.name,
        "generated_at": generated_at,
        "target": target,
        "summary": {
            "records": len(entries),
            "sections": len({entry["section"] for entry in entries}),
            "errors": errors,
        },
        "entries": entries,
    }

    output_dir = report_directory(target, log_path.stem)
    json_path = output_dir / f"{safe_path_component(target)}.json"
    markdown_path = output_dir / f"{safe_path_component(target)}.md"
    html_path = output_dir / f"{safe_path_component(target)}.html"

    json_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )

    markdown = [
        f"# ShadowScope — отчёт по сканированию {target}",
        "",
        f"**Лог:** `{log_path.name}`  ",
        f"**Сформирован:** {generated_at}  ",
        f"**Записей:** {len(entries)} · **Разделов:** "
        f"{payload['summary']['sections']} · **Ошибок:** {errors}",
        "",
    ]
    for entry in entries:
        timestamp = f" — {entry['timestamp']}" if entry["timestamp"] else ""
        markdown.extend([
            f"## {entry['section']}{timestamp}",
            "",
            f"Уровень: `{entry['level']}`",
            "",
            "```text",
            _render_value(entry["data"]),
            "```",
            "",
        ])
    markdown_path.write_text("\n".join(markdown), encoding="utf-8")

    html_entries = []
    for entry in entries:
        timestamp = html.escape(entry["timestamp"] or "")
        level = html.escape(entry["level"])
        section = html.escape(entry["section"])
        data = html.escape(_render_value(entry["data"]))
        html_entries.append(
            f"<article><h2>{section}</h2><p>{timestamp} "
            f"<strong>{level}</strong></p><pre>{data}</pre></article>"
        )
    html_content = f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ShadowScope — {html.escape(target)}</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 1000px; margin: 2rem auto; padding: 0 1rem; color: #222; }}
article {{ border: 1px solid #ddd; border-radius: 6px; margin: 1rem 0; padding: 1rem; }}
pre {{ white-space: pre-wrap; overflow-wrap: anywhere; background: #f5f5f5; padding: 1rem; }}
</style></head><body>
<h1>ShadowScope — {html.escape(target)}</h1>
<p>Лог: {html.escape(log_path.name)} · Сформирован: {html.escape(generated_at)}</p>
<p>Записей: {len(entries)} · Разделов: {payload['summary']['sections']} · Ошибок: {errors}</p>
{''.join(html_entries)}
</body></html>"""
    html_path.write_text(html_content, encoding="utf-8")

    return {"markdown": markdown_path, "json": json_path, "html": html_path}
