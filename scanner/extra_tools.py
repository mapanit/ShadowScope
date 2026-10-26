"""Optional TLS and screenshot integrations backed by external CLI tools."""
import json
import time
from urllib.parse import urlsplit

from core.scope import ScopePolicy
from reports.paths import report_directory
from utils.shell import run_tool


def _target_parts(target: str, scope: ScopePolicy | None):
    normalized = target if "://" in target else f"http://{target}"
    parsed = urlsplit(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"Некорректная цель: {target}")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if scope:
        scope.require(normalized)
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    return normalized, host, port


class TLSXScanner:
    def __init__(self, scope: ScopePolicy | None = None):
        self.scope = scope

    def scan(self, target: str) -> dict:
        normalized, host, port = _target_parts(target, self.scope)
        stdout, stderr = run_tool(
            [
                "tlsx", "-u", host, "-p", str(port),
                "-timeout", "5", "-retry", "0", "-concurrency", "1",
                "-json", "-silent", "-disable-update-check",
            ],
            timeout=30,
        )
        records = []
        for line in stdout.splitlines():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                records.append({"raw": line})
        return {
            "target": normalized,
            "records": records,
            "message": "TLS-ответ не получен" if not records else "",
            "stderr": stderr.strip(),
        }


class TestSSLScanner:
    def __init__(self, scope: ScopePolicy | None = None):
        self.scope = scope

    def scan(self, target: str) -> dict:
        normalized, host, port = _target_parts(target, self.scope)
        stdout, stderr = run_tool(
            [
                "testssl.sh", "--quiet", "--warnings", "off",
                f"{host}:{port}",
            ],
            timeout=300,
        )
        output = "\n".join(part for part in (stdout, stderr) if part).strip()
        status = (
            "not-tls" if "doesn't seem to be a TLS/SSL enabled server" in output
            else "completed"
        )
        return {
            "target": normalized,
            "status": status,
            "output": output,
        }


class GowitnessScanner:
    def __init__(
        self,
        scope: ScopePolicy | None = None,
        headers: dict[str, str] | None = None,
    ):
        self.scope = scope
        self.headers = headers or {}

    def scan(self, target: str) -> dict:
        normalized, _, _ = _target_parts(target, self.scope)
        output_dir = report_directory(
            normalized, f"gowitness-{time.time_ns()}"
        )
        command = [
            "gowitness", "scan", "single",
            "--url", normalized,
            "--screenshot-path", str(output_dir),
            "--write-none",
            "--delay", "1",
            "--timeout", "30",
        ]
        for name, value in self.headers.items():
            command.extend(["--chrome-header", f"{name}: {value}"])
        stdout, stderr = run_tool(command, timeout=60)
        screenshots = sorted(
            str(path) for path in output_dir.iterdir()
            if path.is_file()
        )
        return {
            "target": normalized,
            "screenshot_directory": str(output_dir),
            "screenshots": screenshots,
            "stdout": stdout.strip(),
            "stderr": stderr.strip(),
        }
