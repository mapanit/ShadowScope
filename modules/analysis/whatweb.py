"""
whatweb — Ruby-инструмент, определяет CMS/фреймворки/серверы по
3000+ сигнатурам. Парсим JSON-вывод.
"""
import json

from utils.shell import run_tool, ToolNotInstalled, ToolTimeout


class WhatWebScanner:
    def __init__(self, aggression: int = 1,
                 headers: dict[str, str] | None = None):
        # aggression: 1 (stealth) / 3 (aggressive) / 4 (heavy)
        self.aggression = aggression
        self.headers = headers or {}

    def scan(self, url: str) -> dict:
        try:
            cmd = [
                "whatweb", "--log-json=-",       # JSON в stdout
                f"--aggression={self.aggression}",
                "--follow-redirect=never",
                url,
            ]
            for name, value in self.headers.items():
                cmd.insert(-1, f"--header={name}: {value}")
            stdout, stderr = run_tool(cmd, timeout=60)

            findings = []
            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return {"target": url, "results": findings}
        except ToolNotInstalled as e:
            return {"error": str(e)}
        except ToolTimeout as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"whatweb failed: {e}"}