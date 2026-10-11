"""
httpx (projectdiscovery) — батч-проверка живых хостов.
Даёт: статус-код, title, tech-detect, CDN, заголовки.
JSON-вывод парсим построчно (по одному JSON на хост).
"""
import json

from utils.shell import run_tool, lines, ToolNotInstalled, ToolTimeout


class HttpxProbe:
    def __init__(self, rate_limit: int = 50, timeout: int = 5, threads: int = 25,
                 headers: dict[str, str] | None = None):
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.threads = threads
        self.headers = headers or {}

    def probe(self, hosts: list[str]) -> dict:
        if not hosts:
            return {"live": [], "count": 0}
        try:
            cmd = [
                "httpx",
                "-silent", "-json",
                "-rl", str(self.rate_limit),
                "-threads", str(self.threads),
                "-timeout", str(self.timeout),
                "-status-code", "-title", "-tech-detect",
                "-web-server", "-cdn",
            ]
            for name, value in self.headers.items():
                cmd.extend(["-H", f"{name}: {value}"])
            stdout, stderr = run_tool(
                cmd, timeout=300, input_text="\n".join(hosts),
            )

            results = []
            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

            return {
                "live": results,
                "count": len(results),
                "stderr": stderr.strip() or None,
            }
        except ToolNotInstalled as e:
            return {"error": str(e)}
        except ToolTimeout as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"httpx failed: {e}"}