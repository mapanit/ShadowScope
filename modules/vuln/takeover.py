"""
Поиск subdomain takeover.
subjack — быстрый, по сигнатурам сервисов.
nuclei -t takeovers/ — более глубокий, по актуальным шаблонам.
"""
from utils.shell import run_tool, lines, ToolNotInstalled, ToolTimeout


class TakeoverScanner:
    def __init__(self, rate_limit: int = 25,
                 headers: dict[str, str] | None = None):
        self.rate_limit = rate_limit
        self.headers = headers or {}

    def subjack(self, subdomains: list[str], domain: str) -> dict:
        if not subdomains:
            return {"vulnerable": [], "count": 0}
        try:
            # subjack читает список из stdin, -a — включить all-fingerprints
            cmd = ["subjack", "-w", "/dev/stdin", "-t", "20",
                   "-timeout", "30", "-ssl", "-a", "-v"]
            stdout, stderr = run_tool(
                cmd, timeout=300, input_text="\n".join(subdomains),
            )
            # строки со "[Not Vulnerable]" отбрасываем
            hits = [
                l for l in lines(stdout)
                if "Vulnerable" in l and "Not Vulnerable" not in l
            ]
            return {"vulnerable": hits, "count": len(hits),
                    "stderr": stderr.strip() or None}
        except ToolNotInstalled as e:
            return {"error": str(e)}
        except ToolTimeout as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"subjack failed: {e}"}

    def nuclei_takeovers(self, subdomains: list[str],
                         rate_limit: int | None = None) -> dict:
        if not subdomains:
            return {"vulnerable": [], "count": 0}
        try:
            cmd = [
                "nuclei",
                "-t", "http/takeovers/",
                "-rl", str(self.rate_limit if rate_limit is None else rate_limit),
                "-dr",
                "-jsonl", "-silent", "-no-color",
                "-timeout", "10", "-retries", "1",
            ]
            for name, value in self.headers.items():
                cmd.extend(["-H", f"{name}: {value}"])
            stdout, _ = run_tool(
                cmd, timeout=600, input_text="\n".join(subdomains),
            )
            import json
            results = []
            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return {"vulnerable": results, "count": len(results)}
        except ToolNotInstalled as e:
            return {"error": str(e)}
        except ToolTimeout as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"nuclei takeover failed: {e}"}

    def scan(self, subdomains: list[str], domain: str) -> dict:
        s = self.subjack(subdomains, domain)
        n = self.nuclei_takeovers(subdomains)
        return {"subjack": s, "nuclei": n}