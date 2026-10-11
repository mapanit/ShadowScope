"""
dnsx (projectdiscovery) — быстрый массовый DNS-резолв.
Вход: список домена/поддоменов (stdin).
Выход: живые A/AAAA/CNAME + wildcard-детект.
"""
from utils.shell import run_tool, lines, ToolNotInstalled, ToolTimeout


class DnsxScanner:
    def __init__(self, rate_limit: int = 10):
        self.rate_limit = rate_limit

    def resolve(self, hosts: list[str], wildcard: bool = True) -> dict:
        if not hosts:
            return {"resolved": [], "wildcards": []}
        try:
            cmd = ["dnsx", "-silent", "-a", "-resp", "-rl", str(self.rate_limit)]
            if wildcard:
                cmd += ["-wd", "example.com"]  # -wd принимает домен-родитель
            stdout, stderr = run_tool(
                cmd, timeout=180, input_text="\n".join(hosts),
            )
            return {
                "resolved": lines(stdout),
                "stderr": stderr.strip() or None,
            }
        except ToolNotInstalled as e:
            return {"error": str(e)}
        except ToolTimeout as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"dnsx failed: {e}"}