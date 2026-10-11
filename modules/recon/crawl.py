"""
Katana и gospider — краулинг URL и JS-файлов.
Katana — на Go, gospider — тоже. Оба через subprocess.
"""
import ipaddress
import math
import re

from core.scope import ScopePolicy
from utils.shell import run_tool, lines, ToolNotInstalled, ToolTimeout


class Crawler:
    def __init__(self, rate_limit: int = 10, scope: ScopePolicy | None = None,
                 headers: dict[str, str] | None = None):
        self.rate_limit = rate_limit
        self.scope = scope
        self.headers = headers or {}

    def _scope_regex(self) -> str | None:
        if not self.scope:
            return None

        host_patterns = []
        for root in self.scope.allowed_roots:
            try:
                address = ipaddress.ip_address(root)
            except ValueError:
                host_patterns.append(r"(?:[a-z0-9-]+\.)*" + re.escape(root))
            else:
                escaped = re.escape(root)
                host_patterns.append(
                    rf"\[{escaped}\]" if address.version == 6 else escaped
                )
        return (
            r"(?i)://(?:[^/@]*@)?(?:"
            + "|".join(host_patterns)
            + r")(?::[0-9]+)?(?:[/?#]|$)"
        )

    def katana(self, url: str, depth: int = 3) -> dict:
        try:
            cmd = [
                "katana", "-silent", "-u", url,
                "-d", str(depth), "-jc",          # -jc: парсить JS
                "-kf", "all",                     # все известные расширения
                "-dr",                            # не ходить по редиректам
                "-rl", str(self.rate_limit),
            ]
            scope_regex = self._scope_regex()
            if scope_regex:
                cmd += ["-cs", scope_regex]
            for name, value in self.headers.items():
                cmd.extend(["-H", f"{name}: {value}"])
            stdout, _ = run_tool(cmd, timeout=300)
            return {"urls": sorted(set(lines(stdout)))}
        except ToolNotInstalled as e:
            return {"error": str(e)}
        except ToolTimeout as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"katana failed: {e}"}

    def gospider(self, url: str, depth: int = 3) -> dict:
        try:
            cmd = [
                "gospider", "-s", url,
                "-d", str(depth), "-q",           # тихий режим
                "--no-redirect",
                "--js",                            # собирать JS
                "-t", "1",
                "-k", str(max(1, math.ceil(1 / self.rate_limit))),
            ]
            scope_regex = self._scope_regex()
            if scope_regex:
                cmd += ["--whitelist", scope_regex]
            for name, value in self.headers.items():
                cmd.extend(["-H", f"{name}: {value}"])
            stdout, _ = run_tool(cmd, timeout=300)
            urls = set()
            for line in stdout.splitlines():
                # gospider формат: "[url] - [code] - [size] - [href]"
                parts = line.split(" - ")
                if len(parts) >= 4:
                    urls.add(parts[-1].strip())
            return {"urls": sorted(urls)}
        except ToolNotInstalled as e:
            return {"error": str(e)}
        except ToolTimeout as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"gospider failed: {e}"}

    def crawl(self, url: str, depth: int = 3) -> dict:
        k = self.katana(url, depth)
        g = self.gospider(url, depth)
        merged = set()
        errors = []
        for r in (k, g):
            if "urls" in r:
                merged.update(r["urls"])
            if "error" in r:
                errors.append(r["error"])
        out_of_scope_count = 0
        if self.scope:
            allowed, rejected = self.scope.filter(sorted(merged))
            merged = set(allowed)
            out_of_scope_count = len(rejected)
        return {
            "urls": sorted(merged),
            "count": len(merged),
            "errors": errors,
            "out_of_scope_count": out_of_scope_count,
        }