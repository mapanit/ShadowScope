"""
ffuf — быстрый фаззер директорий/файлов/параметров.
Аналог gobuster, но гибче: несколько режимов.
"""
import json
import shutil
from pathlib import Path

from utils.shell import run_tool, ToolNotInstalled, ToolTimeout

DEFAULT_WORDLIST = "~/usr/share/wordlists/dirb/common.txt"
ALT_WORDLISTS = [
    "~/usr/share/seclists/Discovery/Web-Content/common.txt",
    "~/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
]


def _pick_wordlist(user_path: str | None) -> str | None:
    if user_path and Path(user_path).exists():
        return user_path
    for p in [DEFAULT_WORDLIST, *ALT_WORDLISTS]:
        if Path(p).exists():
            return p
    return None


class FfufScanner:
    def __init__(self, rate_limit: int = 50, threads: int = 40,
                 headers: dict[str, str] | None = None):
        self.rate_limit = rate_limit
        self.threads = threads
        self.headers = headers or {}

    def fuzz_dirs(self, url: str, wordlist: str | None = None) -> dict:
        wl = _pick_wordlist(wordlist)
        if wl is None:
            return {"error": "Словарь не найден. Укажи wordlist явно."}

        try:
            cmd = [
                "ffuf", "-u", f"{url.rstrip('/')}/FUZZ",
                "-w", wl,
                "-mc", "200,204,301,302,307,401,403,405",  # только интересные коды
                "-rate", str(self.rate_limit),
                "-t", str(self.threads),
                "-of", "json",
                "-o", "/dev/stdout",
                "-s",   # silent
            ]
            for name, value in self.headers.items():
                cmd.extend(["-H", f"{name}: {value}"])
            stdout, _ = run_tool(cmd, timeout=300)
            try:
                data = json.loads(stdout)
            except json.JSONDecodeError:
                return {"error": "ffuf: не удалось распарсить JSON", "raw": stdout[:500]}

            results = []
            for r in data.get("results", []):
                results.append({
                    "url": r.get("url"),
                    "status": r.get("status"),
                    "length": r.get("length"),
                    "words": r.get("words"),
                    "lines": r.get("lines"),
                })
            return {"found": results, "count": len(results), "wordlist": wl}
        except ToolNotInstalled as e:
            return {"error": str(e)}
        except ToolTimeout as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"ffuf failed: {e}"}