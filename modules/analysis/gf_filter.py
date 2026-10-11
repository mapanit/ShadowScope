"""
Фильтрация URL по установленным gf-паттернам.
"""
from utils.shell import ToolNotInstalled, ToolTimeout, lines, run_tool

GF_PATTERNS = (
    "xss",
    "sqli",
    "ssrf",
    "lfi",
    "rce",
    "redirect",
    "idor",
    "debug_logic",
)


class GfFilter:
    def filter(self, urls: list[str]) -> dict:
        filtered = {pattern: [] for pattern in GF_PATTERNS}
        errors = []
        input_text = "\n".join(urls)

        if not urls:
            return {"filtered": filtered, "summary": {}, "errors": errors}

        for pattern in GF_PATTERNS:
            try:
                stdout, stderr = run_tool(
                    ["gf", pattern],
                    timeout=60,
                    input_text=input_text,
                )
            except ToolNotInstalled as exc:
                errors.append(str(exc))
                break
            except ToolTimeout as exc:
                errors.append(f"{pattern}: {exc}")
                continue

            filtered[pattern] = lines(stdout)
            if stderr.strip():
                errors.append(f"{pattern}: {stderr.strip()}")

        summary = {
            pattern: len(matches)
            for pattern, matches in filtered.items()
        }
        return {"filtered": filtered, "summary": summary, "errors": errors}