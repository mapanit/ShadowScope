"""
waybackurls + gau — исторические URL из Wayback Machine, Common Crawl,
OTX, URLScan. Собираем и дедуплицируем.
"""
from utils.shell import run_tool, lines, ToolNotInstalled, ToolTimeout


class WaybackScanner:
    def collect(self, domain: str) -> dict:
        urls = set()
        errors = []

        # --- gau ---
        try:
            stdout, stderr = run_tool(
                ["gau", "--threads", "5", "--subs", domain],
                timeout=180,
            )
            urls.update(lines(stdout))
        except ToolNotInstalled as e:
            errors.append(f"gau: {e}")
        except ToolTimeout as e:
            errors.append(f"gau: {e}")
        except Exception as e:
            errors.append(f"gau: {e}")

        # --- waybackurls ---
        try:
            stdout, stderr = run_tool(
                ["waybackurls", domain], timeout=180, input_text=domain,
            )
            urls.update(lines(stdout))
        except ToolNotInstalled as e:
            errors.append(f"waybackurls: {e}")
        except ToolTimeout as e:
            errors.append(f"waybackurls: {e}")
        except Exception as e:
            errors.append(f"waybackurls: {e}")

        return {"urls": sorted(urls), "count": len(urls), "errors": errors}