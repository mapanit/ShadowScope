"""
nuclei с поддержкой кастомных шаблонов из data/templates/.
"""
import json
import shutil
from pathlib import Path

from config import Config
from utils.shell import run_tool, ToolNotInstalled, ToolTimeout

CUSTOM_TPL_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "templates"


class NucleiScanner:
    def __init__(self, config: Config = None):
        self.config = config or Config()

    def scan(self, target: str, templates: str | None = None,
             use_custom: bool = True) -> dict:
        url = target if target.startswith(("http://", "https://")) else f"http://{target}"

        cmd = [
            "nuclei", "-u", url,
            "-rl", str(self.config.get_nuclei_rate_limit),
            "-c", str(self.config.get_max_concurrent_tasks),
            "-severity", self.config.get_nuclei_severity,
            "-timeout", "10", "-retries", "1",
            "-jsonl", "-silent", "-no-color", "-disable-redirects",
        ]
        for name, value in self.config.get_http_headers.items():
            cmd.extend(["-H", f"{name}: {value}"])

        # кастомные шаблоны
        if use_custom and CUSTOM_TPL_DIR.exists() and any(CUSTOM_TPL_DIR.iterdir()):
            cmd += ["-t", str(CUSTOM_TPL_DIR)]

        # явные шаблоны из аргумента
        tpl = templates if templates is not None else self.config.get_nuclei_templates
        if tpl:
            cmd += ["-t", tpl]

        try:
            stdout, _ = run_tool(cmd, timeout=1800)
            findings = []
            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

            summary = {}
            for f in findings:
                sev = f.get("info", {}).get("severity", "unknown")
                summary[sev] = summary.get(sev, 0) + 1

            return {"target": url, "total": len(findings),
                    "by_severity": summary, "findings": findings}
        except ToolNotInstalled as e:
            return {"error": str(e)}
        except ToolTimeout as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"nuclei scan failed: {e}"}

    def update_templates(self):
        try:
            run_tool(["nuclei", "-update-templates", "-silent"], timeout=300)
            return {"status": "ok"}
        except Exception as e:
            return {"error": str(e)}