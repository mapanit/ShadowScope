import shutil
import subprocess
import re
import asyncio
import requests
import aiohttp
from urllib.parse import urljoin

from config import Config
from core.scope import ScopePolicy
from utils.rate_limiter import AsyncRateLimiter

try:
    from wappalyzer import analyze as wappalyzer_analyze
    _WAPPALYZER_AVAILABLE = True
except ImportError:
    _WAPPALYZER_AVAILABLE = False


class ServerVersionScanner:
    def __init__(self, rate_limit: int = 10):
        self.rate_limit = rate_limit

    def scan_with_nmap(self, target):
        if shutil.which("nmap") is None:
            return {"error": "nmap не установлен"}
        try:
            result = subprocess.run(
                ["nmap", "-sV", "-Pn",
                 "--scan-delay", f"{1 / self.rate_limit:.3f}s",
                 "--script", "http-title,http-headers",
                 "-p", "80,443,5012,8000,8080",
                 target],
                capture_output=True, text=True, timeout=90, check=True,
            )
            return {"raw_output": result.stdout.strip()}
        except subprocess.CalledProcessError as e:
            return {"error": f"Nmap завершился с ошибкой: {e.stderr.strip()}"}
        except subprocess.TimeoutExpired:
            return {"error": "Nmap: превышен таймаут сканирования"}
        except Exception as e:
            return {"error": f"Nmap scan failed: {e}"}


class WappalyzerScanner:
    def __init__(self, config: Config = None):
        self.config = config or Config()

    def detect_technologies(self, url):
        result = {"wappalyzer": None, "headers": {}, "signatures": []}

        # 1) Wappalyzer Next
        if _WAPPALYZER_AVAILABLE:
            try:
                raw = wappalyzer_analyze(url, scan_type='fast')
                result["wappalyzer"] = [
                    {"name": n, "versions": i.get("versions", []),
                     "categories": i.get("categories", [])}
                    for n, i in raw.items()
                    if not n.startswith(("http://", "https://"))
                ]
            except Exception as e:
                result["wappalyzer"] = {"error": str(e)}

        # 2) Свои сигнатуры из заголовков
        try:
            r = requests.get(
                url, timeout=self.config.get_timeout,
                allow_redirects=False, headers=self.config.get_http_headers,
            )
            result["headers"] = dict(r.headers)

            server = r.headers.get("Server", "")
            powered = r.headers.get("X-Powered-By", "")
            if server:
                result["signatures"].append(f"Server: {server}")
            if powered:
                result["signatures"].append(f"X-Powered-By: {powered}")

            # 3) Сигнатуры в HTML (фреймворки, JS-библиотеки)
            html = r.text[:50000]
            patterns = {
                "Django":     r"csrfmiddlewaretoken|__admin_media_prefix__",
                "Flask":      r"werkzeug|flask",
                "Laravel":    r"laravel_session|XSRF-TOKEN",
                "WordPress":  r"wp-content|wp-includes",
                "React":      r"react(?:\.min)?\.js|__REACT",
                "Vue":        r"vue(?:\.min)?\.js|__VUE",
                "jQuery":     r"jquery(?:\.min)?\.js",
                "Bootstrap":  r"bootstrap(?:\.min)?\.(?:css|js)",
            }
            for tech, pat in patterns.items():
                if re.search(pat, html, re.IGNORECASE):
                    result["signatures"].append(f"HTML signature: {tech}")
        except Exception as e:
            result["headers_error"] = str(e)

        return result

    async def detect_technologies_async(
        self, url: str, rate_limiter: AsyncRateLimiter,
        scope: ScopePolicy | None = None,
    ) -> dict:
        result = {"wappalyzer": None, "headers": {}, "signatures": []}
        timeout = aiohttp.ClientTimeout(total=self.config.get_timeout)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                current_url = url
                response = None
                for _ in range(6):
                    if scope:
                        scope.require(current_url)
                    await rate_limiter.acquire()
                    response = await session.get(
                        current_url,
                        headers=self.config.get_http_headers,
                        allow_redirects=False,
                    )
                    if response.status not in {301, 302, 303, 307, 308}:
                        break
                    location = response.headers.get("Location")
                    if not location:
                        break
                    next_url = urljoin(current_url, location)
                    if not next_url.startswith(("http://", "https://")):
                        break
                    if scope and not scope.allows(next_url):
                        result["redirect_error"] = (
                            f"Редирект за пределы разрешённой области не выполнен: "
                            f"{next_url}"
                        )
                        break
                    current_url = next_url

                if response is None:
                    raise RuntimeError("HTTP-запрос не был выполнен")
                result["headers"] = dict(response.headers)
                page = await response.text(errors="replace")

            server = result["headers"].get("Server", "")
            powered = result["headers"].get("X-Powered-By", "")
            if server:
                result["signatures"].append(f"Server: {server}")
            if powered:
                result["signatures"].append(f"X-Powered-By: {powered}")

            patterns = {
                "Django": r"csrfmiddlewaretoken|__admin_media_prefix__",
                "Flask": r"werkzeug|flask",
                "Laravel": r"laravel_session|XSRF-TOKEN",
                "WordPress": r"wp-content|wp-includes",
                "React": r"react(?:\.min)?\.js|__REACT",
                "Vue": r"vue(?:\.min)?\.js|__VUE",
                "jQuery": r"jquery(?:\.min)?\.js",
                "Bootstrap": r"bootstrap(?:\.min)?\.(?:css|js)",
            }
            for tech, pattern in patterns.items():
                if re.search(pattern, page[:50000], re.IGNORECASE):
                    result["signatures"].append(f"HTML signature: {tech}")
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
            result["headers_error"] = str(exc)
        return result