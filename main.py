import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

from config import Config
from logger import Logger
from utils.async_utils import AsyncTaskManager

# старые модули
from scanner.passive import WHOISScanner, DNSScanner, extract_domain
from scanner.subdomain_scanner import SubdomainScanner
from scanner.server_version import ServerVersionScanner, WappalyzerScanner
from scanner.file_scan import FileScanner
from scanner.network_traffic import NetworkTrafficScanner, TrafficCaptureScanner
from scanner.api_docs import ApiDocsScanner
from scanner.extra_tools import GowitnessScanner, TestSSLScanner, TLSXScanner

# новый nuclei (единый)
from modules.vuln.nuclei_scan import NucleiScanner

# новый pipeline
from core.pipeline import Pipeline
from core.scope import ScopePolicy
from core.storage import Storage
from core.diff import diff_scans
from reports.html import export_html
from reports.json_export import export_json
from reports.markdown import render_markdown


class ShadowScope:
    """
    Классические одиночные режимы + точка входа в pipeline.
    """
    MODES = {
        "passive":         "passive_scan",
        "subdomains":      "subdomain_scan",
        "server_version":  "server_version_scan",
        "file_scan":       "file_scan",
        "network_traffic": "network_traffic_scan",
        "nuclei":          "nuclei_scan",
        "tlsx":            "tlsx_scan",
        "testssl":         "testssl_scan",
        "gowitness":       "gowitness_scan",
        "api_docs":        "api_docs_scan",
    }

    def __init__(self, config: Config = None, logger: Logger = None,
                 scope: ScopePolicy | None = None):
        self.config = config or Config()
        self.logger = logger or Logger()
        self.scope = scope
        self.manager = AsyncTaskManager(
            max_workers=self.config.get_max_concurrent_tasks
        )

    # ---------- старые режимы ----------
    async def passive_scan(self, domain):
        if self.scope:
            self.scope.require(domain)
        domain = extract_domain(domain)
        print(f"🔍 Пассивное сканирование: {domain}")
        await self.rate_limiter.acquire()
        whois_info = await self.manager.run_task(WHOISScanner().get_whois, domain)
        await self.rate_limiter.acquire()
        dns_records = await self.manager.run_task(DNSScanner().get_dns_records, domain)
        self.logger.log("WHOIS", whois_info)
        self.logger.log("DNS-записи", dns_records)
        return {"whois": whois_info, "dns": dns_records}

    async def subdomain_scan(self, domain):
        if self.scope:
            self.scope.require(domain)
        print(f"🌐 Поиск поддоменов: {domain}")
        result = await SubdomainScanner(self.config).scan_subdomains(domain)
        if self.scope and isinstance(result, dict):
            allowed, rejected = self.scope.filter(result.get("subdomains", []))
            result["subdomains"] = allowed
            if rejected:
                result.setdefault("errors", []).append(
                    f"Пропущено целей вне scope: {len(rejected)}"
                )
        self.logger.log("Поддомены", result)
        return result

    async def server_version_scan(self, target):
        if self.scope:
            self.scope.require(target)
        print(f"🔧 Анализ версии сервера: {target}")
        nmap_result = await self.manager.run_task(
            ServerVersionScanner(
                rate_limit=self.config.get_rate_limit
            ).scan_with_nmap, target
        )
        self.logger.log("Nmap (версия сервера)", nmap_result)

        # правильный URL: учитываем порт из target или из nmap open_ports
        url = self._build_url(target, nmap_result)
        if self.scope:
            self.scope.require(url)
        print(f"🌐 Wappalyzer: {url}")
        wapp_result = await WappalyzerScanner(self.config).detect_technologies_async(
            url, self.rate_limiter
        )
        self.logger.log("Wappalyzer", wapp_result)
        return {"nmap": nmap_result, "wappalyzer": wapp_result}

    async def file_scan(self, target):
        if self.scope:
            self.scope.require(target)
        url = self._build_url(target, None)
        if self.scope:
            self.scope.require(url)
        print(f"📁 Поиск файлов/директорий: {url}")
        scanner = FileScanner(
            rate_limit=self.config.get_rate_limit,
            headers=self.config.get_http_headers,
        )
        estimate = scanner.estimate_duration()
        result = await self._run_with_progress(
            self.manager.run_task(scanner.scan, url),
            "Поиск файлов/директорий",
            estimate,
        )
        self.logger.log("Найденные файлы/директории", result)
        return result

    @staticmethod
    async def _run_with_progress(awaitable, label, estimated_seconds):
        task = asyncio.create_task(awaitable)
        started = time.monotonic()
        tty = sys.stdout.isatty()
        spinner = "|/-\\"
        last_message = ""
        frame = 0

        def format_duration(seconds):
            seconds = max(0, int(seconds))
            return f"{seconds // 60:02d}:{seconds % 60:02d}"

        try:
            while not task.done():
                elapsed = time.monotonic() - started
                estimate_progress = (
                    f"осталось ~{format_duration(estimated_seconds - elapsed)}"
                    if elapsed < estimated_seconds
                    else "ориентир времени превышен"
                )
                message = (
                    f"{spinner[frame % len(spinner)]} {label}: выполняется "
                    f"{format_duration(elapsed)} · оценка "
                    f"~{format_duration(estimated_seconds)} "
                    f"({estimate_progress})"
                )
                if tty:
                    sys.stdout.write(f"\r\033[K{message}")
                    sys.stdout.flush()
                elif message != last_message:
                    print(message, flush=True)
                last_message = message
                frame += 1
                try:
                    await asyncio.wait_for(asyncio.shield(task), timeout=0.5)
                except asyncio.TimeoutError:
                    pass

            result = task.result()
        except BaseException:
            if tty:
                sys.stdout.write("\r\033[K")
                sys.stdout.flush()
            raise

        elapsed = time.monotonic() - started
        if tty:
            sys.stdout.write(
                f"\r\033[K✅ {label}: завершено за {format_duration(elapsed)}\n"
            )
            sys.stdout.flush()
        else:
            print(f"✅ {label}: завершено за {format_duration(elapsed)}", flush=True)
        return result

    async def network_traffic_scan(self, target):
        if self.scope:
            self.scope.require(target)
        print(f"🔄 Анализ сетевого трафика: {target}")
        result = await self.manager.run_task(
            NetworkTrafficScanner(
                rate_limit=self.config.get_rate_limit
            ).analyze_with_nmap, target
        )
        self.logger.log("Nmap http-enum", result)
        return result

    async def nuclei_scan(self, target):
        if self.scope:
            self.scope.require(target)
        print(f"☢️  Nuclei: {target} (rl={self.config.get_nuclei_rate_limit}/s)")
        scanner = NucleiScanner(self.config)
        result = await self.manager.run_task(scanner.scan, target)
        self.logger.log("Nuclei", result)
        return result

    async def tlsx_scan(self, target):
        result = await self.manager.run_task(
            TLSXScanner(self.scope).scan, target
        )
        self.logger.log("tlsx", result)
        return result

    async def testssl_scan(self, target):
        result = await self.manager.run_task(
            TestSSLScanner(self.scope).scan, target
        )
        self.logger.log("testssl.sh", result)
        return result

    async def gowitness_scan(self, target):
        result = await self.manager.run_task(
            GowitnessScanner(self.scope, self.config.get_http_headers).scan,
            target,
        )
        self.logger.log("gowitness", result)
        return result

    async def api_docs_scan(self, target):
        result = await self.manager.run_task(
            ApiDocsScanner(
                timeout=self.config.get_timeout,
                headers=self.config.get_http_headers,
                scope=self.scope,
            ).scan,
            target,
        )
        self.logger.log("API documentation discovery", result)
        return result

    async def live_capture(self, interface, duration, count):
        print(f"📡 Захват трафика на {interface} ({duration}s)")
        result = await self.manager.run_task(
            TrafficCaptureScanner(interface, count, duration).capture
        )
        self.logger.log("Захват трафика (pyshark)", result)
        return result

    @property
    def rate_limiter(self):
        from utils.rate_limiter import AsyncRateLimiter
        limiter = getattr(self, "_rate_limiter", None)
        if limiter is None:
            self._rate_limiter = AsyncRateLimiter(self.config.get_rate_limit)
        return self._rate_limiter

    # ---------- helpers ----------
    @staticmethod
    def _build_url(target: str, nmap_result) -> str:
        """Собирает URL из target + портов, найденных nmap."""
        if target.startswith(("http://", "https://")):
            return target
        if ":" in target:
            return f"http://{target}"

        open_ports = []
        if isinstance(nmap_result, dict):
            open_ports = nmap_result.get("open_ports", [])

        if 443 in open_ports:
            return f"https://{target}"
        if 80 in open_ports:
            return f"http://{target}"
        if open_ports:
            return f"http://{target}:{open_ports[0]}"
        return f"http://{target}"

    # ---------- pipeline (полный прогон) ----------
    async def full_pipeline(self, target: str, base_url: str | None = None):
        print(f"🎯 Полный прогон: {target}")
        pipeline = Pipeline(config=self.config, logger=self.logger, scope=self.scope)
        try:
            return await pipeline.run_full(target, base_url=base_url)
        finally:
            pass  # Pipeline сам закрывает менеджер и storage


# ---------- CLI ----------
async def cli_main():
    parser = argparse.ArgumentParser(
        description="ShadowScope — инструмент разведки для bug bounty"
    )
    parser.add_argument("--passive",         action="store_true", help="WHOIS + DNS")
    parser.add_argument("--subdomains",      action="store_true", help="subfinder/amass/sublist3r")
    parser.add_argument("--server_version",  action="store_true", help="nmap -sV + Wappalyzer")
    parser.add_argument("--file_scan",       action="store_true", help="gobuster + dirb")
    parser.add_argument("--network_traffic", action="store_true", help="nmap http-enum")
    parser.add_argument("--nuclei",          action="store_true", help="nuclei")
    parser.add_argument("--tlsx", action="store_true", help="TLS certificate inspection with tlsx")
    parser.add_argument("--testssl", action="store_true", help="TLS configuration checks with testssl.sh")
    parser.add_argument("--gowitness", action="store_true", help="Screenshot the target with gowitness")
    parser.add_argument("--api-docs", dest="api_docs", action="store_true",
                        help="Discover same-origin OpenAPI/Swagger documentation")
    parser.add_argument("--capture",         action="store_true", help="захват трафика (pyshark)")
    parser.add_argument("--full",            action="store_true",
                        help="ПОЛНЫЙ прогон: recon → analysis → vuln → отчёты")
    parser.add_argument("--diff",            action="store_true",
                        help="Diff последнего скана с предыдущим")
    parser.add_argument("--allow-scope", default="",
                        help="Дополнительные разрешённые домены через запятую")
    parser.add_argument("--list-scans", action="store_true",
                        help="Список сохранённых запусков")
    parser.add_argument("--scan-info", type=int, metavar="ID",
                        help="Детали запуска по ID")
    parser.add_argument("--export-scan", type=int, metavar="ID",
                        help="Создать отчёты для запуска по ID")
    parser.add_argument("--check-tools",     action="store_true", help="проверка наличия внешних утилит")
    parser.add_argument("--interface", default="eth0", help="интерфейс захвата")
    parser.add_argument("--duration",  type=int, default=20)
    parser.add_argument("--count",     type=int, default=50)
    parser.add_argument("target",      nargs="?", default=None, help="домен или IP")
    args = parser.parse_args()

    # --check-tools: проверка наличия внешних утилит
    if args.check_tools:
        from utils.healthcheck import check_tools
        check_tools()
        return

    if args.list_scans:
        _list_scans()
        return
    if args.scan_info is not None:
        _show_scan(args.scan_info)
        return
    if args.export_scan is not None:
        _export_scan(args.export_scan)
        return

    if not args.target:
        parser.print_help()
        return

    # --full: pipeline сам управляет своими ресурсами
    if args.full:
        try:
            scope = ShadowScope(scope=ScopePolicy(args.target, args.allow_scope))
        except ValueError as exc:
            parser.error(str(exc))
        print(f"📝 Лог: {scope.logger.log_file}")
        try:
            result = await scope.full_pipeline(args.target)
        except Exception as exc:
            print(f"❌ Полный прогон завершился ошибкой: {exc}")
            return
        print("\n📊 Полный прогон завершён. Отчёты:")
        for kind, path in result.items():
            print(f"   • {kind}: {path}")
        return

    # --diff: не требует менеджера
    if args.diff:
        _show_diff(args.target)
        return

    # классические режимы
    selected = [flag for flag in ShadowScope.MODES if getattr(args, flag)]
    if not selected and not args.capture:
        parser.print_help()
        return

    try:
        policy = ScopePolicy(args.target, args.allow_scope)
    except ValueError as exc:
        parser.error(str(exc))
    scope = ShadowScope(scope=policy)
    print(f"📝 Лог: {scope.logger.log_file}")
    storage = Storage()
    scan_id = storage.start_scan(
        args.target,
        str(scope.logger.log_file),
        {**scope.config.as_dict(), "scope": list(policy.allowed_roots)},
    )
    started_at = time.monotonic()
    mode_summary = []
    try:
        for flag in selected:
            started = time.monotonic()
            try:
                result = await getattr(scope, ShadowScope.MODES[flag])(args.target)
                mode_status = _result_state(result)
            except Exception as exc:
                mode_status = "failed"
                scope.logger.logger.exception("Режим %s завершился ошибкой", flag)
                print(f"❌ {flag}: {exc}")
            mode_summary.append({
                "name": flag,
                "status": mode_status,
                "duration_seconds": round(time.monotonic() - started, 2),
            })
        if args.capture:
            started = time.monotonic()
            try:
                result = await scope.live_capture(
                    args.interface, args.duration, args.count
                )
                mode_status = _result_state(result)
            except Exception as exc:
                mode_status = "failed"
                scope.logger.logger.exception("Захват трафика завершился ошибкой")
                print(f"❌ capture: {exc}")
            mode_summary.append({
                "name": "capture",
                "status": mode_status,
                "duration_seconds": round(time.monotonic() - started, 2),
            })
    finally:
        scope.manager.shutdown()
        statuses = [item["status"] for item in mode_summary]
        status = (
            "failed" if statuses and all(item == "failed" for item in statuses)
            else "partial" if any(item != "completed" for item in statuses)
            else "completed"
        )
        summary = {
            "scan_id": scan_id,
            "scope": list(policy.allowed_roots),
            "duration_seconds": round(time.monotonic() - started_at, 2),
            "modes": mode_summary,
        }
        storage.finish_scan(scan_id, status, summary)
        storage.close()
    print(f"\n📊 Итог запуска #{scan_id}: {status} "
          f"за {summary['duration_seconds']:.2f} сек.")
    for item in mode_summary:
        print(
            f"   • {item['name']}: {item['status']} "
            f"({item['duration_seconds']:.2f} сек.)"
        )


def _result_state(result) -> str:
    if isinstance(result, dict):
        if "error" in result or any(key.endswith("_error") for key in result):
            return "failed" if len(result) == 1 and "error" in result else "partial"
        if result.get("errors"):
            return "partial"
        states = [_result_state(value) for value in result.values()
                  if isinstance(value, (dict, list))]
        if "failed" in states:
            return "partial"
    elif isinstance(result, list):
        if "failed" in [_result_state(value) for value in result
                        if isinstance(value, (dict, list))]:
            return "partial"
    return "completed"


def _show_diff(target: str):
    st = Storage()
    row = st.conn.execute(
        "SELECT id FROM scans WHERE target = ? ORDER BY id DESC LIMIT 1",
        (target,),
    ).fetchone()
    if not row:
        print(f"❌ Нет ни одного скана для {target}")
        return
    d = diff_scans(st, target, row["id"])
    print(json.dumps(d, indent=2, ensure_ascii=False, default=str))
    st.close()


def _list_scans():
    st = Storage()
    try:
        scans = st.list_scans()
        if not scans:
            print("Сохранённых сканирований пока нет.")
            return
        print("ID | Цель | Начало | Статус | Активы | Находки")
        for scan in scans:
            print(
                f"{scan['id']} | {scan['target']} | {scan['started_at']} | "
                f"{scan['status'] or 'unknown'} | {scan['asset_count']} | "
                f"{scan['finding_count']}"
            )
    finally:
        st.close()


def _show_scan(scan_id: int):
    st = Storage()
    try:
        scan = st.scan_by_id(scan_id)
        if not scan:
            print(f"Скан #{scan_id} не найден.")
            return
        print(json.dumps(scan, ensure_ascii=False, indent=2, default=str))
    finally:
        st.close()


def _export_scan(scan_id: int):
    st = Storage()
    try:
        scan = st.scan_by_id(scan_id)
        if not scan:
            print(f"Скан #{scan_id} не найден.")
            return
        target = scan["target"]
        diff = diff_scans(st, target, scan_id)
        assets = st.assets_for(target)
        findings = st.findings_for_scan(scan_id)
        paths = {
            "Markdown": render_markdown(
                target, scan_id, assets, findings, diff, scan
            ),
            "JSON": export_json(target, scan_id, st, diff),
            "HTML": export_html(target, scan_id, st, diff),
        }
        for kind, path in paths.items():
            print(f"{kind}: {path}")
    finally:
        st.close()


def main():
    asyncio.run(cli_main())


if __name__ == "__main__":
    main()