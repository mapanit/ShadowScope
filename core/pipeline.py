"""
Пайплайн сканирования. Связывает модули, storage, diff, отчёты.
"""
import asyncio
import json
import time
from pathlib import Path

from config import Config
from logger import Logger
from core.storage import Storage
from core.diff import diff_scans
from core.scope import ScopePolicy
from utils.async_utils import AsyncTaskManager

# recon
from modules.recon.dnsx import DnsxScanner
from modules.recon.httpx_probe import HttpxProbe
from modules.recon.wayback import WaybackScanner
from modules.recon.crawl import Crawler
# analysis
from modules.analysis.whatweb import WhatWebScanner
from modules.analysis.gf_filter import GfFilter
# vuln
from modules.vuln.nuclei_scan import NucleiScanner
from modules.vuln.ffuf_scan import FfufScanner
from modules.vuln.takeover import TakeoverScanner
# reports
from reports.markdown import render_markdown
from reports.json_export import export_json
from reports.html import export_html


class Pipeline:
    def __init__(self, config: Config = None, logger: Logger = None,
                 scope: ScopePolicy | None = None):
        self.config = config or Config()
        self.logger = logger or Logger()
        self.scope = scope
        self.manager = AsyncTaskManager(max_workers=self.config.get_max_concurrent_tasks)
        self.storage = Storage()
        self.scan_id: int | None = None
        self.target: str | None = None
        self.assets_cache = {"subdomains": [], "urls": []}
        self.stage_summary = []
        self.stage_issues = set()
        self.started_at = 0.0

    # ---- scan lifecycle ----
    def _start(self, target: str):
        if self.scope:
            self.scope.require(target)
        self.target = target
        self.scan_id = self.storage.start_scan(
            target=target,
            log_file=str(self.logger.log_file),
            config={
                **self.config.as_dict(),
                "scope": list(self.scope.allowed_roots) if self.scope else [target],
            },
        )
        self.logger.logger.info(f"Scan #{self.scan_id} started for {target}")

    def _finish(self):
        statuses = [stage["status"] for stage in self.stage_summary]
        status = (
            "failed" if statuses and all(item == "failed" for item in statuses)
            else "partial" if any(item != "completed" for item in statuses)
            else "completed"
        )
        summary = {
            "assets": len(self.storage.assets_for(self.target)),
            "findings": len(self.storage.findings_for_scan(self.scan_id)),
            "scope": list(self.scope.allowed_roots) if self.scope else [self.target],
            "duration_seconds": round(time.monotonic() - self.started_at, 2),
            "stages": self.stage_summary,
        }
        self.storage.finish_scan(self.scan_id, status, summary)
        self.logger.logger.info(f"Scan #{self.scan_id} finished")
        print(f"\n📊 Итог полного сканирования #{self.scan_id}: {status}, "
              f"{summary['duration_seconds']:.2f} сек.")
        for stage in self.stage_summary:
            print(
                f"   • {stage['name']}: {stage['status']} "
                f"({stage['duration_seconds']:.2f} сек.)"
            )

    async def _run_stage(self, name: str, operation):
        started = time.monotonic()
        try:
            result = await operation()
        except Exception:
            self.stage_summary.append({
                "name": name,
                "status": "failed",
                "duration_seconds": round(time.monotonic() - started, 2),
            })
            raise

        status = "completed"
        if isinstance(result, dict):
            if "error" in result or any(key.endswith("_error") for key in result):
                status = "failed" if len(result) == 1 and "error" in result else "partial"
            elif result.get("errors"):
                status = "partial"
        if any(name == issue or name.startswith(f"{issue} ")
               for issue in self.stage_issues):
            status = "partial"
        self.stage_summary.append({
            "name": name,
            "status": status,
            "duration_seconds": round(time.monotonic() - started, 2),
        })
        return result

    def _record_asset(self, kind: str, value: str):
        return self.storage.add_asset(self.target, kind, value)

    def _record_finding(self, kind: str, severity: str,
                        title: str, data: dict, asset_value: str | None = None):
        asset_id = None
        if asset_value:
            asset_id = self._record_asset("host", asset_value)
        # если NULL — значит asset существовал; найдём id
        if asset_id is None and asset_value:
            row = self.storage.conn.execute(
                "SELECT id FROM assets WHERE target_root=? AND kind=? AND value=?",
                (self.target, "host", asset_value),
            ).fetchone()
            asset_id = row["id"] if row else None
        self.storage.add_finding(
            self.scan_id, asset_id, kind, severity, title, data,
        )

    # ---- этапы ----
    async def step_dnsx(self, hosts: list[str]) -> list[str]:
        if self.scope:
            hosts, rejected = self.scope.filter(hosts)
            if rejected:
                self.logger.logger.warning(
                    "dnsx: пропущены цели вне scope: %s", ", ".join(rejected)
                )
        print(f"🔎 dnsx: резолв {len(hosts)} хостов")
        result = await self.manager.run_task(
            DnsxScanner(self.config.get_rate_limit).resolve, hosts
        )
        if isinstance(result, dict) and result.get("error"):
            raise RuntimeError(result["error"])
        self.logger.log("dnsx", result)
        resolved = result.get("resolved", []) if isinstance(result, dict) else []
        if self.scope:
            resolved, rejected = self.scope.filter(resolved)
            if rejected:
                self.logger.logger.warning(
                    "dnsx: отброшены результаты вне scope: %s", ", ".join(rejected)
                )
        for h in resolved:
            self._record_asset("host", h)
        return resolved

    async def step_httpx(self, hosts: list[str]) -> list[dict]:
        if self.scope:
            hosts, rejected = self.scope.filter(hosts)
            if rejected:
                self.logger.logger.warning(
                    "httpx: пропущены цели вне scope: %s", ", ".join(rejected)
                )
        print(f"🌐 httpx: проверка {len(hosts)} хостов")
        result = await self.manager.run_task(
            HttpxProbe(rate_limit=self.config.get_rate_limit,
                       timeout=self.config.get_timeout,
                       headers=self.config.get_http_headers).probe, hosts,
        )
        if isinstance(result, dict) and result.get("error"):
            raise RuntimeError(result["error"])
        self.logger.log("httpx", result)
        live = result.get("live", []) if isinstance(result, dict) else []
        if self.scope:
            scoped_live = []
            for item in live:
                candidate = item.get("url") or item.get("input")
                if candidate and self.scope.allows(candidate):
                    scoped_live.append(item)
                elif candidate:
                    self.logger.logger.warning(
                        "httpx: результат вне scope отброшен: %s", candidate
                    )
            live = scoped_live
        for h in live:
            url = h.get("url") or h.get("input")
            if url:
                self._record_asset("url", url)
                self._record_asset("tech", ",".join(h.get("tech", []))) if h.get("tech") else None
        return live

    async def step_wayback(self) -> list[str]:
        print(f"📜 wayback/gau: сбор исторических URL")
        result = await self.manager.run_task(WaybackScanner().collect, self.target)
        self.logger.log("wayback/gau", {"count": result.get("count"),
                                        "errors": result.get("errors")})
        if result.get("errors"):
            self.stage_issues.add("wayback")
        urls = result.get("urls", []) if isinstance(result, dict) else []
        if self.scope:
            urls, rejected = self.scope.filter(urls)
            if rejected:
                self.logger.logger.warning(
                    "wayback: отброшено URL вне scope: %s", len(rejected)
                )
        for u in urls:
            self._record_asset("url", u)
        return urls

    async def step_crawl(self, url: str) -> list[str]:
        if self.scope:
            self.scope.require(url)
        print(f"🕸️  katana+gospider: краулинг {url}")
        result = await self.manager.run_task(
            Crawler(self.config.get_rate_limit, self.scope,
                    self.config.get_http_headers).crawl, url, 3
        )
        self.logger.log("crawl", {"count": result.get("count"),
                                  "errors": result.get("errors"),
                                  "out_of_scope_count":
                                      result.get("out_of_scope_count", 0)})
        if result.get("errors"):
            self.stage_issues.add("crawl")
        urls = result.get("urls", []) if isinstance(result, dict) else []
        for u in urls:
            self._record_asset("url", u)
        return urls

    async def step_whatweb(self, url: str) -> dict:
        if self.scope:
            self.scope.require(url)
        print(f"🔬 whatweb: {url}")
        result = await self.manager.run_task(
            WhatWebScanner(headers=self.config.get_http_headers).scan, url
        )
        self.logger.log("whatweb", result)
        return result

    async def step_gf(self, urls: list[str]) -> dict:
        if self.scope:
            urls, rejected = self.scope.filter(urls)
            if rejected:
                self.logger.logger.warning(
                    "gf: отброшено URL вне scope: %s", len(rejected)
                )
        print(f"🧬 gf: фильтрация {len(urls)} URL по паттернам")
        result = await self.manager.run_task(GfFilter().filter, urls)
        self.logger.log("gf", {"summary": result.get("summary"),
                               "errors": result.get("errors")})
        if result.get("errors"):
            self.stage_issues.add("gf")
        # сохраняем интересные URL как находки
        for pat, hits in (result.get("filtered") or {}).items():
            for url in hits:
                self._record_finding("url-interest", "info",
                                     f"Потенциальный {pat.upper()}: {url}",
                                     {"pattern": pat, "url": url})
        return result

    async def step_nuclei(self, hosts: list[str]) -> dict:
        if self.scope:
            hosts, rejected = self.scope.filter(hosts)
            if rejected:
                self.logger.logger.warning(
                    "nuclei: отброшено целей вне scope: %s", len(rejected)
                )
        print(f"☢️  nuclei: сканирование {len(hosts)} целей")
        scanner = NucleiScanner(self.config)
        merged = {"findings": [], "by_severity": {}, "errors": []}
        for host in hosts:
            url = host if host.startswith("http") else f"http://{host}"
            r = await self.manager.run_task(scanner.scan, url)
            if isinstance(r, dict) and "findings" in r:
                for f in r["findings"]:
                    merged["findings"].append(f)
                    sev = f.get("info", {}).get("severity", "unknown")
                    merged["by_severity"][sev] = merged["by_severity"].get(sev, 0) + 1
                    self._record_finding(
                        "vuln", sev,
                        f.get("info", {}).get("name", "nuclei finding"),
                        f, asset_value=url,
                    )
            elif isinstance(r, dict) and r.get("error"):
                merged["errors"].append({"target": url, "error": r["error"]})
        self.logger.log("nuclei", {"total": len(merged["findings"]),
                                   "by_severity": merged["by_severity"]})
        return merged

    async def step_ffuf(self, url: str) -> dict:
        if self.scope:
            self.scope.require(url)
        print(f"💥 ffuf: фаззинг {url}")
        result = await self.manager.run_task(
            FfufScanner(
                rate_limit=self.config.get_rate_limit,
                headers=self.config.get_http_headers,
            ).fuzz_dirs, url
        )
        self.logger.log("ffuf", {"count": result.get("count"),
                                 "error": result.get("error")})
        for hit in (result.get("found") or []):
            self._record_finding(
                "path", "info",
                f"Найден путь [{hit.get('status')}]: {hit.get('url')}",
                hit, asset_value=url,
            )
        return result

    async def step_takeover(self, subdomains: list[str]) -> dict:
        if self.scope:
            subdomains, rejected = self.scope.filter(subdomains)
            if rejected:
                self.logger.logger.warning(
                    "takeover: отброшено хостов вне scope: %s", len(rejected)
                )
        print(f"🎯 takeover: проверка {len(subdomains)} поддоменов")
        result = await self.manager.run_task(
            TakeoverScanner(
                self.config.get_nuclei_rate_limit,
                self.config.get_http_headers,
            ).scan,
            subdomains, self.target,
        )
        self.logger.log("takeover", {
            "subjack_count": (result.get("subjack", {}) or {}).get("count"),
            "nuclei_count": (result.get("nuclei", {}) or {}).get("count"),
        })
        for name in ("subjack", "nuclei"):
            if (result.get(name) or {}).get("error"):
                self.stage_issues.add("takeover")
        for h in (result.get("subjack", {}) or {}).get("vulnerable", []):
            self._record_finding("takeover", "high",
                                 f"Subdomain takeover (subjack): {h}",
                                 {"source": "subjack", "raw": h})
        for f in (result.get("nuclei", {}) or {}).get("vulnerable", []):
            sev = f.get("info", {}).get("severity", "high")
            self._record_finding("takeover", sev,
                                 f"Subdomain takeover (nuclei): "
                                 f"{f.get('info', {}).get('name', '')}", f)
        return result

    # ---- финал ----
    async def generate_reports(self):
        print("📄 Генерация отчётов")
        diff = diff_scans(self.storage, self.target, self.scan_id)
        assets = self.storage.assets_for(self.target)
        findings = self.storage.findings_for_scan(self.scan_id)
        stage_statuses = [stage["status"] for stage in self.stage_summary]
        run_status = (
            "failed" if stage_statuses and all(s == "failed" for s in stage_statuses)
            else "partial" if any(s != "completed" for s in stage_statuses)
            else "completed"
        )
        scan_metadata = {
            "status": run_status,
            "summary_json": json.dumps({
                "assets": len(assets),
                "findings": len(findings),
                "scope": list(self.scope.allowed_roots) if self.scope
                else [self.target],
                "duration_seconds": round(time.monotonic() - self.started_at, 2),
                "stages": self.stage_summary,
            }, ensure_ascii=False),
        }

        md_path = render_markdown(
            self.target, self.scan_id, assets, findings, diff,
            scan_metadata,
        )
        json_path = export_json(
            self.target, self.scan_id, self.storage, diff, scan_metadata
        )
        html_path = export_html(
            self.target, self.scan_id, self.storage, diff, scan_metadata
        )

        self.logger.log("Отчёт Markdown", {"path": str(md_path)})
        self.logger.log("Отчёт JSON", {"path": str(json_path)})
        self.logger.log("Отчёт HTML", {"path": str(html_path)})
        if diff.get("counts"):
            self.logger.log("Diff", diff["counts"])
        return {"markdown": md_path, "json": json_path, "html": html_path}

    async def run_full(self, domain: str, base_url: str | None = None):
        """
        Полный прогон: recon → analysis → vuln → отчёты.
        """
        self.started_at = time.monotonic()
        self.stage_summary = []
        self.stage_issues = set()
        self._start(domain)
        try:
            # 1) DNS
            try:
                resolved = await self._run_stage(
                    "dnsx", lambda: self.step_dnsx([domain])
                )
            except Exception as e:
                self.logger.logger.warning(f"Ошибка на шаге dnsx: {e}")
                resolved = [domain]

            # 2) httpx (может дать реальный URL с портом)
            try:
                live = await self._run_stage(
                    "httpx", lambda: self.step_httpx(resolved or [domain])
                )
            except Exception as e:
                self.logger.logger.warning(f"Ошибка на шаге httpx: {e}")
                live = []

            urls_to_scan = [h.get("url") for h in live if h.get("url")]
            if self.scope:
                urls_to_scan, rejected = self.scope.filter(urls_to_scan)
                if rejected:
                    self.logger.logger.warning(
                        "httpx: URL вне scope не будет сканироваться: %s",
                        ", ".join(rejected),
                    )
            if not urls_to_scan:
                urls_to_scan = [base_url or f"http://{domain}"]

            # 3) whatweb по первой живой цели
            try:
                await self._run_stage(
                    "whatweb", lambda: self.step_whatweb(urls_to_scan[0])
                )
            except Exception as e:
                self.logger.logger.warning(f"Ошибка на шаге whatweb: {e}")

            # 4) wayback + crawl
            hist = []
            try:
                hist = await self._run_stage("wayback", self.step_wayback)
            except Exception as e:
                self.logger.logger.warning(f"Ошибка на шаге wayback: {e}")

            crawled = []
            for u in urls_to_scan[:3]:
                try:
                    crawled.extend(await self._run_stage(
                        f"crawl {u}", lambda url=u: self.step_crawl(url)
                    ))
                except Exception as e:
                    self.logger.logger.warning(f"Ошибка на шаге crawl ({u}): {e}")
            all_urls = sorted(set(hist) | set(crawled))

            # 5) gf-фильтр
            if all_urls:
                try:
                    await self._run_stage("gf", lambda: self.step_gf(all_urls))
                except Exception as e:
                    self.logger.logger.warning(f"Ошибка на шаге gf: {e}")

            # 6) nuclei по живым хостам
            try:
                await self._run_stage(
                    "nuclei", lambda: self.step_nuclei(urls_to_scan)
                )
            except Exception as e:
                self.logger.logger.warning(f"Ошибка на шаге nuclei: {e}")

            # 7) ffuf по первому URL
            try:
                await self._run_stage(
                    "ffuf", lambda: self.step_ffuf(urls_to_scan[0])
                )
            except Exception as e:
                self.logger.logger.warning(f"Ошибка на шаге ffuf: {e}")

            # 8) takeover (если есть поддомены из пассивной разведки)
            try:
                subs = [a["value"] for a in self.storage.assets_for(domain, "host")]
                if subs:
                    await self._run_stage(
                        "takeover", lambda: self.step_takeover(subs)
                    )
            except Exception as e:
                self.logger.logger.warning(f"Ошибка на шаге takeover: {e}")

            # 9) отчёты
            return await self._run_stage("reports", self.generate_reports)
        finally:
            self._finish()
            self.manager.shutdown()
            self.storage.close()