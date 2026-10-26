"""
Интерактивное меню ShadowScope.
Запуск: python menu.py
"""
import asyncio
import json
import sys
import time
from pathlib import Path

from config import Config
from core.diff import diff_scans
from core.scope import ScopePolicy
from logger import Logger, LOG_DIR
from main import ShadowScope
from core.pipeline import Pipeline
from core.storage import Storage
from reports.json_export import export_json
from reports.markdown import render_markdown
from reports.html import export_html
from reports.log_export import generate_reports_from_log


BANNER = r"""
   _____ __              __  _____
  / ___// /_  ____ _____/ / / ___/_________  ____  ____  _____
  \__ \/ __ \/ __ `/ __  /  \__ \/ ___/ __ \/ __ \/ __ \/ ___/
 ___/ / / / / /_/ / /_/ /  ___/ / /__/ /_/ / /_/ / /_/ /  __/
/____/_/ /_/\__,_/\__,_/  /____/\___/\____/ .___/\____/\___/
                                         /_/
            Bug Bounty Recon Toolkit  ·  v2.0
"""


def clear():
    print("\033[2J\033[H", end="")


def ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or (default or "")


def ask_int(prompt: str, default: int) -> int:
    raw = ask(prompt, str(default))
    try:
        return int(raw)
    except ValueError:
        print(f"⚠️  Некорректное число, использую {default}")
        return default


def pause(msg="Enter для продолжения..."):
    input(f"\n{msg}")


# ---------- конфиг ----------
def print_config(cfg: Config):
    print("\n📋 Текущая конфигурация:")
    for k, v in cfg.as_dict().items():
        print(f"   • {k}: {v}")
    print()


def settings_menu(cfg: Config):
    while True:
        clear()
        print(BANNER)
        print("⚙️  НАСТРОЙКИ")
        print("─" * 50)
        print_config(cfg)
        print("1) rate_limit (запросов/сек, глобально)")
        print("2) nuclei_rate_limit")
        print("3) timeout (сек)")
        print("4) max_concurrent_tasks")
        print("5) nuclei_severity")
        print("6) nuclei_templates (пусто = все)")
        print("7) 💾 Сохранить в config.json")
        print("8) X-Bug-Bounty")
        print("0) Назад")
        choice = ask("Выбор", "0")

        if choice == "1":
            cfg.set("rate_limit", ask_int("rate_limit", cfg.get_rate_limit))
        elif choice == "2":
            cfg.set("nuclei_rate_limit", ask_int("nuclei_rate_limit", cfg.get_nuclei_rate_limit))
        elif choice == "3":
            cfg.set("timeout", ask_int("timeout", cfg.get_timeout))
        elif choice == "4":
            cfg.set("max_concurrent_tasks", ask_int("max_concurrent_tasks", cfg.get_max_concurrent_tasks))
        elif choice == "5":
            cfg.set("nuclei_severity", ask("severity", cfg.get_nuclei_severity))
        elif choice == "6":
            cfg.set("nuclei_templates", ask("путь к шаблонам", cfg.get_nuclei_templates))
        elif choice == "8":
            cfg.set(
                "bug_bounty_header_value",
                ask("X-Bug-Bounty", cfg.as_dict()["bug_bounty_header_value"]),
            )
        elif choice == "7":
            cfg.save()
            print("✅ Сохранено в config.json")
            pause()
        elif choice == "0":
            return


# ---------- одиночные режимы ----------
async def run_modes(cfg: Config, target: str, modes: list[str],
                    capture_opts: dict | None = None,
                    generate_report: bool = False,
                    allowed_scope: str = ""):
    logger = Logger()
    policy = ScopePolicy(target, allowed_scope)
    scope = ShadowScope(config=cfg, logger=logger, scope=policy)
    storage = Storage()
    scan_id = storage.start_scan(
        target, str(logger.log_file), {**cfg.as_dict(), "scope": list(policy.allowed_roots)}
    )
    summary = {"scan_id": scan_id, "scope": list(policy.allowed_roots), "modes": []}
    started_at = time.monotonic()
    print(f"📝 Лог: {logger.log_file}\n")
    try:
        for mode in modes:
            if mode == "capture":
                continue
            method = ShadowScope.MODES.get(mode)
            if method is None:
                print(f"⚠️  Неизвестный режим: {mode}")
                continue
            mode_started = time.monotonic()
            try:
                result = await getattr(scope, method)(target)
            except Exception as exc:
                result = {"error": str(exc)}
                logger.logger.exception("Режим %s завершился ошибкой", mode)
            state = _result_state(result)
            summary["modes"].append({
                "name": mode,
                "status": state,
                "duration_seconds": round(time.monotonic() - mode_started, 2),
            })

        if "capture" in modes:
            opts = capture_opts or {}
            mode_started = time.monotonic()
            try:
                result = await scope.live_capture(
                    opts.get("interface", "eth0"),
                    opts.get("duration", 20),
                    opts.get("count", 50),
                )
            except Exception as exc:
                result = {"error": str(exc)}
                logger.logger.exception("Захват трафика завершился ошибкой")
            summary["modes"].append({
                "name": "capture",
                "status": _result_state(result),
                "duration_seconds": round(time.monotonic() - mode_started, 2),
            })
    finally:
        scope.manager.shutdown()
        summary["duration_seconds"] = round(time.monotonic() - started_at, 2)
        statuses = [item["status"] for item in summary["modes"]]
        summary["status"] = (
            "failed" if statuses and all(s == "failed" for s in statuses)
            else "partial" if any(s != "completed" for s in statuses)
            else "completed"
        )
        storage.finish_scan(scan_id, summary["status"], summary)
        storage.close()

    _print_run_summary(summary)

    if generate_report:
        try:
            reports = generate_reports_from_log(Path(logger.log_file))
        except (OSError, ValueError) as exc:
            summary["report_error"] = str(exc)
            summary["status"] = "partial"
            logger.logger.exception("Не удалось создать отчёты")
            summary_storage = Storage()
            try:
                summary_storage.finish_scan(scan_id, summary["status"], summary)
            finally:
                summary_storage.close()
            print(f"❌ Ошибка генерации отчётов: {exc}")
        else:
            print("\n✅ Отчёты по логу созданы:")
            for kind, path in reports.items():
                print(f"   • {kind}: {path}")
    return summary


def _result_state(result) -> str:
    if isinstance(result, dict):
        if "error" in result or any(key.endswith("_error") for key in result):
            return "failed" if len(result) == 1 and "error" in result else "partial"
        if result.get("errors"):
            return "partial"
        nested = [_result_state(value) for value in result.values()
                  if isinstance(value, (dict, list))]
        if nested and "failed" in nested:
            return "partial"
    elif isinstance(result, list):
        nested = [_result_state(value) for value in result
                  if isinstance(value, (dict, list))]
        if "failed" in nested:
            return "partial"
    return "completed"


def _print_run_summary(summary: dict):
    print(
        f"\n📊 Итог запуска #{summary['scan_id']}: {summary['status']} "
        f"за {summary['duration_seconds']:.2f} сек."
    )
    for mode in summary["modes"]:
        print(
            f"   • {mode['name']}: {mode['status']} "
            f"({mode['duration_seconds']:.2f} сек.)"
        )


def _export_db_reports(storage: Storage, scan_id: int) -> dict[str, Path]:
    scan = storage.scan_by_id(scan_id)
    if not scan:
        raise ValueError(f"Скан #{scan_id} не найден")
    target = scan["target"]
    diff = diff_scans(storage, target, scan_id)
    assets = storage.assets_for(target)
    findings = storage.findings_for_scan(scan_id)
    return {
        "markdown": render_markdown(
            target, scan_id, assets, findings, diff, scan
        ),
        "json": export_json(target, scan_id, storage, diff),
        "html": export_html(target, scan_id, storage, diff),
    }


# ---------- полный прогон ----------
async def run_full(cfg: Config, target: str, allowed_scope: str = ""):
    logger = Logger()
    print(f"📝 Лог: {logger.log_file}\n")
    policy = ScopePolicy(target, allowed_scope)
    pipeline = Pipeline(config=cfg, logger=logger, scope=policy)
    try:
        result = await pipeline.run_full(target)
        print("\n✅ Готово. Отчёты:")
        for kind, path in result.items():
            print(f"   • {kind}: {path}")
    except Exception as e:
        print(f"❌ Ошибка pipeline: {e}")
        import traceback
        traceback.print_exc()


# ---------- diff ----------
def show_diff_menu():
    target = ask("Цель (домен/IP, как в scans)")
    if not target:
        return
    st = Storage()
    try:
        row = st.conn.execute(
            "SELECT id, started_at FROM scans WHERE target = ? "
            "ORDER BY id DESC LIMIT 1",
            (target,),
        ).fetchone()
        if not row:
            print(f"❌ Нет сканов для {target}")
            pause()
            return
        d = diff_scans(st, target, row["id"])
        print(f"\n📊 Diff по scan #{row['id']} ({row['started_at']})")
        counts = d.get("counts", {})
        print(f"   • новых активов:     {counts.get('new_assets', len(d.get('new_assets', [])))}")
        print(f"   • пропавших:         {counts.get('removed_assets', len(d.get('removed_assets', [])))}")
        print(f"   • новых находок:     {counts.get('new_findings', len(d.get('new_findings', [])))}")
        print(f"   • предыдущий scan:   {d.get('previous_scan_id')}")
        if d.get("first_scan"):
            print("   ℹ️  Это первый скан цели, сравнивать пока не с чем.")

        if d.get("new_assets"):
            print("\n🆕 Новые активы:")
            for a in d["new_assets"][:30]:
                print(f"   • [{a['kind']}] {a['value']}")
        if d.get("new_findings"):
            print("\n🔥 Новые находки:")
            for f in d["new_findings"][:30]:
                print(f"   • [{f['severity']}] {f['title']}")
    finally:
        st.close()
        pause()


# ---------- отчёты ----------
def show_reports_menu():
    source = ask("Источник отчёта: 1 — база сканов, 2 — лог-файл", "2")
    if source == "2":
        files = sorted(LOG_DIR.glob("*.log"))
        if not files:
            print(f"❌ Лог-файлы не найдены в {LOG_DIR.resolve()}")
            pause()
            return

        print("\n📁 Доступные логи:")
        for index, path in enumerate(files, 1):
            print(f"{index}) {path.name}")
        selection = ask("Выберите номер или имя файла", str(len(files)))
        if selection.isdigit():
            index = int(selection)
            if not 1 <= index <= len(files):
                print("❌ Номер лога вне списка")
                pause()
                return
            log_path = files[index - 1]
        else:
            log_path = next((path for path in files if path.name == selection), None)
            if log_path is None:
                print("❌ Выберите лог из списка")
                pause()
                return

        reports = generate_reports_from_log(log_path)
        print(f"\n📄 Отчёты по логу {log_path.name}:")
        for kind, path in reports.items():
            print(f"   • {kind}: {path}")
        pause()
        return
    if source != "1":
        print("❌ Неизвестный источник отчёта")
        pause()
        return

    raw_scan_id = ask("ID сканирования")
    if not raw_scan_id.isdigit():
        print("❌ Введите числовой ID сканирования")
        pause()
        return
    st = Storage()
    try:
        try:
            paths = _export_db_reports(st, int(raw_scan_id))
        except ValueError as exc:
            print(f"❌ {exc}")
            pause()
            return
        print(f"\n📄 Отчёты для scan #{raw_scan_id}:")
        for kind, path in paths.items():
            print(f"   • {kind}: {path}")
    finally:
        st.close()
        pause()


# ---------- scan management ----------
def scans_menu():
    st = Storage()
    try:
        scans = st.list_scans()
        if not scans:
            print("❌ Сохранённых сканирований пока нет")
            pause()
            return

        print("\n🗂️  Последние сканирования:")
        for scan in scans:
            print(
                f"#{scan['id']} {scan['target']} | {scan['started_at']} | "
                f"{scan['status'] or 'unknown'} | "
                f"активов: {scan['asset_count']} | находок: {scan['finding_count']}"
            )
        raw_id = ask("ID сканирования для просмотра/экспорта")
        if not raw_id.isdigit():
            print("❌ Введите числовой ID")
            pause()
            return

        scan = st.scan_by_id(int(raw_id))
        if not scan:
            print(f"❌ Скан #{raw_id} не найден")
            pause()
            return
        print(f"\n📋 Скан #{scan['id']} — {scan['target']}")
        print(f"   Начало: {scan['started_at']}")
        print(f"   Завершение: {scan['finished_at'] or 'ещё выполняется'}")
        print(f"   Статус: {scan['status'] or 'unknown'}")
        print(f"   Лог: {scan['log_file'] or 'не указан'}")
        if scan.get("summary_json"):
            print("   Итог:")
            print(json.dumps(
                json.loads(scan["summary_json"]),
                ensure_ascii=False,
                indent=2,
            ))

        if ask("Создать/обновить отчёты для этого скана? (y/n)", "n").lower() in {
            "y", "yes", "д", "да"
        }:
            for kind, path in _export_db_reports(st, scan["id"]).items():
                print(f"   • {kind}: {path}")
    finally:
        st.close()
        pause()


# ---------- scan menu ----------
def scan_menu(cfg: Config):
    clear()
    print(BANNER)
    print("🎯 НОВОЕ СКАНИРОВАНИЕ")
    print("─" * 50)

    target = ask("Цель (домен или IP)")
    if not target:
        print("❌ Цель не указана")
        pause()
        return
    allowed_scope = ask(
        "Дополнительные разрешённые домены через запятую "
        "(Enter = только цель и её поддомены)",
        "",
    )

    options = {
        "1":  ("passive",         "WHOIS + DNS"),
        "2":  ("subdomains",      "Поиск поддоменов"),
        "3":  ("server_version",  "Nmap -sV + Wappalyzer"),
        "4":  ("file_scan",       "Gobuster + dirb"),
        "5":  ("network_traffic", "Nmap http-enum"),
        "6":  ("nuclei",          "Nuclei"),
        "7":  ("capture",         "Захват трафика (pyshark)"),
        "8":  ("full_pipeline",   "🎯 ПОЛНЫЙ ПРОГОН (recon → vuln → отчёты)"),
        "9":  ("tlsx",            "Сведения о TLS-сертификате (tlsx)"),
        "10": ("testssl",         "Проверка TLS-конфигурации (testssl.sh)"),
        "11": ("gowitness",       "Скриншот веб-страницы (gowitness)"),
        "12": ("api_docs",        "Поиск OpenAPI/Swagger документации"),
    }
    print("\nРежимы (через запятую, например 1,2,6):")
    for k, (_, desc) in options.items():
        print(f"  {k}) {desc}")

    raw = ask("Режимы", "1,2,6")
    selected = [k.strip() for k in raw.split(",") if k.strip() in options]
    if not selected:
        print("❌ Ничего не выбрано")
        pause()
        return

    modes = [options[k][0] for k in selected]

    # --- специальные случаи ---
    if "full_pipeline" in modes:
        print("\nℹ️  Полный прогон всегда создаёт отчёты из базы сканирования.")
        print(f"\n🚀 Полный прогон: {target}\n")
        try:
            asyncio.run(run_full(cfg, target, allowed_scope))
        except KeyboardInterrupt:
            print("\n⏹️  Прервано")
        pause()
        return

    capture_opts = None
    if "capture" in modes:
        capture_opts = {
            "interface": ask("Интерфейс", "eth0"),
            "duration":  ask_int("Длительность, сек", 20),
            "count":     ask_int("Макс. пакетов", 50),
        }

    generate_report = ask("Автоматически создать отчёты по логу после сканирования? (y/n)", "n").lower()
    generate_report = generate_report in {"y", "yes", "д", "да"}

    print(f"\n🚀 Запуск: target={target}, modes={modes}\n")
    try:
        asyncio.run(
            run_modes(
                cfg, target, modes, capture_opts, generate_report, allowed_scope
            )
        )
    except KeyboardInterrupt:
        print("\n⏹️  Прервано")
    pause()


# ---------- логи ----------
def show_logs():
    clear()
    print(f"📁 Логи: {LOG_DIR.resolve()}")
    files = sorted(LOG_DIR.glob("*.log"))
    if not files:
        print("   (пусто)")
    else:
        for f in files[-15:]:
            print(f"   • {f.name}  ({f.stat().st_size} байт)")
    pause()


# ---------- main ----------
def main():
    cfg = Config()
    while True:
        clear()
        print(BANNER)
        print("ГЛАВНОЕ МЕНЮ")
        print("─" * 50)
        print("1) 🎯 Новое сканирование")
        print("2) ⚙️  Настройки")
        print("3) 📊 Diff с прошлым сканом")
        print("4) 📄 Сгенерировать отчёты")
        print("5) 📁 Показать логи")
        print("6) 📋 Показать config")
        print("7) 🗂️  Управление сканированиями")
        print("0) 🚪 Выход")
        choice = ask("Выбор", "0")

        if choice == "1":
            scan_menu(cfg)
        elif choice == "2":
            settings_menu(cfg)
        elif choice == "3":
            show_diff_menu()
        elif choice == "4":
            show_reports_menu()
        elif choice == "5":
            show_logs()
        elif choice == "6":
            clear()
            print_config(cfg)
            pause()
        elif choice == "7":
            scans_menu()
        elif choice == "0":
            print("👋 До связи!")
            sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Прервано")
        sys.exit(0)