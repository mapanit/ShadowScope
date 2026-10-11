<div align="center">

# 🛰️ ShadowScope

**ShadowScope — модульный CLI-инструмент на Python для авторизованной разведки и анализа поверхности атаки.** Объединяет внешние инструменты, сохраняет результаты в SQLite и формирует отчёты для сравнения запусков.

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.12-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.linux.org/)

</div>

---

## 📖 О проекте

ShadowScope оркестрирует пассивную и активную разведку, fingerprinting и выборочные проверки безопасности в едином пайплайне. Результаты можно хранить между запусками, сравнивать и экспортировать.

### Что демонстрирует проект
- Интеграцию Python-оркестратора с внешними CLI-инструментами.
- Асинхронное управление задачами, контроль частоты запросов и обработку частичных ошибок.
- Scope-проверки, хранение истории результатов в SQLite и сравнение запусков.
- Генерацию Markdown-, HTML- и JSON-отчётов.
- Автоматические тесты и GitHub Actions CI для Python 3.10 и 3.12.

---

## ✨ Ключевые возможности

- **Recon:** WHOIS/DNS, сбор поддоменов (`subfinder`, `amass`, `sublist3r`), DNS-резолвинг (`dnsx`) и HTTP-пробинг (`httpx`).
- **Discovery:** архивные URL (`waybackurls`, `gau`), краулинг (`katana`, `gospider`), фильтрация URL-параметров (`gf`).
- **Fingerprinting:** `whatweb`, Wappalyzer и Nmap.
- **Проверки:** Nuclei, ffuf, Gobuster/Dirb и проверка takeover через subjack/Nuclei.
- **Безопасность запуска:** ограничение целевых доменов и IP, собственные лимиты скорости для поддерживаемых инструментов, идентифицирующий заголовок `X-Bug-Bounty`.
- **История и отчёты:** SQLite, diff между запусками и экспорт Markdown/HTML/JSON в `reports/output/<цель>/<скан>/`. Отчёты включают severity, статус находок и рекомендации, если они доступны в данных сканера.

---

## 🏗️ Архитектура пайплайна

```text
                           [ Target Domain / IP ]
                                     │
                                     ▼
                     ┌───────────────────────────────┐
                     │     1. RECONNAISSANCE         │
                     │  (whois, dnsx, httpx, amass)  │
                     └───────────────┬───────────────┘
                                     │
                                     ▼
                     ┌───────────────────────────────┐
                     │   2. DISCOVERY & CRAWLING     │
                     │ (katana, waybackurls, whatweb)│
                     └───────────────┬───────────────┘
                                     │
                                     ▼
                     ┌───────────────────────────────┐
                     │   3. VULNERABILITY SCANNING   │
                     │   (nuclei, ffuf, subjack)     │
                     └───────────────┬───────────────┘
                                     │
                                     ▼
                     ┌───────────────────────────────┐
                     │    4. CORE STORAGE & DIFF     │
                     │  (SQLite DB / Asset Tracking) │
                     └───────────────┬───────────────┘
                                     │
                                     ▼
                     ┌───────────────────────────────┐
                     │     5. MULTI-FORMAT REPORT    │
                     │     [ Markdown | HTML | JSON ]│
                     └───────────────────────────────┘
```

---

## 🚀 Установка

Требуются Linux и Python 3.10 или 3.12. Внешние сканеры устанавливаются отдельно; набор доступных интеграций зависит от установленных программ.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Проверить, какие внешние утилиты обнаружены в `PATH`:
```bash
python main.py --check-tools
```

Для удобной, но более широкой системной установки предусмотрен `install.sh`. Он устанавливает пакеты ОС и настраивает права `tshark`; изучите его перед запуском.

> **Важно для Arch Linux:** перед запуском установщика добавьте репозиторий BlackArch. Инструкции доступны в [официальном репозитории BlackArch](https://github.com/BlackArch/blackarch). Установить его можно командой:
> ```bash
> curl -s https://blackarch.org/strap.sh | sudo bash
> ```

Установщик поддерживает `apt`, `dnf` и `pacman`:
```bash
chmod +x install.sh
./install.sh           # установить системные и Python-зависимости, а также Go-инструменты
./install.sh --no-go   # пропустить Go-инструменты
```

---

## 💻 Использование

Перед запуском активных проверок проверьте, что цель и методы входят в разрешённую область программы Bug Bounty или письменного разрешения.

### Полный пайплайн
Проходит этапы discovery, анализа и проверки, сохраняет результаты и формирует отчёты:
```bash
python main.py --full authorized-target.example.test
```

### Отдельные режимы

```bash
# Пассивная разведка (WHOIS + DNS)
python main.py --passive authorized-target.example.test

# Поиск и валидация поддоменов
python main.py --subdomains authorized-target.example.test

# Определение версий сервисов и веб-стека
python main.py --server_version authorized-target.example.test

# Поиск скрытых файлов и путей (fuzzing)
python main.py --file_scan authorized-target.example.test

# Сканирование шаблонами Nuclei
python main.py --nuclei authorized-target.example.test

# Добавить домен в scope только при наличии явного разрешения на него
python main.py --full authorized-target.example.test \
  --allow-scope another-authorized-target.example.test
```

Замените примерную цель на ресурс, разрешённый правилами программы. По умолчанию scope включает точную цель и её поддомены; дополнительные корни передаются через `--allow-scope`. IP-адреса ограничиваются точным IP. HTTP-переходы за пределы scope не выполняются там, где их можно контролировать.

### История и сравнение
```bash
python main.py --list-scans
python main.py --scan-info 12
python main.py --export-scan 12
python main.py --diff authorized-target.example.test
```
Отчёты по скану сохраняются в `reports/output/<цель>/<скан>/`.

### Интерактивное меню
```bash
python menu.py
```
Меню позволяет запускать режимы, настраивать scope и лимиты, просматривать историю и экспортировать отчёты.

---

## 📁 Структура проекта

```text
ShadowScope/
├── core/                  # Ядро: пайплайн, хранилище SQLite и diff
│   ├── pipeline.py        # Оркестрация этапов сканирования
│   ├── storage.py         # Работа с базой данных активов и находок
│   └── diff.py            # Движок вычисления разницы запусков
├── modules/               # Модули расширенного сканирования
│   ├── recon/             # dnsx, httpx, wayback, crawl
│   ├── analysis/          # whatweb, gf-фильтр
│   └── vuln/              # nuclei, ffuf, takeover
├── scanner/               # Локальные сканеры (nmap, whois, traffic)
├── reports/               # Генераторы отчётов (Markdown, HTML, JSON)
├── utils/                 # Утилиты (асинхронный менеджер, shell, healthcheck)
├── tests/                 # Автоматические unit-тесты
├── .github/workflows/     # GitHub Actions CI
├── config.py              # Парсер настроек
├── logger.py              # Логирование событий
├── install.sh             # Автоустановщик окружения
├── main.py                # Точка входа CLI
└── menu.py                # Интерактивное TUI-меню
```

---

## ⚙️ Конфигурация

Параметры можно переопределить в `config.json` или переменными окружения `SHADOWSCOPE_<ИМЯ_ПАРАМЕТРА>`. Например:

```json
{
  "bug_bounty_header_value": "ShadowScope/2.0"
}
```

Этот маркер передаётся как `X-Bug-Bounty` только HTTP-инструментам, которые поддерживают пользовательские заголовки. DNS-запросы, Nmap и обращения к сторонним источникам данных им не маркируются. Маркер помогает идентифицировать запросы, но не подтверждает наличие разрешения.

## 🧪 Тесты и CI
Установить runtime- и dev-зависимости, затем запустить тесты:
```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m compileall -q main.py menu.py config.py core modules reports scanner utils tests
```

GitHub Actions выполняет тесты и проверку компиляции при `push` и `pull_request` на Python 3.10 и 3.12. Тесты используют временную SQLite-базу и моки; реальные сетевые сканы не запускаются.

---

## ⚖️ Дисклеймер (Legal Disclaimer)

ShadowScope предназначен для обучения и авторизованной проверки безопасности. Используйте его только на целях и с методами, разрешёнными владельцем ресурса или правилами программы Bug Bounty. Пользователь отвечает за соблюдение применимых правил и законов.

---

## 📜 Лицензия

Проект распространяется под открытой лицензией [MIT](LICENSE).
