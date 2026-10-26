<div align="center">

# 🛰️ ShadowScope

**ShadowScope — модульный CLI-инструмент на Python для авторизованной разведки и анализа поверхности атаки.** Объединяет внешние инструменты, сохраняет результаты в SQLite и формирует отчёты для сравнения запусков.

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.12-blue)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.linux.org/)

</div>

---

## Содержание

- [О проекте](#-о-проекте)
- [Ключевые возможности](#-ключевые-возможности)
- [Установка](#-установка)
- [Использование](#-использование)
- [Структура проекта](#-структура-проекта)
- [Конфигурация](#️-конфигурация)
- [Тесты и CI](#-тесты-и-ci)
- [Ограничения и безопасность](#️-ограничения-и-безопасность)

---

## 📖 О проекте

ShadowScope — учебный CLI-проект на Python для авторизованной разведки и ограниченных проверок безопасности. Он запускает доступные внешние утилиты, сохраняет результаты сканирований в SQLite, позволяет сравнивать запуски и экспортировать отчёты.

### Что демонстрирует проект
- Интеграцию Python-оркестратора с внешними CLI-инструментами.
- Асинхронное управление задачами, контроль частоты запросов и обработку частичных ошибок.
- Scope-проверки в поддерживаемых модулях, хранение истории результатов в SQLite и сравнение запусков.
- Генерацию Markdown-, HTML- и JSON-отчётов.
- Автоматические тесты и GitHub Actions CI для Python 3.10 и 3.12.

---

## ✨ Ключевые возможности

- **Recon:** WHOIS/DNS, сбор поддоменов (`subfinder`, `amass`, `sublist3r`), DNS-резолвинг (`dnsx`) и HTTP-пробинг (`httpx`).
- **Discovery:** архивные URL (`waybackurls`, `gau`), краулинг (`katana`, `gospider`), фильтрация URL-параметров (`gf`).
- **Fingerprinting:** `whatweb`, Wappalyzer и Nmap.
- **Проверки:** Nuclei, ffuf, Gobuster/Dirb и проверка takeover через subjack/Nuclei.
- **Дополнительные проверки:** `tlsx`, `testssl.sh`, `gowitness` и обнаружение документации OpenAPI/Swagger.
- **Безопасность запуска:** scope-проверки в поддерживаемых модулях, настраиваемые лимиты скорости и идентифицирующий заголовок `X-Bug-Bounty`.
- **История и отчёты:** SQLite, diff между запусками и экспорт Markdown/HTML/JSON в `reports/output/<цель>/<скан>/`. Отчёты включают severity, статус находок и рекомендации, если они доступны в данных сканера.

Внешние утилиты не устанавливаются через `requirements.txt`. Без нужной программы соответствующий режим может сообщить, что утилита недоступна. Список проверяемых инструментов можно посмотреть командой `--check-tools`.

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

Требуются Linux, Python 3.10 или 3.12 и Git. Клонируйте репозиторий и выполните команды из его корня. Python-пакеты устанавливаются отдельно от внешних сканеров:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Проверьте наличие внешних утилит в `PATH`:

```bash
python main.py --check-tools
```

Опциональный `install.sh` устанавливает системные пакеты через `apt`, `dnf` или `pacman`, создаёт `.venv` и устанавливает часть Go-инструментов. Скрипт также пытается настроить права для `tshark`. Перед запуском просмотрите его содержимое: для установки системных пакетов потребуются права `sudo`.

```bash
chmod +x install.sh
./install.sh          # системные зависимости, Python-зависимости и поддерживаемые Go-инструменты
./install.sh --no-go  # пропустить установку Go-инструментов
```

Установщик не ставит все интеграции проекта. Такие утилиты, как `testssl.sh`, `gowitness`, `tlsx`, `ffuf`, `katana`, `waybackurls` и `gau`, при необходимости устанавливаются отдельно по официальным инструкциям соответствующих проектов. Добавьте установленные бинарные файлы в `PATH`, затем повторите `--check-tools`.

---

## 💻 Использование

Перед запуском убедитесь, что домен, IP-адрес и выбранные методы входят в scope программы Bug Bounty или письменного разрешения. Список актуальных аргументов CLI можно вывести командой `python main.py --help`.

### Полный пайплайн

`--full` последовательно выполняет DNS-разрешение, HTTP-пробинг, fingerprinting, получение архивных URL и краулинг, фильтрацию URL, Nuclei, проверку путей через ffuf и проверку takeover при наличии поддоменов. Затем сохраняет результаты и формирует отчёты. Отсутствие внешней утилиты или ошибка отдельного этапа не обязательно останавливает весь запуск; проверяйте итоговый статус и лог.

```bash
python main.py --full authorized-target.example.test
```

Добавлять дополнительные корни scope следует только при наличии отдельного разрешения:

```bash
python main.py --full authorized-target.example.test \
  --allow-scope another-authorized-target.example.test
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

# Nmap HTTP enumeration
python main.py --network_traffic authorized-target.example.test

# Сканирование шаблонами Nuclei
python main.py --nuclei authorized-target.example.test

# Проверка TLS-сертификата / конфигурации TLS
python main.py --tlsx https://authorized-target.example.test
python main.py --testssl https://authorized-target.example.test

# Скриншот и поиск API-документации того же origin
python main.py --gowitness https://authorized-target.example.test
python main.py --api-docs https://authorized-target.example.test

# Захват сетевого трафика (может потребовать дополнительных системных прав)
python main.py --capture --interface eth0 --duration 20 --count 50 \
  authorized-target.example.test
```

Несколько режимов можно запускать одной командой:

```bash
python main.py --passive --subdomains --nuclei authorized-target.example.test
```

Для поддерживаемых scope-проверкой режимов политика разрешает исходную цель, её поддомены и явно добавленные через `--allow-scope` корни; IP-адрес разрешает только точное совпадение. Поддержка и строгость scope-контроля различаются между интеграциями, особенно для внешних утилит. Не считайте эту проверку заменой правилам программы или ручному контролю цели.

`--file_scan` по умолчанию использует `/usr/share/wordlists/dirb/common.txt`. Если сервер возвращает одинаковую страницу для несуществующих путей (часто у SPA), Gobuster прекращает сканирование. Размер такой страницы можно проверить случайным путём и передать Gobuster через `--exclude-length <размер>`; ShadowScope выводит ошибку Gobuster вместо пустого успешного результата.

Дополнительные одиночные режимы `--tlsx`, `--testssl`, `--gowitness` и `--api-docs` не входят в `--full`: запускайте их отдельно и только в разрешённом scope. Для них нужны внешние программы `tlsx`, `testssl.sh`, `gowitness` и Chrome/Chromium для снимков экрана. Проверка API-документации не загружает спецификацию, если Swagger UI ссылается на другой origin.

### История, отчёты и интерактивное меню

```bash
# Список сохранённых сканирований
python main.py --list-scans

# Информация о запуске и повторное создание его отчётов
python main.py --scan-info 12
python main.py --export-scan 12

# Сравнение последнего запуска цели с предыдущим
python main.py --diff authorized-target.example.test

# Интерактивный режим
python menu.py
```

Сканирования хранятся в `data/shadowscope.db`, логи — в `logs/`, отчёты — в `reports/output/`. Для просмотра или повторного экспорта исторического запуска укажите его числовой ID. Интерактивное меню позволяет запускать режимы, настраивать параметры и управлять сохранёнными сканированиями.

---

## 📁 Структура проекта

```text
ShadowScope/
├── .github/
│   └── workflows/
│       └── ci.yml                 # Тесты, проверка зависимостей и Bandit
├── core/
│   ├── diff.py                    # Сравнение запусков
│   ├── pipeline.py                # Полный пайплайн сканирования
│   ├── scope.py                   # Проверка разрешённых целей
│   └── storage.py                 # История сканов, активы и находки (SQLite)
├── modules/
│   ├── analysis/
│   │   ├── gf_filter.py           # Фильтрация URL по шаблонам gf
│   │   └── whatweb.py             # Fingerprinting веб-технологий
│   ├── recon/
│   │   ├── crawl.py               # Краулинг веб-страниц
│   │   ├── dnsx.py                # DNS-разрешение
│   │   ├── httpx_probe.py         # HTTP-пробинг
│   │   └── wayback.py             # Архивные URL
│   └── vuln/
│       ├── ffuf_scan.py           # Поиск путей через ffuf
│       ├── nuclei_scan.py         # Запуск Nuclei
│       └── takeover.py            # Проверка takeover поддоменов
├── reports/
│   ├── html.py                    # HTML-отчёты
│   ├── json_export.py             # JSON-отчёты
│   ├── log_export.py              # Экспорт логов
│   ├── markdown.py                # Markdown-отчёты
│   ├── paths.py                  # Пути и безопасные имена отчётов
│   └── summary.py                # Сводка находок
├── scanner/
│   ├── active.py                  # Активные сетевые проверки
│   ├── api_docs.py                # Поиск OpenAPI/Swagger
│   ├── extra_tools.py             # tlsx, testssl.sh, gowitness
│   ├── file_scan.py               # Gobuster/Dirb
│   ├── network_traffic.py         # Nmap HTTP enumeration
│   ├── passive.py                 # WHOIS и DNS
│   ├── server_version.py          # Nmap и Wappalyzer
│   └── subdomain_scanner.py       # Поиск поддоменов
├── tests/
│   └── test_core.py               # Автоматические тесты
├── utils/
│   ├── async_utils.py             # Управление асинхронными задачами
│   ├── healthcheck.py             # Проверка внешних утилит
│   ├── rate_limiter.py            # Ограничение частоты запросов
│   └── shell.py                   # Запуск внешних команд
├── .gitignore                     # Исключения для локальных данных и артефактов
├── config.py                      # Настройки проекта
├── install.sh                     # Установка системных и Python-зависимостей
├── logger.py                      # Логирование
├── main.py                        # CLI и запуск одиночных режимов
├── menu.py                        # Интерактивное меню
├── requirements-dev.txt           # Зависимости для разработки и CI
└── requirements.txt               # Python-зависимости приложения
```

Во время работы создаются `data/shadowscope.db`, файлы в `logs/` и отчёты в `reports/output/`. Эти локальные данные и виртуальные окружения не входят в исходное дерево репозитория.

---

## ⚙️ Конфигурация

Параметры можно переопределить в корневом `config.json` или переменными окружения `SHADOWSCOPE_<ИМЯ_ПАРАМЕТРА>`. Переменные окружения имеют приоритет над файлом конфигурации.

```json
{
  "rate_limit": 50,
  "nuclei_rate_limit": 25,
  "timeout": 5,
  "max_concurrent_tasks": 5,
  "nuclei_severity": "low,medium,high,critical",
  "nuclei_templates": "",
  "bug_bounty_header_value": "ShadowScope/2.0"
}
```

Например, `SHADOWSCOPE_TIMEOUT=10` переопределит тайм-аут. Доступные ключи: `rate_limit`, `nuclei_rate_limit`, `timeout`, `max_concurrent_tasks`, `nuclei_severity`, `nuclei_templates` и `bug_bounty_header_value`.

`bug_bounty_header_value` задаёт значение заголовка `X-Bug-Bounty`. Он передаётся только HTTP-инструментам, поддерживающим пользовательские заголовки; DNS-запросы, Nmap и обращения к сторонним источникам данных этим заголовком не маркируются. Маркер помогает идентифицировать запросы, но не подтверждает наличие разрешения. Не помещайте в конфигурацию секреты: она не является хранилищем секретов.

## 🧪 Тесты и CI
Установить runtime- и dev-зависимости, затем запустить тесты:
```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m compileall -q main.py menu.py config.py core modules reports scanner utils tests
```

Дополнительные проверки безопасности самого проекта:
```bash
pip-audit -r requirements-dev.txt
bandit -ll -r main.py menu.py config.py core modules reports scanner utils
```

Bandit запускается с порогом Medium: низкоуровневые предупреждения о штатном вызове внешних CLI-инструментов не считаются ошибкой CI.

GitHub Actions выполняет тесты и проверку компиляции при `push` и `pull_request` на Python 3.10 и 3.12, а также проверяет зависимости и Python-код с помощью `pip-audit` и Bandit. Тесты используют временную SQLite-базу и моки; реальные сетевые сканы не запускаются.

---

## ⚠️ Ограничения и безопасность

- Используйте проект только на системах, для которых у вас есть разрешение; соблюдайте scope, правила программы, лимиты запросов и запреты на автоматизированное сканирование.
- Некоторые режимы выполняют активные запросы или запускают внешние инструменты. Настройка `rate_limit` не обязательно управляет скоростью всех внешних программ.
- Результаты автоматизированных инструментов могут быть неполными или ошибочными. Проверяйте находки вручную и не воспринимайте отчёт как подтверждение уязвимости.
- Обнаружение версии, открытого пути или совпадения с шаблоном само по себе не доказывает наличие эксплуатируемой уязвимости.
- `--capture` использует `tshark` через PyShark; доступ к захвату пакетов зависит от системных разрешений и конфигурации ОС.
- Локальные логи, отчёты, базы данных, виртуальные окружения и `config.json` исключены из Git. `.gitignore` не удаляет файлы, уже отслеживаемые Git.

## ⚖️ Дисклеймер

ShadowScope предоставляется для обучения и авторизованной проверки безопасности. Пользователь самостоятельно отвечает за выбор цели, наличие разрешения и соблюдение применимых правил и законов. Авторы проекта не несут ответственности за неправомерное использование инструмента.

## Лицензия

В репозитории пока не указана лицензия. Перед публичной публикацией добавьте файл лицензии, чтобы явно определить условия использования и распространения проекта.

---
