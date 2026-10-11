import json
import os
from pathlib import Path


class Config:
    """
    Единая точка конфигурации ShadowScope.
    Значения по умолчанию можно переопределить через:
      - config.json в корне проекта
      - переменные окружения (SHADOWSCOPE_RATE_LIMIT и т.п.)
    """

    DEFAULTS = {
        "rate_limit": 50,              # запросов в секунду (глобально)
        "nuclei_rate_limit": 25,       # запросов в секунду для nuclei
        "timeout": 5,                  # тайм-аут сетевых операций, сек
        "max_concurrent_tasks": 5,     # макс. параллельных задач
        "nuclei_severity": "low,medium,high,critical",
        "nuclei_templates": "",        # пусто = все шаблоны
        "bug_bounty_header_value": "ShadowScope/2.0",
    }

    def __init__(self, config_path: str | None = None):
        self._data = dict(self.DEFAULTS)

        # 1) файл config.json в корне проекта (если есть)
        path = Path(config_path) if config_path else Path(__file__).parent / "config.json"
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self._data.update(json.load(f))
                self._data.pop("user_agent", None)
            except (json.JSONDecodeError, OSError):
                pass  # битый конфиг — работаем на дефолтах

        # 2) переменные окружения имеют приоритет
        for key in self.DEFAULTS:
            env_val = os.getenv(f"SHADOWSCOPE_{key.upper()}")
            if env_val is not None:
                # приводим к типу дефолта
                default = self.DEFAULTS[key]
                try:
                    if isinstance(default, int):
                        self._data[key] = int(env_val)
                    else:
                        self._data[key] = env_val
                except ValueError:
                    pass

    # --- геттеры (сохранены для обратной совместимости) ---
    @property
    def get_rate_limit(self):
        return self._data["rate_limit"]

    @property
    def get_nuclei_rate_limit(self):
        return self._data["nuclei_rate_limit"]

    @property
    def get_timeout(self):
        return self._data["timeout"]

    @property
    def get_max_concurrent_tasks(self):
        return self._data["max_concurrent_tasks"]

    @property
    def get_nuclei_severity(self):
        return self._data["nuclei_severity"]

    @property
    def get_nuclei_templates(self):
        return self._data["nuclei_templates"]

    @property
    def get_http_headers(self) -> dict[str, str]:
        value = self._data["bug_bounty_header_value"]
        if not isinstance(value, str) or not value.strip():
            raise ValueError("Значение заголовка X-Bug-Bounty не может быть пустым")
        if "\r" in value or "\n" in value:
            raise ValueError("Значение заголовка X-Bug-Bounty содержит перевод строки")
        return {"X-Bug-Bounty": value.strip()}

    def set(self, key: str, value):
        """Рантайм-изменение параметра (используется интерактивным меню)."""
        if key not in self.DEFAULTS:
            raise KeyError(f"Неизвестный параметр конфигурации: {key}")
        self._data[key] = value

    def as_dict(self):
        return dict(self._data)

    def save(self, path: str = "config.json"):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, ensure_ascii=False)