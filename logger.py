import logging
from datetime import datetime
from pathlib import Path

LOG_DIR = Path(__file__).parent / "logs"


class Logger:
    """
    Логгер с уникальным файлом на каждый запуск/скан.
    Файлы: logs/scan_YYYY-MM-DD_HH-MM-SS.log
    """

    def __init__(self, log_file: str | None = None, name: str = "ShadowScope"):
        LOG_DIR.mkdir(exist_ok=True)

        if log_file is None:
            stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            log_file = str(LOG_DIR / f"scan_{stamp}.log")

        self.log_file = log_file
        self.logger = logging.getLogger(f"{name}.{log_file}")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False  # не дублировать через root

        if not self.logger.handlers:
            formatter = logging.Formatter(
                "%(asctime)s - %(levelname)s - %(message)s"
            )

            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

    def log(self, label, data):
        is_error = isinstance(data, dict) and "error" in data
        if is_error:
            self.logger.error(f"{label}: {data}")
        else:
            self.logger.info(f"{label}: {data}")