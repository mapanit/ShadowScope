import math
import shutil
import subprocess

# Стандартный путь к словарю в Kali/большинстве security-дистрибутивов
# (пакет dirb ставит его сюда по умолчанию).
DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


class FileScanner:
    def __init__(self, rate_limit=10, headers=None):
        if rate_limit <= 0:
            raise ValueError("rate_limit должен быть больше нуля")
        self.rate_limit = rate_limit
        self.headers = headers or {}

    def _scan_timeout(self, wordlist):
        estimated_seconds = self.estimate_duration(wordlist)
        return max(180, math.ceil(estimated_seconds * 1.5) + 30)

    def estimate_duration(self, wordlist=DEFAULT_WORDLIST):
        try:
            with open(wordlist, encoding="utf-8", errors="replace") as stream:
                entries = sum(1 for line in stream if line.strip())
        except OSError as e:
            raise OSError(f"Не удалось прочитать словарь {wordlist}: {e}") from e

        return entries / self.rate_limit

    @staticmethod
    def _tool_available(name: str) -> bool:
        return shutil.which(name) is not None

    def scan_with_gobuster(self, url, wordlist=DEFAULT_WORDLIST):
        if not self._tool_available("gobuster"):
            return {"error": "gobuster не найден в PATH"}
        try:
            timeout = self._scan_timeout(wordlist)
            threads = min(self.rate_limit, 10)
            delay = threads / self.rate_limit
            command = [
                "gobuster", "dir", "-u", url, "-w", wordlist, "-q",
                "-t", str(threads), "--delay", f"{delay:.3f}s",
            ]
            for name, value in self.headers.items():
                command.extend(["-H", f"{name}: {value}"])
            result = subprocess.run(
                command,
                capture_output=True, text=True, timeout=timeout,
            )
            return {"found_files": [line for line in result.stdout.splitlines() if line.strip()]}
        except subprocess.TimeoutExpired:
            return {"error": f"Gobuster: превышен таймаут сканирования ({timeout} сек.)"}
        except OSError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"Gobuster scan failed: {e}"}

    def scan_with_dirb(self, url, wordlist=DEFAULT_WORDLIST):
        """
        В ТЗ требовался DirBuster, но это Java GUI-инструмент без вменяемого
        CLI. В качестве консольного аналога используется dirb — тот же
        принцип брутфорса директорий/файлов по словарю.
        """
        if not self._tool_available("dirb"):
            return {"error": "dirb не найден в PATH"}
        try:
            timeout = self._scan_timeout(wordlist)
            command = [
                "dirb", url, wordlist, "-S", "-z",
                str(max(1, round(1000 / self.rate_limit))),
            ]
            for name, value in self.headers.items():
                command.extend(["-H", f"{name}: {value}"])
            result = subprocess.run(
                command,
                capture_output=True, text=True, timeout=timeout,
            )
            found = [line for line in result.stdout.splitlines() if line.strip().startswith("+")]
            return {"found_files": found}
        except subprocess.TimeoutExpired:
            return {"error": f"Dirb: превышен таймаут сканирования ({timeout} сек.)"}
        except OSError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"Dirb scan failed: {e}"}

    def scan(self, url, wordlist=DEFAULT_WORDLIST):
        """Использует Gobuster, если он доступен, иначе запускает Dirb."""
        if self._tool_available("gobuster"):
            return {
                "gobuster": self.scan_with_gobuster(url, wordlist),
                "dirb": {"skipped": "Используется Gobuster"},
            }
        return {
            "gobuster": {"skipped": "Gobuster не установлен"},
            "dirb": self.scan_with_dirb(url, wordlist),
        }