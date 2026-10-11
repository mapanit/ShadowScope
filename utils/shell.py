"""
Единая точка запуска внешних инструментов.
Все Go-тулзы вызываются через неё, чтобы одинаково обрабатывать
таймауты, отсутствие бинаря и stderr.
"""
import shutil
import subprocess


class ToolNotInstalled(Exception):
    pass


class ToolTimeout(Exception):
    pass


def run_tool(cmd: list[str], timeout: int = 120, input_text: str | None = None,
             check_path: str | None = None) -> tuple[str, str]:
    """
    Возвращает (stdout, stderr).
    check_path — имя бинаря для проверки наличия в PATH.
    """
    binary = check_path or cmd[0]
    if shutil.which(binary) is None:
        raise ToolNotInstalled(f"{binary} не найден в PATH")

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, input=input_text,
        )
        return proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        raise ToolTimeout(f"{binary}: превышен таймаут {timeout}s")


def lines(stdout: str) -> list[str]:
    return [l.strip() for l in stdout.splitlines() if l.strip()]