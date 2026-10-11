import shutil
import subprocess

from config import Config
from utils.async_utils import AsyncTaskManager


class SubdomainScanner:
    def __init__(self, config: Config = None):
        # БАГ в исходнике: Config() использовался без импорта -> NameError
        self.config = config or Config()
        self.manager = AsyncTaskManager(max_workers=self.config.get_max_concurrent_tasks)

    @staticmethod
    def _tool_available(name: str) -> bool:
        return shutil.which(name) is not None

    # --- синхронные обёртки над внешними тулами (выполняются в потоке) ---

    def _run_subfinder_sync(self, domain):
        if not self._tool_available("subfinder"):
            return {"error": "subfinder не найден в PATH"}
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True, text=True, timeout=120,
        )
        return [line for line in result.stdout.splitlines() if line.strip()]

    def _run_amass_sync(self, domain):
        if not self._tool_available("amass"):
            return {"error": "amass не найден в PATH"}
        result = subprocess.run(
            ["amass", "enum", "-passive", "-silent", "-d", domain],
            capture_output=True, text=True, timeout=180,
        )
        return [line for line in result.stdout.splitlines() if line.strip()]

    def _run_sublist3r_sync(self, domain):
        if not self._tool_available("sublist3r"):
            return {"error": "sublist3r не найден в PATH"}
        result = subprocess.run(
            ["sublist3r", "-d", domain, "-o", "/dev/stdout"],
            capture_output=True, text=True, timeout=120,
        )
        return [line for line in result.stdout.splitlines() if line.strip() and "." in line]

    # --- асинхронные обёртки: реально не блокируют event loop ---

    async def run_subfinder(self, domain):
        try:
            # БАГ в исходнике: вызывался несуществующий self.manager.run_task
            return await self.manager.run_task(self._run_subfinder_sync, domain)
        except Exception as e:
            return {"error": f"Subfinder failed: {e}"}

    async def run_amass(self, domain):
        try:
            return await self.manager.run_task(self._run_amass_sync, domain)
        except Exception as e:
            return {"error": f"Amass failed: {e}"}

    async def run_sublist3r(self, domain):
        try:
            return await self.manager.run_task(self._run_sublist3r_sync, domain)
        except Exception as e:
            return {"error": f"Sublist3r failed: {e}"}

    async def scan_subdomains(self, domain):
        # БАГ в исходнике: в run_concurrently передавались уже созданные
        # объекты корутин, а manager пытался вызвать их как task() ->
        # TypeError. Плюс выполнение было последовательным в одном потоке.
        # Теперь run_concurrently честно работает через asyncio.gather,
        # и три тула реально опрашиваются параллельно.
        results = await self.manager.run_concurrently([
            self.run_sublist3r(domain),
            self.run_amass(domain),
            self.run_subfinder(domain),
        ])

        subdomains = set()
        errors = []
        for result in results:
            if isinstance(result, list):
                subdomains.update(result)
            elif isinstance(result, dict) and "error" in result:
                errors.append(result["error"])
            elif isinstance(result, Exception):
                errors.append(str(result))

        return {"subdomains": sorted(subdomains), "errors": errors}