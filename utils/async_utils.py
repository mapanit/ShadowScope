"""
БАГИ в исходнике:
1. В классе AsyncTaskManager не было метода run_task — вызывающий код
   (subdomain_scanner.py) обращался к self.manager.run_task(...), которого
   не существовало -> AttributeError.
2. run_concurrently принимал список задач и вызывал их как `task()` внутри
   ОДНОГО run_in_executor-задания -> выполнение было последовательным
   внутри одного потока, а не параллельным, и падало с TypeError, если
   на вход приходили уже созданные объекты корутин (а не callable).
3. Был лишний модульный `run_task`, не связанный с классом — похоже,
   метод по ошибке объявили вне класса.

Ниже — исправленная версия: run_task оборачивает СИНХРОННУЮ функцию и
отдаёт её в ThreadPoolExecutor, не блокируя event loop; run_concurrently
параллельно ждёт список КОРУТИН через asyncio.gather.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Awaitable, Callable, List


class AsyncTaskManager:
    def __init__(self, max_workers: int = 5):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)

    async def run_task(self, func: Callable, *args, **kwargs) -> Any:
        """Выполнить блокирующую синхронную функцию в отдельном потоке,
        не блокируя event loop."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self.executor, lambda: func(*args, **kwargs))

    async def run_concurrently(self, coros: List[Awaitable]) -> List[Any]:
        """Параллельно дождаться списка корутин. Если одна упала с
        исключением — остальные результаты всё равно возвращаются."""
        return await asyncio.gather(*coros, return_exceptions=True)

    def shutdown(self):
        self.executor.shutdown(wait=True)