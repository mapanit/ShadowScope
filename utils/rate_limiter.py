"""Async request-start limiter shared by Python HTTP scanners."""
import asyncio


class AsyncRateLimiter:
    def __init__(self, requests_per_second: int | float):
        if requests_per_second <= 0:
            raise ValueError("requests_per_second должен быть больше нуля")
        self.interval = 1.0 / requests_per_second
        self._lock = asyncio.Lock()
        self._next_request_at = 0.0

    async def acquire(self) -> None:
        loop = asyncio.get_running_loop()
        async with self._lock:
            delay = self._next_request_at - loop.time()
            if delay > 0:
                await asyncio.sleep(delay)
            self._next_request_at = loop.time() + self.interval
