import asyncio


class AsyncEngine:
    def __init__(self, concurrency=20):
        self.concurrency = max(1, int(concurrency or 1))

    async def _gather_limited(self, coroutines):
        semaphore = asyncio.Semaphore(self.concurrency)

        async def _guard(coro):
            async with semaphore:
                return await coro

        tasks = [_guard(coro) for coro in coroutines]
        if not tasks:
            return []
        return await asyncio.gather(*tasks, return_exceptions=True)

    def run_coroutines(self, coroutines):
        jobs = list(coroutines)
        if not jobs:
            return []

        async def _runner():
            return await self._gather_limited(jobs)

        try:
            return asyncio.run(_runner())
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(_runner())
            finally:
                loop.close()
