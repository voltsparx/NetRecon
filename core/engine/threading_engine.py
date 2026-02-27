from concurrent.futures import ThreadPoolExecutor, as_completed


class ThreadingEngine:
    def __init__(self, max_workers, thread_name_prefix="netrecon-worker"):
        self.max_workers = max(1, int(max_workers or 1))
        self.thread_name_prefix = thread_name_prefix
        self._executor = None

    def __enter__(self):
        self._executor = ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix=self.thread_name_prefix,
        )
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._executor is not None:
            self._executor.shutdown(wait=True)
            self._executor = None

    def _ensure_executor(self):
        if self._executor is None:
            self._executor = ThreadPoolExecutor(
                max_workers=self.max_workers,
                thread_name_prefix=self.thread_name_prefix,
            )
        return self._executor

    def submit(self, fn, *args, **kwargs):
        executor = self._ensure_executor()
        return executor.submit(fn, *args, **kwargs)

    def map_unordered(self, items, worker):
        queue = list(items)
        if not queue:
            return
        executor = self._ensure_executor()
        futures = {executor.submit(worker, item): item for item in queue}
        for future in as_completed(futures):
            item = futures[future]
            try:
                yield item, future.result(), None
            except Exception as exc:
                yield item, None, exc
