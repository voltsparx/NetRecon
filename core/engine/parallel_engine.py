import os
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed


class ParallelEngine:
    def __init__(self, max_workers=None, backend="thread", thread_name_prefix="netrecon-parallel"):
        default_workers = os.cpu_count() or 4
        self.max_workers = max(1, int(max_workers or default_workers))
        selected = str(backend or "thread").strip().lower()
        self.backend = selected if selected in {"thread", "process"} else "thread"
        self.thread_name_prefix = thread_name_prefix

    def map_unordered(self, items, worker, fallback_to_threads=True):
        queue = list(items)
        if not queue:
            return

        if self.backend == "process":
            try:
                with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
                    futures = {executor.submit(worker, item): item for item in queue}
                    for future in as_completed(futures):
                        item = futures[future]
                        try:
                            yield item, future.result(), None
                        except Exception as exc:
                            yield item, None, exc
                return
            except Exception:
                if not fallback_to_threads:
                    raise

        with ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix=self.thread_name_prefix,
        ) as executor:
            futures = {executor.submit(worker, item): item for item in queue}
            for future in as_completed(futures):
                item = futures[future]
                try:
                    yield item, future.result(), None
                except Exception as exc:
                    yield item, None, exc
