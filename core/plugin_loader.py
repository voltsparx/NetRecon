import importlib.util
import inspect
import threading
from pathlib import Path

from .engine.async_engine import AsyncEngine
from .engine.threading_engine import ThreadingEngine

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "plugins"
_PLUGIN_CACHE = None
_PLUGIN_CACHE_LOCK = threading.Lock()


def _iter_plugin_files():
    if not PLUGIN_DIR.exists():
        return []
    return sorted(
        path for path in PLUGIN_DIR.glob("*.py")
        if not path.name.startswith("_")
    )


def _load_plugin_inventory():
    global _PLUGIN_CACHE
    if _PLUGIN_CACHE is not None:
        return _PLUGIN_CACHE

    with _PLUGIN_CACHE_LOCK:
        if _PLUGIN_CACHE is not None:
            return _PLUGIN_CACHE

        plugins = []
        load_errors = {}

        for plugin_path in _iter_plugin_files():
            module_name = f"netrecon_plugin_{plugin_path.stem}"
            spec = importlib.util.spec_from_file_location(module_name, plugin_path)
            if not spec or not spec.loader:
                continue

            try:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
            except Exception as exc:
                load_errors[plugin_path.stem] = {"error": str(exc)}
                continue

            run_func = getattr(module, "run", None)
            if not callable(run_func):
                continue

            plugins.append(
                {
                    "name": plugin_path.stem,
                    "run": run_func,
                    "is_async": inspect.iscoroutinefunction(run_func),
                }
            )

        _PLUGIN_CACHE = (plugins, load_errors)
        return _PLUGIN_CACHE


async def _run_async_plugin(plugin_name, run_func, target, open_ports, services):
    try:
        result = await run_func(target, list(open_ports), dict(services))
        return plugin_name, result, None
    except Exception as exc:
        return plugin_name, None, str(exc)


def run_plugins(target, open_ports, services, max_workers=6, async_limit=16):
    findings = {}
    plugins, load_errors = _load_plugin_inventory()
    findings.update(load_errors)
    if not plugins:
        return findings

    normalized_ports = tuple(open_ports or [])
    normalized_services = dict(services or {})
    safe_workers = max(1, int(max_workers or 1))
    safe_async_limit = max(1, int(async_limit or safe_workers))

    sync_jobs = []
    async_jobs = []
    for plugin in plugins:
        name = plugin["name"]
        run_func = plugin["run"]
        if plugin["is_async"]:
            async_jobs.append(_run_async_plugin(name, run_func, target, normalized_ports, normalized_services))
        else:
            sync_jobs.append((name, run_func))

    if sync_jobs:
        def _run_sync(job):
            plugin_name, run_func = job
            result = run_func(target, list(normalized_ports), dict(normalized_services))
            return plugin_name, result

        with ThreadingEngine(max_workers=safe_workers, thread_name_prefix="plugin-sync") as engine:
            for job, payload, error in engine.map_unordered(sync_jobs, _run_sync):
                plugin_name = job[0]
                if error is not None:
                    findings[plugin_name] = {"error": str(error)}
                    continue
                _, result = payload
                if result:
                    findings[plugin_name] = result

    if async_jobs:
        async_engine = AsyncEngine(concurrency=safe_async_limit)
        for item in async_engine.run_coroutines(async_jobs):
            if isinstance(item, Exception):
                continue
            plugin_name, result, error = item
            if error:
                findings[plugin_name] = {"error": str(error)}
            elif result:
                findings[plugin_name] = result

    return findings


def list_plugins():
    return [path.stem for path in _iter_plugin_files()]
