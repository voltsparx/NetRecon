import importlib.util
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "plugins"


def _iter_plugin_files():
    if not PLUGIN_DIR.exists():
        return []
    return sorted(
        path for path in PLUGIN_DIR.glob("*.py")
        if not path.name.startswith("_")
    )


def run_plugins(target, open_ports, services):
    findings = {}

    for plugin_path in _iter_plugin_files():
        module_name = f"netrecon_plugin_{plugin_path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, plugin_path)
        if not spec or not spec.loader:
            continue

        try:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception as exc:
            findings[plugin_path.stem] = {"error": str(exc)}
            continue

        run_func = getattr(module, "run", None)
        if not callable(run_func):
            continue

        try:
            result = run_func(target, open_ports, services)
            if result:
                findings[plugin_path.stem] = result
        except Exception as exc:
            findings[plugin_path.stem] = {"error": str(exc)}

    return findings


def list_plugins():
    return [path.stem for path in _iter_plugin_files()]
