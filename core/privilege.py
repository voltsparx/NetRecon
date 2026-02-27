import os
import shutil
import subprocess
import sys


def _is_windows_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def is_privileged():
    if os.name == "nt":
        return _is_windows_admin()
    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid):
        return geteuid() == 0
    return False


def privilege_name():
    return "Administrator" if os.name == "nt" else "root"


def can_sudo_relaunch():
    return os.name != "nt" and shutil.which("sudo") is not None


def relaunch_with_sudo():
    if not can_sudo_relaunch():
        return False, "sudo is unavailable on this platform."
    if os.environ.get("NETRECON_ELEVATED") == "1":
        return False, "Elevation was attempted but privileged mode is still unavailable."

    env = os.environ.copy()
    env["NETRECON_ELEVATED"] = "1"
    cmd = ["sudo", "-E", sys.executable] + sys.argv
    code = subprocess.call(cmd, env=env)
    return True, int(code)
