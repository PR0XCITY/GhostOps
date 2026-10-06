"""Locate external command-line tools (opa, infracost, terraform)."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


def registry_path() -> str | None:
    """Current machine + user PATH from the Windows registry (None elsewhere).

    A process started before a tool was installed has a stale PATH; the registry
    holds what a fresh terminal would get.
    """
    if sys.platform != "win32":
        return None
    import winreg

    parts = []
    for root, key in (
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
        (winreg.HKEY_CURRENT_USER, "Environment"),
    ):
        try:
            with winreg.OpenKey(root, key) as handle:
                value, _ = winreg.QueryValueEx(handle, "Path")
        except OSError:
            continue
        parts.append(os.path.expandvars(value))
    return os.pathsep.join(parts) or None


def find_tool(name: str, env_var: str) -> str | None:
    """`env_var` if set (must exist), else PATH, else the registry PATH. None if absent."""
    configured = os.environ.get(env_var)
    if configured:
        return configured if Path(configured).is_file() else None
    found = shutil.which(name)
    if found:
        return found
    fresh = registry_path()
    return shutil.which(name, path=fresh) if fresh else None
