"""Local parser overlay loader."""

from __future__ import annotations

import importlib
import pkgutil
import sys
from pathlib import Path

from muninn.config import get_parser_paths
from muninn.registry import registration_source


def load_local_parsers(
    paths: list[str | Path] | tuple[str | Path, ...] | None = None,
) -> list[str]:
    """Import parser modules from external paths and register them as local.

    Args:
        paths: Search paths to scan for parser modules. If omitted, uses
            configured parser paths from runtime config.

    Returns:
        List of imported module names.
    """
    overlay_paths = (
        get_parser_paths() if paths is None else tuple(Path(path) for path in paths)
    )
    imported_modules: list[str] = []

    for path in overlay_paths:
        resolved_path = path.expanduser().resolve()
        if not resolved_path.exists() or not resolved_path.is_dir():
            msg = f"Parser path does not exist or is not a directory: {resolved_path}"
            raise ValueError(msg)

        path_str = str(resolved_path)
        if path_str not in sys.path:
            sys.path.insert(0, path_str)

        with registration_source("local"):
            for module_info in pkgutil.walk_packages([path_str]):
                module_name = module_info.name
                if module_name in sys.modules:
                    importlib.reload(sys.modules[module_name])
                else:
                    importlib.import_module(module_name)
                imported_modules.append(module_name)

    return imported_modules
