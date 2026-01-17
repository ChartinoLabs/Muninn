"""Muninn parsers package.

Importing this package automatically discovers and registers all parsers.
"""

import importlib
import pkgutil


def _discover_parsers() -> None:
    """Auto-discover and import all parser modules to trigger registration."""
    # Walk all subpackages and modules under this package
    for module_info in pkgutil.walk_packages(__path__, prefix=__name__ + "."):
        importlib.import_module(module_info.name)


_discover_parsers()
