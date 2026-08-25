"""Module discovery.

Walks the `adreaper.modules` package, imports every submodule, and registers
any concrete `BaseModule` subclass by its declared `name`. Dropping a new file
under `adreaper/modules/<category>/` is all it takes to add a module.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import Optional

from adreaper.core.logging import log
from adreaper.core.module import BaseModule

_registry: dict[str, type[BaseModule]] = {}
_loaded = False


def _iter_module_names(package_name: str = "adreaper.modules"):
    pkg = importlib.import_module(package_name)
    for info in pkgutil.walk_packages(pkg.__path__, prefix=pkg.__name__ + "."):
        if not info.ispkg:
            yield info.name


def discover(force: bool = False) -> dict[str, type[BaseModule]]:
    """Import all module files and return {name: module_class}."""
    global _loaded
    if _loaded and not force:
        return dict(_registry)
    _registry.clear()
    for mod_name in _iter_module_names():
        try:
            mod = importlib.import_module(mod_name)
        except Exception as e:  # a broken module shouldn't kill discovery
            log.warn("failed to import %s: %s", mod_name, e)
            continue
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if (
                issubclass(obj, BaseModule)
                and obj is not BaseModule
                and not inspect.isabstract(obj)
                and obj.__module__ == mod_name  # avoid re-registering imports
            ):
                key = obj.name
                if key in _registry and _registry[key] is not obj:
                    log.warn("duplicate module name %r (%s)", key, mod_name)
                _registry[key] = obj
    _loaded = True
    return dict(_registry)


def get(name: str) -> Optional[type[BaseModule]]:
    discover()
    return _registry.get(name)


def all_modules() -> dict[str, type[BaseModule]]:
    return discover()


def categories() -> dict[str, list[type[BaseModule]]]:
    """Group discovered modules by category for `list` output."""
    out: dict[str, list[type[BaseModule]]] = {}
    for cls in discover().values():
        out.setdefault(cls.category, []).append(cls)
    for v in out.values():
        v.sort(key=lambda c: c.name)
    return dict(sorted(out.items()))
