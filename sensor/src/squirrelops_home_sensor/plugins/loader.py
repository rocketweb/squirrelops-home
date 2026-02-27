"""Dynamic plugin discovery and loading.

``PluginLoader`` scans a directory for Python files that contain a
concrete ``BaseAgentModule`` subclass, imports them, and instantiates
the plugin class.  Invalid modules are logged and skipped so one broken
plugin cannot prevent the rest from loading.
"""

from __future__ import annotations

import importlib.util
import inspect
import logging
import sys
from pathlib import Path
from types import ModuleType

from squirrelops_home_sensor.plugins.base import BaseAgentModule

logger = logging.getLogger(__name__)

# Files that are never treated as plugins.
_SKIP_NAMES = {"__init__.py"}


class PluginLoader:
    """Discover and load agent-module plugins from a directory.

    Parameters
    ----------
    plugin_dir:
        Path to the directory that holds ``*.py`` plugin files.
    """

    def __init__(self, plugin_dir: Path) -> None:
        self._plugin_dir = plugin_dir

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def discover(self) -> list[str]:
        """Return the module names (stems) of candidate plugin files.

        Skips ``__init__.py``, ``__pycache__``, and non-``.py`` files.
        Returns an empty list if the directory does not exist.
        """
        if not self._plugin_dir.is_dir():
            return []

        names: list[str] = []
        for path in sorted(self._plugin_dir.iterdir()):
            if path.is_dir():
                continue
            if path.suffix != ".py":
                continue
            if path.name in _SKIP_NAMES:
                continue
            names.append(path.stem)
        return names

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    async def load(self, module_name: str) -> BaseAgentModule:
        """Import *module_name* from the plugin directory and instantiate it.

        Raises
        ------
        FileNotFoundError
            If the corresponding ``.py`` file does not exist.
        SyntaxError
            If the module has a syntax error.
        ValueError
            If the module contains no ``BaseAgentModule`` subclass.
        """
        file_path = self._plugin_dir / f"{module_name}.py"
        if not file_path.is_file():
            raise FileNotFoundError(f"Plugin file not found: {file_path}")

        module = self._import_file(module_name, file_path)
        cls = self._find_plugin_class(module, module_name)
        return cls()

    async def load_all(self) -> list[BaseAgentModule]:
        """Discover and load all valid plugins.

        Modules that fail to import or lack a ``BaseAgentModule`` subclass
        are logged and skipped -- they do **not** prevent other plugins from
        loading.
        """
        plugins: list[BaseAgentModule] = []
        for name in self.discover():
            try:
                plugin = await self.load(name)
                plugins.append(plugin)
                logger.info("Loaded plugin %s v%s", plugin.name, plugin.version)
            except Exception:
                logger.warning(
                    "Skipping plugin %r -- failed to load", name, exc_info=True
                )
        return plugins

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _import_file(module_name: str, file_path: Path) -> ModuleType:
        """Import a single Python file as a module."""
        qualified = f"_squirrelops_plugin_{module_name}"
        spec = importlib.util.spec_from_file_location(qualified, file_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot create module spec for {file_path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[qualified] = module
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        return module

    @staticmethod
    def _find_plugin_class(
        module: ModuleType, module_name: str
    ) -> type[BaseAgentModule]:
        """Find the first concrete ``BaseAgentModule`` subclass in *module*."""
        for _attr_name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, BaseAgentModule)
                and obj is not BaseAgentModule
                and not inspect.isabstract(obj)
            ):
                return obj  # type: ignore[return-value]

        raise ValueError(
            f"No BaseAgentModule subclass found in plugin {module_name!r}"
        )
