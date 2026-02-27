"""Tests for the plugin discovery, loading, validation, and lifecycle."""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pytest

from squirrelops_home_sensor.plugins.base import BaseAgentModule
from squirrelops_home_sensor.plugins.loader import PluginLoader


# ---------------------------------------------------------------------------
# Helpers -- concrete plugin for testing the ABC
# ---------------------------------------------------------------------------


class FakePlugin(BaseAgentModule):
    """Minimal concrete implementation of BaseAgentModule for tests."""

    name = "fake_plugin"
    version = "0.1.0"

    def __init__(self) -> None:
        super().__init__()
        self.setup_called = False
        self.started = False
        self.stopped = False

    async def setup(self, config: dict[str, Any], db: Any, event_bus: Any) -> None:
        self.setup_called = True

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.stopped = True

    async def health_check(self) -> bool:
        return True


# ---------------------------------------------------------------------------
# BaseAgentModule tests
# ---------------------------------------------------------------------------


class TestBaseAgentModule:
    """Verify the abstract base class contract."""

    def test_cannot_instantiate_abc(self) -> None:
        with pytest.raises(TypeError):
            BaseAgentModule()  # type: ignore[abstract]

    def test_concrete_subclass_instantiates(self) -> None:
        plugin = FakePlugin()
        assert plugin.name == "fake_plugin"
        assert plugin.version == "0.1.0"

    @pytest.mark.asyncio
    async def test_lifecycle_methods(self) -> None:
        plugin = FakePlugin()
        await plugin.setup({}, None, None)
        assert plugin.setup_called

        await plugin.start()
        assert plugin.started

        assert await plugin.health_check() is True

        await plugin.stop()
        assert plugin.stopped

    def test_subclass_missing_abstract_methods_raises(self) -> None:
        """A subclass that omits abstract methods cannot be instantiated."""

        class IncompletePlugin(BaseAgentModule):
            name = "incomplete"
            version = "0.0.1"

        with pytest.raises(TypeError):
            IncompletePlugin()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# PluginLoader tests
# ---------------------------------------------------------------------------


@pytest.fixture()
def plugin_dir(tmp_path: Path) -> Path:
    """Create a temporary plugin directory."""
    return tmp_path


@pytest.fixture()
def valid_plugin_file(plugin_dir: Path) -> Path:
    """Write a valid plugin module to the plugin directory."""
    code = textwrap.dedent("""\
        from __future__ import annotations
        from typing import Any
        from squirrelops_home_sensor.plugins.base import BaseAgentModule

        class SampleAgent(BaseAgentModule):
            name = "sample_agent"
            version = "1.0.0"

            async def setup(self, config: dict[str, Any], db: Any, event_bus: Any) -> None:
                pass

            async def start(self) -> None:
                pass

            async def stop(self) -> None:
                pass

            async def health_check(self) -> bool:
                return True
    """)
    path = plugin_dir / "sample_agent.py"
    path.write_text(code)
    return path


@pytest.fixture()
def second_valid_plugin_file(plugin_dir: Path) -> Path:
    """Write a second valid plugin module."""
    code = textwrap.dedent("""\
        from __future__ import annotations
        from typing import Any
        from squirrelops_home_sensor.plugins.base import BaseAgentModule

        class AnotherAgent(BaseAgentModule):
            name = "another_agent"
            version = "2.0.0"

            async def setup(self, config: dict[str, Any], db: Any, event_bus: Any) -> None:
                pass

            async def start(self) -> None:
                pass

            async def stop(self) -> None:
                pass

            async def health_check(self) -> bool:
                return True
    """)
    path = plugin_dir / "another_agent.py"
    path.write_text(code)
    return path


@pytest.fixture()
def invalid_plugin_no_subclass(plugin_dir: Path) -> Path:
    """Write a Python file with no BaseAgentModule subclass."""
    code = textwrap.dedent("""\
        # This module has no BaseAgentModule subclass
        def some_utility():
            return 42
    """)
    path = plugin_dir / "not_a_plugin.py"
    path.write_text(code)
    return path


@pytest.fixture()
def syntax_error_plugin(plugin_dir: Path) -> Path:
    """Write a Python file with a syntax error."""
    code = "def broken(\n"
    path = plugin_dir / "broken_plugin.py"
    path.write_text(code)
    return path


class TestPluginLoaderDiscover:
    """PluginLoader.discover finds valid plugin module names."""

    def test_empty_directory(self, plugin_dir: Path) -> None:
        loader = PluginLoader(plugin_dir)
        assert loader.discover() == []

    def test_discovers_valid_plugin(
        self, plugin_dir: Path, valid_plugin_file: Path
    ) -> None:
        loader = PluginLoader(plugin_dir)
        names = loader.discover()
        assert "sample_agent" in names

    def test_discovers_multiple_plugins(
        self,
        plugin_dir: Path,
        valid_plugin_file: Path,
        second_valid_plugin_file: Path,
    ) -> None:
        loader = PluginLoader(plugin_dir)
        names = loader.discover()
        assert len(names) == 2
        assert "sample_agent" in names
        assert "another_agent" in names

    def test_skips_init_file(self, plugin_dir: Path) -> None:
        (plugin_dir / "__init__.py").write_text("")
        loader = PluginLoader(plugin_dir)
        assert loader.discover() == []

    def test_skips_pycache_directory(self, plugin_dir: Path) -> None:
        cache_dir = plugin_dir / "__pycache__"
        cache_dir.mkdir()
        (cache_dir / "cached.pyc").write_bytes(b"\x00")
        loader = PluginLoader(plugin_dir)
        assert loader.discover() == []

    def test_skips_non_python_files(self, plugin_dir: Path) -> None:
        (plugin_dir / "readme.txt").write_text("hello")
        (plugin_dir / "data.json").write_text("{}")
        loader = PluginLoader(plugin_dir)
        assert loader.discover() == []

    def test_nonexistent_directory(self, tmp_path: Path) -> None:
        loader = PluginLoader(tmp_path / "does_not_exist")
        assert loader.discover() == []


class TestPluginLoaderLoad:
    """PluginLoader.load imports and instantiates a single plugin."""

    @pytest.mark.asyncio
    async def test_load_valid_plugin(
        self, plugin_dir: Path, valid_plugin_file: Path
    ) -> None:
        loader = PluginLoader(plugin_dir)
        plugin = await loader.load("sample_agent")
        assert isinstance(plugin, BaseAgentModule)
        assert plugin.name == "sample_agent"
        assert plugin.version == "1.0.0"

    @pytest.mark.asyncio
    async def test_load_invalid_module_raises_value_error(
        self, plugin_dir: Path, invalid_plugin_no_subclass: Path
    ) -> None:
        loader = PluginLoader(plugin_dir)
        with pytest.raises(ValueError, match="No BaseAgentModule subclass"):
            await loader.load("not_a_plugin")

    @pytest.mark.asyncio
    async def test_load_nonexistent_module_raises_file_not_found(
        self, plugin_dir: Path
    ) -> None:
        loader = PluginLoader(plugin_dir)
        with pytest.raises(FileNotFoundError):
            await loader.load("nonexistent")

    @pytest.mark.asyncio
    async def test_load_syntax_error_raises(
        self, plugin_dir: Path, syntax_error_plugin: Path
    ) -> None:
        loader = PluginLoader(plugin_dir)
        with pytest.raises(SyntaxError):
            await loader.load("broken_plugin")


class TestPluginLoaderLoadAll:
    """PluginLoader.load_all discovers and loads all valid plugins."""

    @pytest.mark.asyncio
    async def test_load_all_empty_dir(self, plugin_dir: Path) -> None:
        loader = PluginLoader(plugin_dir)
        plugins = await loader.load_all()
        assert plugins == []

    @pytest.mark.asyncio
    async def test_load_all_with_valid_plugins(
        self,
        plugin_dir: Path,
        valid_plugin_file: Path,
        second_valid_plugin_file: Path,
    ) -> None:
        loader = PluginLoader(plugin_dir)
        plugins = await loader.load_all()
        assert len(plugins) == 2
        names = {p.name for p in plugins}
        assert names == {"sample_agent", "another_agent"}

    @pytest.mark.asyncio
    async def test_load_all_skips_invalid_continues_with_valid(
        self,
        plugin_dir: Path,
        valid_plugin_file: Path,
        invalid_plugin_no_subclass: Path,
    ) -> None:
        """A bad plugin is logged and skipped; valid plugins still load."""
        loader = PluginLoader(plugin_dir)
        plugins = await loader.load_all()
        assert len(plugins) == 1
        assert plugins[0].name == "sample_agent"

    @pytest.mark.asyncio
    async def test_load_all_skips_syntax_error(
        self,
        plugin_dir: Path,
        valid_plugin_file: Path,
        syntax_error_plugin: Path,
    ) -> None:
        loader = PluginLoader(plugin_dir)
        plugins = await loader.load_all()
        assert len(plugins) == 1
        assert plugins[0].name == "sample_agent"


class TestPluginLifecycle:
    """Full lifecycle: load -> setup -> start -> health_check -> stop."""

    @pytest.mark.asyncio
    async def test_full_lifecycle(
        self, plugin_dir: Path, valid_plugin_file: Path
    ) -> None:
        loader = PluginLoader(plugin_dir)
        plugin = await loader.load("sample_agent")

        # Setup
        await plugin.setup(config={"key": "value"}, db=None, event_bus=None)

        # Start
        await plugin.start()

        # Health check
        healthy = await plugin.health_check()
        assert healthy is True

        # Stop
        await plugin.stop()
