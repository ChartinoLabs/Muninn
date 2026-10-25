"""Tests for the process-wide built-in parser registry shared by runtimes."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from typing import Any

import pytest

import muninn.runtime as runtime_module
from muninn.config import ExecutionMode
from muninn.parser import BaseParser
from muninn.registry import RuntimeRegistry, register
from muninn.runtime import Muninn
from muninn.tags import ParserTag

_TEST_TAGS = frozenset({ParserTag.SYSTEM})


@pytest.fixture
def fresh_builtin_registry() -> Iterator[None]:
    """Force the next load_builtin_parsers() call to rebuild the shared registry."""
    saved = runtime_module._builtin_registry
    runtime_module._builtin_registry = None
    yield
    runtime_module._builtin_registry = saved


def _local_show_version_parser() -> type[BaseParser]:
    @register("nxos", "show version")
    class LocalShowVersionParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {"source": "local"}

    return LocalShowVersionParser


def test_runtimes_share_one_builtin_registry() -> None:
    """Every runtime reads the same built-in registry object."""
    first = Muninn()
    second = Muninn()
    first.load_builtin_parsers()
    second.load_builtin_parsers()

    assert first.registry._base is not None
    assert first.registry._base is second.registry._base


def test_load_builtin_parsers_returns_imported_modules_every_call() -> None:
    """Later calls report the same modules as the call that built the registry."""
    first = Muninn().load_builtin_parsers()
    second = Muninn().load_builtin_parsers()

    assert first
    assert first == second
    assert all(name.startswith("muninn.parsers.") for name in first)


def test_builtin_parsers_parse_through_shared_registry() -> None:
    """A runtime parses with a built-in parser it did not register itself."""
    runtime = Muninn()
    runtime.load_builtin_parsers()

    assert runtime.registry.get_parser_candidates("iosxr", "show isis interface brief")
    assert runtime.registry._literal_registry == {}
    assert runtime.registry._pattern_registry == {}


def test_local_registration_does_not_leak_to_other_runtimes() -> None:
    """A parser registered on one runtime is invisible to another."""
    owner = Muninn()
    other = Muninn()
    owner.load_builtin_parsers()
    other.load_builtin_parsers()
    owner.configuration.set_execution_mode(ExecutionMode.LOCAL_ONLY)
    other.configuration.set_execution_mode(ExecutionMode.LOCAL_ONLY)

    parser_cls = _local_show_version_parser()
    owner.registry.register_parser("nxos", "show version", parser_cls, "local")

    assert owner.parse("nxos", "show version", "output") == {"source": "local"}
    other_sources = {
        candidate.source
        for candidate in other.registry.get_parser_candidates("nxos", "show version")
    }
    assert "local" not in other_sources
    shared = owner.registry._base
    assert shared is not None
    assert all(
        candidate.source == "built_in"
        for candidates in shared._literal_registry.values()
        for candidate in candidates
    )


def test_local_parser_overrides_builtin_in_local_first_mode() -> None:
    """Local candidates in a runtime's own layer still win in local-first mode."""
    runtime = Muninn()
    runtime.load_builtin_parsers()
    runtime.configuration.set_execution_mode(ExecutionMode.LOCAL_FIRST_FALLBACK)
    runtime.registry.register_parser(
        "nxos", "show version", _local_show_version_parser(), "local"
    )

    candidates = runtime.registry.get_parser_candidates(
        "nxos", "show version", source_order=("local", "built_in")
    )
    assert [candidate.source for candidate in candidates][:2] == ["local", "built_in"]
    assert runtime.parse("nxos", "show version", "output") == {"source": "local"}


def test_registering_a_conflicting_builtin_checks_the_shared_base() -> None:
    """Duplicate detection sees parsers in the base, not only the runtime's layer."""
    base = RuntimeRegistry()
    layered = RuntimeRegistry(base=base)

    @register("nxos", "show version")
    class BaseParserCls(BaseParser):
        tags = _TEST_TAGS

        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {}

    @register("nxos", "show version")
    class ConflictingParser(BaseParser):
        tags = _TEST_TAGS

        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {}

    base.register_parser("nxos", "show version", BaseParserCls, "built_in")
    layered.register_parser("nxos", "show version", BaseParserCls, "built_in")
    assert len(layered.get_parser_candidates("nxos", "show version")) == 1

    with pytest.raises(ValueError, match="Duplicate literal registration"):
        layered.register_parser("nxos", "show version", ConflictingParser, "built_in")


def test_list_command_specs_includes_base_and_own_layer() -> None:
    """Listing a layered registry returns the base's specs and its own."""
    base = RuntimeRegistry()
    layered = RuntimeRegistry(base=base)

    @register("nxos", "show version")
    class BaseOnly(BaseParser):
        tags = _TEST_TAGS

        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {}

    base.register_parser("nxos", "show version", BaseOnly, "built_in")
    layered.register_parser("nxos", "show clock", _local_show_version_parser(), "local")

    listed = {(spec.source, spec.command_text) for spec in layered.list_command_specs()}
    assert listed == {("built_in", "show version"), ("local", "show clock")}
    assert len(base.list_command_specs()) == 1


def test_clear_detaches_the_shared_base() -> None:
    """Clearing a runtime registry empties it without touching the base."""
    runtime = Muninn()
    runtime.load_builtin_parsers()
    shared = runtime.registry._base
    assert shared is not None
    before = len(shared.list_command_specs())

    runtime.registry.clear()

    assert runtime.registry.list_command_specs() == []
    assert len(shared.list_command_specs()) == before


def test_registry_rejects_itself_as_base() -> None:
    """A registry cannot be layered over itself."""
    registry = RuntimeRegistry()
    with pytest.raises(ValueError, match="cannot use itself"):
        registry.set_base(registry)


@pytest.mark.usefixtures("fresh_builtin_registry")
def test_concurrent_first_loads_build_the_registry_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Threads racing on the first load all get one fully built registry.

    A barrier releases every thread at once. Module walking is slowed down so
    the threads overlap inside the build window; without the lock several of
    them would build, or one would read a half-filled registry.
    """
    threads_count = 16
    builds: list[int] = []
    real_walk = runtime_module.pkgutil.walk_packages

    def slow_walk(*args: Any, **kwargs: Any) -> Iterator[Any]:  # noqa: ANN401
        # walk_packages recurses into subpackages through this same patched
        # name; only the top-level walk marks the start of a build.
        if kwargs.get("prefix") == "muninn.parsers.":
            builds.append(threading.get_ident())
        for module_info in real_walk(*args, **kwargs):
            yield module_info
            threading.Event().wait(0.0005)

    monkeypatch.setattr(runtime_module.pkgutil, "walk_packages", slow_walk)

    barrier = threading.Barrier(threads_count)
    results: list[tuple[int, int]] = []
    errors: list[BaseException] = []

    def load() -> None:
        try:
            runtime = Muninn()
            barrier.wait()
            runtime.load_builtin_parsers()
            base = runtime.registry._base
            assert base is not None
            results.append((id(base), len(base.list_command_specs())))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=load) for _ in range(threads_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(builds) == 1
    assert len(results) == threads_count
    assert len({registry_id for registry_id, _ in results}) == 1
    assert len({spec_count for _, spec_count in results}) == 1
    assert results[0][1] > 0


@pytest.mark.usefixtures("fresh_builtin_registry")
def test_failed_build_publishes_nothing_and_is_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exception while building leaves no registry behind; the next call retries."""
    real_import = runtime_module.importlib.import_module
    calls = {"count": 0}

    def failing_import(name: str, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        calls["count"] += 1
        if calls["count"] == 3:
            raise ImportError("simulated parser import failure")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(runtime_module.importlib, "import_module", failing_import)
    with pytest.raises(ImportError, match="simulated"):
        Muninn().load_builtin_parsers()
    assert runtime_module._builtin_registry is None

    monkeypatch.setattr(runtime_module.importlib, "import_module", real_import)
    runtime = Muninn()
    assert runtime.load_builtin_parsers()
    assert runtime_module._builtin_registry is not None
