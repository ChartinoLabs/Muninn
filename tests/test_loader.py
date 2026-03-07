"""Tests for local parser overlay loading."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from muninn.config import ExecutionMode
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.runtime import Muninn


def test_load_local_parsers_from_path(tmp_path: Path) -> None:
    """Local parser modules can be loaded from an external path."""
    runtime = Muninn(autoload_builtins=False)
    runtime.configuration.set_execution_mode(ExecutionMode.LOCAL_FIRST_FALLBACK)

    @register("nxos", "show version")
    class BuiltInParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, str]:
            return {"source": "built_in"}

    runtime.registry.register_parser("nxos", "show version", BuiltInParser, "built_in")

    package_name = f"local_parsers_{uuid4().hex}"
    package_dir = tmp_path / package_name
    package_dir.mkdir()
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "show_version.py").write_text(
        "from muninn.registry import register\n"
        "from muninn.parser import BaseParser\n"
        "\n"
        "@register('nxos', 'show version')\n"
        "class LocalShowVersionParser(BaseParser):\n"
        "    @classmethod\n"
        "    def parse(cls, output: str) -> dict[str, str]:\n"
        "        return {'source': 'local'}\n",
        encoding="utf-8",
    )

    imported_modules = runtime.load_local_parsers([tmp_path])
    assert any(module.endswith("show_version") for module in imported_modules)

    result = runtime.parse("nxos", "show version", "show version output")
    assert result == {"source": "local"}

    candidates = runtime.registry.get_parser_candidates("nxos", "show version")
    assert candidates[0].source == "local"
