"""Tests for parser selection diagnostics logging."""

from __future__ import annotations

import logging
from typing import Any

from pytest import LogCaptureFixture

from muninn.config import ExecutionMode
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.runtime import Muninn


def test_logs_fallback_reason_and_selected_parser(
    caplog: LogCaptureFixture,
) -> None:
    """Fallback and final parser selection are logged at debug level."""
    runtime = Muninn(autoload_builtins=False)
    runtime.configuration.set_execution_mode(ExecutionMode.LOCAL_FIRST_FALLBACK)
    runtime.configuration.set_fallback_on_invalid_result(True)

    @register("nxos", "show version")
    class BuiltInParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {"source": "built_in"}

    @register("nxos", "show version")
    class LocalParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {}

    runtime.registry.register_parser("nxos", "show version", BuiltInParser, "built_in")
    runtime.registry.register_parser("nxos", "show version", LocalParser, "local")

    caplog.set_level(logging.DEBUG, logger="muninn.runtime")
    runtime.parse("nxos", "show version", "show version output")

    debug_messages = [record.getMessage() for record in caplog.records]
    assert any("Fallback triggered" in message for message in debug_messages)
    assert any("reason=invalid_result" in message for message in debug_messages)
    assert any(
        "Parser selected BuiltInParser source=built_in" in message
        for message in debug_messages
    )
