"""Tests for parser selection diagnostics logging."""

from __future__ import annotations

import logging
from typing import Any

from pytest import LogCaptureFixture

from muninn import registry
from muninn.config import (
    ExecutionMode,
    configuration,
)
from muninn.core import parse
from muninn.parser import BaseParser


def test_logs_fallback_reason_and_selected_parser(
    caplog: LogCaptureFixture,
) -> None:
    """Fallback and final parser selection are logged at debug level."""
    registry._registry.clear()
    configuration.set_execution_mode(ExecutionMode.LOCAL_FIRST_FALLBACK)
    configuration.set_fallback_on_invalid_result(True)

    @registry.register("nxos", "show version")
    class BuiltInParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {"source": "built_in"}

    with registry.registration_source("local"):

        @registry.register("nxos", "show version")
        class LocalParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

    caplog.set_level(logging.DEBUG, logger="muninn.core")
    parse("nxos", "show version", "show version output")

    debug_messages = [record.getMessage() for record in caplog.records]
    assert any("Fallback triggered" in message for message in debug_messages)
    assert any("reason=invalid_result" in message for message in debug_messages)
    assert any(
        "Parser selected BuiltInParser source=built_in" in message
        for message in debug_messages
    )
