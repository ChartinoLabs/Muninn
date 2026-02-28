"""Tests for all parsers using directory-based test cases."""

from typing import TYPE_CHECKING

from muninn.runtime import MuninnRuntime

if TYPE_CHECKING:
    from tests.parsers.conftest import ParserTestCase


def test_parser(
    parser_test_case: "ParserTestCase",
    runtime: MuninnRuntime,
) -> None:
    """Test that parser produces expected output."""
    result = runtime.parse(
        parser_test_case["os"],
        parser_test_case["command"],
        parser_test_case["input"],
    )

    assert result == parser_test_case["expected"]
