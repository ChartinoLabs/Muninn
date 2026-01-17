"""Tests for all parsers using directory-based test cases."""

from typing import TYPE_CHECKING

import muninn

if TYPE_CHECKING:
    from tests.parsers.conftest import ParserTestCase


def test_parser(parser_test_case: "ParserTestCase") -> None:
    """Test that parser produces expected output."""
    result = muninn.parse(
        parser_test_case["os"],
        parser_test_case["command"],
        parser_test_case["input"],
    )

    assert result == parser_test_case["expected"]
