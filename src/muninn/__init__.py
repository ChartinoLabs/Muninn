"""Muninn: A standalone CLI output parser library for network devices."""

# Import parsers to trigger registration
from muninn import parsers as _parsers  # noqa: F401
from muninn.core import parse
from muninn.exceptions import (
    EmptyOutputError,
    MuninnError,
    ParseError,
    ParserNotFoundError,
)
from muninn.os import OS, OperatingSystem, resolve_os
from muninn.parser import BaseParser
from muninn.registry import get_parser, list_parsers, register

__all__ = [
    "BaseParser",
    "MuninnError",
    "OS",
    "OperatingSystem",
    "EmptyOutputError",
    "ParseError",
    "ParserNotFoundError",
    "get_parser",
    "list_parsers",
    "parse",
    "register",
    "resolve_os",
]
