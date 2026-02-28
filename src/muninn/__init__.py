"""Muninn: A standalone CLI output parser library for network devices."""

# Import parsers to trigger registration
from muninn import parsers as _parsers  # noqa: F401
from muninn.config import (
    ExecutionMode,
    configuration,
)
from muninn.core import parse
from muninn.exceptions import (
    EmptyOutputError,
    MuninnError,
    ParseError,
    ParserNotFoundError,
)
from muninn.loader import load_local_parsers
from muninn.os import OS, OperatingSystem, resolve_os
from muninn.parser import BaseParser
from muninn.registry import get_parser, list_parsers, register

if configuration.get_parser_paths():
    load_local_parsers()

__all__ = [
    "BaseParser",
    "MuninnError",
    "OS",
    "OperatingSystem",
    "EmptyOutputError",
    "ExecutionMode",
    "ParseError",
    "ParserNotFoundError",
    "configuration",
    "get_parser",
    "list_parsers",
    "load_local_parsers",
    "parse",
    "register",
    "resolve_os",
]
