"""Muninn: A standalone CLI output parser library for network devices."""

# Import parsers to trigger registration
from muninn import parsers as _parsers  # noqa: F401
from muninn.config import (
    ExecutionMode,
    configuration,
    get_execution_mode,
    get_fallback_on_invalid_result,
    get_parser_paths,
    set_execution_mode,
    set_fallback_on_invalid_result,
    set_parser_paths,
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

if get_parser_paths():
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
    "get_execution_mode",
    "get_fallback_on_invalid_result",
    "get_parser",
    "get_parser_paths",
    "list_parsers",
    "load_local_parsers",
    "parse",
    "register",
    "resolve_os",
    "set_execution_mode",
    "set_fallback_on_invalid_result",
    "set_parser_paths",
]
