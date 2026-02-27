"""Muninn: A standalone CLI output parser library for network devices."""

# Import parsers to trigger registration
from muninn import parsers as _parsers  # noqa: F401
from muninn.config import (
    configuration,
    get_feature_enabled,
    get_parser_backend,
    get_retries,
    get_settings,
    load_config,
    set_feature_enabled,
    set_parser_backend,
    set_retries,
)
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
    "configuration",
    "get_feature_enabled",
    "get_parser_backend",
    "get_retries",
    "get_settings",
    "get_parser",
    "list_parsers",
    "load_config",
    "parse",
    "register",
    "resolve_os",
    "set_feature_enabled",
    "set_parser_backend",
    "set_retries",
]
