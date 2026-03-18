"""Muninn: A standalone CLI output parser library for network devices."""

from muninn.config import Configuration, ExecutionMode
from muninn.exceptions import (
    EmptyOutputError,
    MuninnError,
    ParseError,
    ParserAmbiguityError,
    ParserNotFoundError,
)
from muninn.os import OS, OperatingSystem, resolve_os
from muninn.parser import BaseParser
from muninn.registry import ParserInfo, RuntimeRegistry, register
from muninn.runtime import Muninn
from muninn.tags import ParserTag

__all__ = [
    "BaseParser",
    "Configuration",
    "EmptyOutputError",
    "ExecutionMode",
    "MuninnError",
    "Muninn",
    "OS",
    "OperatingSystem",
    "ParseError",
    "ParserAmbiguityError",
    "ParserInfo",
    "ParserNotFoundError",
    "ParserTag",
    "RuntimeRegistry",
    "register",
    "resolve_os",
]
