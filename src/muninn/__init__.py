"""Muninn: A standalone CLI output parser library for network devices."""

from muninn.config import Configuration, ExecutionMode
from muninn.exceptions import (
    EmptyOutputError,
    MuninnError,
    ParseError,
    ParserNotFoundError,
)
from muninn.os import OS, OperatingSystem, resolve_os
from muninn.parser import BaseParser
from muninn.registry import RuntimeRegistry, register
from muninn.runtime import MuninnRuntime

__all__ = [
    "BaseParser",
    "Configuration",
    "EmptyOutputError",
    "ExecutionMode",
    "MuninnError",
    "MuninnRuntime",
    "OS",
    "OperatingSystem",
    "ParseError",
    "ParserNotFoundError",
    "RuntimeRegistry",
    "register",
    "resolve_os",
]
