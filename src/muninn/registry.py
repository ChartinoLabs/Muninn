"""Parser registry primitives and parser registration metadata."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from muninn.exceptions import ParserNotFoundError
from muninn.os import OS, OperatingSystem, resolve_os

if TYPE_CHECKING:
    from muninn.parser import BaseParser

ParserSource = Literal["built_in", "local"]


@dataclass(frozen=True)
class ParserCandidate:
    """Registered parser candidate with source metadata."""

    parser_cls: type[BaseParser[object]]
    source: ParserSource


def register(
    os: str | OS | type[OperatingSystem], command: str
) -> Callable[[type[BaseParser[object]]], type[BaseParser[object]]]:
    """Class decorator that annotates parser classes with registration metadata."""
    resolved_os = resolve_os(os)
    normalized_command = _normalize_command(command)

    def decorator(cls: type[BaseParser[object]]) -> type[BaseParser[object]]:
        cls.os = resolved_os
        cls.command = normalized_command
        registrations = (
            list(cls._muninn_registrations)
            if hasattr(cls, "_muninn_registrations")
            else []
        )
        registration = (resolved_os, normalized_command)
        if registration not in registrations:
            registrations.append(registration)
        cls._muninn_registrations = registrations
        return cls

    return decorator


class RuntimeRegistry:
    """Runtime-owned parser registry without module-level mutable state."""

    def __init__(self) -> None:
        """Initialize an empty parser registry."""
        self._registry: dict[tuple[OS, str], list[ParserCandidate]] = {}

    def clear(self) -> None:
        """Clear all registered parser candidates."""
        self._registry.clear()

    def register_parser(
        self,
        os: str | OS | type[OperatingSystem],
        command: str,
        parser_cls: type[BaseParser[object]],
        source: ParserSource,
    ) -> None:
        """Register a parser class with explicit source metadata."""
        resolved_os = resolve_os(os)
        normalized_command = _normalize_command(command)
        key = (resolved_os, normalized_command)

        parser_cls.os = resolved_os
        parser_cls.command = normalized_command

        candidates = self._registry.setdefault(key, [])
        already_registered = any(
            candidate.parser_cls is parser_cls and candidate.source == source
            for candidate in candidates
        )
        if not already_registered:
            candidates.append(ParserCandidate(parser_cls=parser_cls, source=source))

    def get_parser_candidates(
        self,
        os: str | OS | type[OperatingSystem],
        command: str,
        source_order: tuple[ParserSource, ...] = ("local", "built_in"),
    ) -> list[ParserCandidate]:
        """Get ordered parser candidates for an OS/command pair."""
        resolved_os = resolve_os(os)
        normalized_command = _normalize_command(command)
        key = (resolved_os, normalized_command)

        if key not in self._registry:
            raise ParserNotFoundError(resolved_os.value.name, command)

        candidates = self._registry[key]
        grouped: dict[ParserSource, list[ParserCandidate]] = {
            "local": [],
            "built_in": [],
        }
        for candidate in candidates:
            grouped[candidate.source].append(candidate)

        ordered: list[ParserCandidate] = []
        for source in source_order:
            ordered.extend(grouped[source])

        return ordered

    def list_parsers(self) -> list[tuple[OS, str]]:
        """List all registered parser keys."""
        return list(self._registry.keys())


def _normalize_command(command: str) -> str:
    """Normalize a command string for consistent registry lookup."""
    return " ".join(command.lower().split())
