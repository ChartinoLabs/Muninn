"""Parser registry primitives and parser registration metadata."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Protocol, cast

from muninn.exceptions import ParserAmbiguityError, ParserNotFoundError
from muninn.os import OS, OperatingSystem, resolve_os

if TYPE_CHECKING:
    from muninn.parser import BaseParser

ParserSource = Literal["built_in", "local"]

_DOC_PLACEHOLDER_RE = re.compile(r"<(?P<name>[a-z0-9-]+)>")
_NAMED_GROUP_TOKEN_RE = re.compile(
    r"^\(\?P<(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)>(?P<body>.+)\)$"
)
_COMPLEX_PATTERN_CHARS = set("()[]{}|?+*")


@dataclass(frozen=True)
class Registration:
    """Decorator-owned parser registration metadata."""

    os: OS
    command: str
    doc_template: str | None = None


class _RegistrableParserClass(Protocol):
    """Parser class protocol with registration metadata attributes."""

    os: OS
    command: str
    _muninn_registrations: list[Registration]


@dataclass(frozen=True)
class CommandSpec:
    """Resolved command registration used by the runtime registry."""

    os: OS
    command_text: str
    match_text: str
    doc_template: str
    parser_cls: type[BaseParser[object]]
    source: ParserSource
    is_pattern: bool
    compiled_pattern: re.Pattern[str] | None = None
    group_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class ParserCandidate:
    """Registered parser candidate with source metadata."""

    parser_cls: type[BaseParser[object]]
    source: ParserSource
    command_spec: CommandSpec


def register(
    os: str | OS | type[OperatingSystem],
    command: str,
    *,
    doc_template: str | None = None,
) -> Callable[[type[BaseParser[object]]], type[BaseParser[object]]]:
    """Class decorator that annotates parser classes with registration metadata."""
    resolved_os = resolve_os(os)

    def decorator(cls: type[BaseParser[object]]) -> type[BaseParser[object]]:
        cls.os = resolved_os
        cls.command = _normalize_command(command)
        registrable_cls = cast(_RegistrableParserClass, cls)
        registrations = []
        if hasattr(registrable_cls, "_muninn_registrations"):
            registrations = list(registrable_cls._muninn_registrations)
        registration = Registration(
            os=resolved_os,
            command=command,
            doc_template=doc_template,
        )
        if registration not in registrations:
            registrations.append(registration)
        registrable_cls._muninn_registrations = registrations
        return cls

    return decorator


class RuntimeRegistry:
    """Runtime-owned parser registry without module-level mutable state."""

    def __init__(self) -> None:
        """Initialize an empty parser registry."""
        self._literal_registry: dict[tuple[OS, str], list[ParserCandidate]] = {}
        self._pattern_registry: dict[OS, list[ParserCandidate]] = {}

    def clear(self) -> None:
        """Clear all registered parser candidates."""
        self._literal_registry.clear()
        self._pattern_registry.clear()

    def register_parser(
        self,
        os: str | OS | type[OperatingSystem],
        command: str,
        parser_cls: type[BaseParser[object]],
        source: ParserSource,
        *,
        doc_template: str | None = None,
    ) -> None:
        """Register a parser class with explicit source metadata."""
        resolved_os = resolve_os(os)
        spec = _build_command_spec(
            os=resolved_os,
            command=command,
            doc_template=doc_template,
            parser_cls=parser_cls,
            source=source,
        )

        parser_cls.os = resolved_os
        parser_cls.command = spec.doc_template

        candidate = ParserCandidate(
            parser_cls=parser_cls,
            source=source,
            command_spec=spec,
        )

        if spec.is_pattern:
            candidates = self._pattern_registry.setdefault(resolved_os, [])
        else:
            key = (resolved_os, spec.match_text)
            candidates = self._literal_registry.setdefault(key, [])

        self._add_candidate(candidates, candidate)

    def get_parser_candidates(
        self,
        os: str | OS | type[OperatingSystem],
        command: str,
        source_order: tuple[ParserSource, ...] = ("local", "built_in"),
    ) -> list[ParserCandidate]:
        """Get ordered parser candidates for an OS/command pair."""
        resolved_os = resolve_os(os)
        normalized_command = _normalize_command(command)

        literal_candidates = self._ordered_literal_candidates(
            resolved_os,
            normalized_command,
            source_order,
        )
        if literal_candidates:
            return literal_candidates

        pattern_candidates = self._ordered_pattern_candidates(
            resolved_os,
            normalized_command,
            source_order,
            command,
        )
        if pattern_candidates:
            return pattern_candidates

        raise ParserNotFoundError(resolved_os.value.name, command)

    def list_parsers(self) -> list[tuple[OS, str]]:
        """List all registered parser templates."""
        return [(spec.os, spec.doc_template) for spec in self.list_command_specs()]

    def list_command_specs(self) -> list[CommandSpec]:
        """List all registered command specifications."""
        specs: list[CommandSpec] = []
        for candidates in self._literal_registry.values():
            specs.extend(candidate.command_spec for candidate in candidates)
        for candidates in self._pattern_registry.values():
            specs.extend(candidate.command_spec for candidate in candidates)
        return specs

    def _add_candidate(
        self,
        candidates: list[ParserCandidate],
        candidate: ParserCandidate,
    ) -> None:
        already_registered = any(
            existing.parser_cls is candidate.parser_cls
            and existing.source == candidate.source
            and existing.command_spec.match_text == candidate.command_spec.match_text
            for existing in candidates
        )
        if already_registered:
            return

        conflicting = next(
            (
                existing
                for existing in candidates
                if existing.source == candidate.source
                and existing.command_spec.match_text
                == candidate.command_spec.match_text
            ),
            None,
        )
        if conflicting is not None:
            source = candidate.source
            os_name = candidate.command_spec.os.value.name
            descriptor = "pattern" if candidate.command_spec.is_pattern else "literal"
            msg = (
                f"Duplicate {descriptor} registration for os={os_name!r}, "
                f"source={source!r}, command={candidate.command_spec.command_text!r}"
            )
            raise ValueError(msg)

        candidates.append(candidate)

    def _ordered_literal_candidates(
        self,
        os: OS,
        normalized_command: str,
        source_order: tuple[ParserSource, ...],
    ) -> list[ParserCandidate]:
        key = (os, normalized_command)
        candidates = self._literal_registry.get(key, [])
        if not candidates:
            return []

        ordered: list[ParserCandidate] = []
        for source in source_order:
            ordered.extend(
                candidate for candidate in candidates if candidate.source == source
            )
        return ordered

    def _ordered_pattern_candidates(
        self,
        os: OS,
        normalized_command: str,
        source_order: tuple[ParserSource, ...],
        original_command: str,
    ) -> list[ParserCandidate]:
        candidates = self._pattern_registry.get(os, [])
        if not candidates:
            return []

        ordered: list[ParserCandidate] = []
        for source in source_order:
            matching = [
                candidate
                for candidate in candidates
                if candidate.source == source
                and candidate.command_spec.compiled_pattern is not None
                and candidate.command_spec.compiled_pattern.fullmatch(
                    normalized_command
                )
            ]
            if len(matching) > 1:
                raise ParserAmbiguityError(
                    os.value.name,
                    original_command,
                    [candidate.command_spec.doc_template for candidate in matching],
                )
            if matching:
                return matching

        return ordered


def _build_command_spec(
    *,
    os: OS,
    command: str,
    doc_template: str | None,
    parser_cls: type[BaseParser[object]],
    source: ParserSource,
) -> CommandSpec:
    collapsed_command = _collapse_command_whitespace(command)
    if not collapsed_command:
        raise ValueError("command must be non-empty")

    if "(?P<" not in collapsed_command:
        normalized_command = _normalize_command(collapsed_command)
        template = _resolve_doc_template(
            doc_template=doc_template,
            fallback=normalized_command,
            group_names=(),
        )
        return CommandSpec(
            os=os,
            command_text=command,
            match_text=normalized_command,
            doc_template=template,
            parser_cls=parser_cls,
            source=source,
            is_pattern=False,
        )

    runtime_pattern = _normalize_pattern_for_runtime(collapsed_command)
    compiled_pattern = _compile_pattern(runtime_pattern)
    group_names = tuple(compiled_pattern.groupindex)
    template = _resolve_pattern_doc_template(
        runtime_pattern=runtime_pattern,
        group_names=group_names,
        doc_template=doc_template,
    )
    return CommandSpec(
        os=os,
        command_text=command,
        match_text=runtime_pattern,
        doc_template=template,
        parser_cls=parser_cls,
        source=source,
        is_pattern=True,
        compiled_pattern=compiled_pattern,
        group_names=group_names,
    )


def _resolve_pattern_doc_template(
    *,
    runtime_pattern: str,
    group_names: tuple[str, ...],
    doc_template: str | None,
) -> str:
    generated_doc_template = _generate_doc_template(runtime_pattern)
    if doc_template is None:
        if generated_doc_template is None:
            msg = (
                "doc_template is required for complex command patterns: "
                f"{runtime_pattern!r}"
            )
            raise ValueError(msg)
        return _resolve_doc_template(
            doc_template=generated_doc_template,
            fallback=generated_doc_template,
            group_names=group_names,
        )

    return _resolve_doc_template(
        doc_template=doc_template,
        fallback=generated_doc_template or runtime_pattern,
        group_names=group_names,
    )


def _resolve_doc_template(
    *,
    doc_template: str | None,
    fallback: str,
    group_names: tuple[str, ...],
) -> str:
    template = (
        fallback if doc_template is None else _collapse_command_whitespace(doc_template)
    )
    if not template:
        raise ValueError("doc_template must be non-empty")

    placeholders = _DOC_PLACEHOLDER_RE.findall(template)
    if len(placeholders) != len(set(placeholders)):
        msg = f"doc_template contains duplicate placeholders: {template!r}"
        raise ValueError(msg)

    placeholder_groups = {placeholder.replace("-", "_") for placeholder in placeholders}
    expected_groups = set(group_names)
    if placeholder_groups != expected_groups:
        msg = (
            "doc_template placeholders must align with named regex groups: "
            f"template={template!r}, groups={sorted(expected_groups)!r}"
        )
        raise ValueError(msg)

    return template


def _generate_doc_template(runtime_pattern: str) -> str | None:
    tokens = runtime_pattern.split()
    template_tokens: list[str] = []
    for token in tokens:
        named_group_match = _NAMED_GROUP_TOKEN_RE.fullmatch(token)
        if named_group_match is not None:
            template_tokens.append(
                _group_name_to_placeholder(named_group_match["name"])
            )
            continue

        if any(char in _COMPLEX_PATTERN_CHARS for char in token) or "\\" in token:
            return None
        template_tokens.append(token.lower())

    return " ".join(template_tokens)


def _group_name_to_placeholder(name: str) -> str:
    return f"<{name.replace('_', '-')}>"


def _compile_pattern(pattern: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise ValueError(f"Invalid command pattern {pattern!r}: {exc}") from exc


def _normalize_pattern_for_runtime(pattern: str) -> str:
    return _strip_optional_anchors(pattern)


def _strip_optional_anchors(pattern: str) -> str:
    stripped = pattern
    if stripped.startswith("^"):
        stripped = stripped[1:]
    if stripped.endswith("$"):
        stripped = stripped[:-1]
    return stripped


def _collapse_command_whitespace(command: str) -> str:
    return " ".join(command.split())


def _normalize_command(command: str) -> str:
    """Normalize a command string for consistent registry lookup."""
    return _collapse_command_whitespace(command).lower()
