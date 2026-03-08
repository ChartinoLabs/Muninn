"""Runtime object that owns configuration, registry, and parser execution."""

from __future__ import annotations

import importlib
import logging
import pkgutil
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Protocol, cast

from muninn.config import Configuration, ExecutionMode
from muninn.exceptions import EmptyOutputError, ParseError, ParserNotFoundError
from muninn.os import OS, OperatingSystem, resolve_os
from muninn.parser import BaseParser
from muninn.registry import ParserCandidate, ParserSource, RuntimeRegistry

logger = logging.getLogger(__name__)


def _source_order_for_mode(mode: ExecutionMode) -> tuple[ParserSource, ...]:
    if mode is ExecutionMode.CENTRALIZED_FIRST_FALLBACK:
        return ("built_in", "local")
    if mode is ExecutionMode.LOCAL_FIRST_FALLBACK:
        return ("local", "built_in")
    return ("local",)


def _is_invalid_result(result: object) -> bool:
    return result is None or result == {}


class MuninnRuntime:
    """Standalone runtime with no shared module-level mutable state."""

    def __init__(
        self,
        configuration: Configuration | None = None,
        autoload_builtins: bool = True,
    ) -> None:
        """Create a runtime with its own configuration and registry."""
        self.configuration = configuration or Configuration()
        self.registry = RuntimeRegistry()
        self._autoload_builtins = autoload_builtins
        self._builtins_loaded = False

    def _register_module_parsers(
        self,
        module: ModuleType,
        source: ParserSource,
    ) -> None:
        for value in vars(module).values():
            if not isinstance(value, type):
                continue
            if not issubclass(value, BaseParser):
                continue
            if not hasattr(value, "_muninn_registrations"):
                continue
            for registration in value._muninn_registrations:
                self.registry.register_parser(
                    registration.os,
                    registration.command,
                    value,
                    source=source,
                    doc_template=registration.doc_template,
                )

    def load_builtin_parsers(self) -> list[str]:
        """Discover and register built-in parsers into this runtime."""
        import muninn.parsers

        imported_modules: list[str] = []
        for module_info in pkgutil.walk_packages(
            muninn.parsers.__path__, prefix=muninn.parsers.__name__ + "."
        ):
            module = importlib.import_module(module_info.name)
            self._register_module_parsers(module, source="built_in")
            imported_modules.append(module_info.name)

        self._builtins_loaded = True
        return imported_modules

    def load_local_parsers(
        self,
        paths: list[str | Path] | tuple[str | Path, ...] | None = None,
    ) -> list[str]:
        """Load and register local parser modules into this runtime."""
        overlay_paths = (
            self.configuration.get_parser_paths() if paths is None else paths
        )
        imported_modules: list[str] = []

        for path in overlay_paths:
            resolved_path = Path(path).expanduser().resolve()
            if not resolved_path.exists() or not resolved_path.is_dir():
                msg = (
                    f"Parser path does not exist or is not a directory: {resolved_path}"
                )
                raise ValueError(msg)

            path_str = str(resolved_path)
            if path_str not in sys.path:
                sys.path.insert(0, path_str)

            for module_info in pkgutil.walk_packages([path_str]):
                module = importlib.import_module(module_info.name)
                self._register_module_parsers(module, source="local")
                imported_modules.append(module_info.name)

        return imported_modules

    def _prepare_parse_candidates(
        self,
        os: str | OS | type[OperatingSystem],
        command: str,
    ) -> tuple[ExecutionMode, list[tuple[str, str]], list[ParserCandidate], bool]:
        if self._autoload_builtins and not self._builtins_loaded:
            self.load_builtin_parsers()

        self.configuration.reload()
        execution_mode = self.configuration.get_execution_mode()
        source_order = _source_order_for_mode(execution_mode)
        candidates = self.registry.get_parser_candidates(
            os, command, source_order=source_order
        )
        candidate_order = [
            (candidate.source, candidate.parser_cls.__name__)
            for candidate in candidates
        ]
        fallback_on_invalid_result = self.configuration.get_fallback_on_invalid_result()
        return (
            execution_mode,
            candidate_order,
            candidates,
            fallback_on_invalid_result,
        )

    def _log_candidate_order(
        self,
        resolved_os: OS,
        command: str,
        execution_mode: ExecutionMode,
        candidate_order: list[tuple[str, str]],
    ) -> None:
        logger.debug(
            "Parser candidate order for os=%s command=%r mode=%s: %s",
            resolved_os.value.name,
            command,
            execution_mode.value,
            [f"{source}:{name}" for source, name in candidate_order],
        )

    def _try_candidate(
        self,
        candidate: ParserCandidate,
        resolved_os: OS,
        command: str,
        output: str,
        fallback_on_invalid_result: bool,
    ) -> tuple[dict[str, Any] | None, str | None]:
        parser_cls = candidate.parser_cls
        source = candidate.source
        logger.debug(
            "Attempting parser %s source=%s for os=%s command=%r",
            parser_cls.__name__,
            source,
            resolved_os.value.name,
            command,
        )

        try:
            result = parser_cls.parse(output)
        except Exception as exc:
            reason = f"exception:{type(exc).__name__}"
            logger.debug(
                "Fallback triggered for parser %s source=%s reason=%s",
                parser_cls.__name__,
                source,
                reason,
                exc_info=True,
            )
            return None, f"{source}:{parser_cls.__name__}:{reason}"

        if fallback_on_invalid_result and _is_invalid_result(result):
            reason = "invalid_result"
            logger.debug(
                "Fallback triggered for parser %s source=%s reason=%s",
                parser_cls.__name__,
                source,
                reason,
            )
            return None, f"{source}:{parser_cls.__name__}:{reason}"

        logger.debug(
            "Parser selected %s source=%s for os=%s command=%r",
            parser_cls.__name__,
            source,
            resolved_os.value.name,
            command,
        )
        return cast(dict[str, Any], result), None

    def parse(
        self,
        os: str | OS | type[OperatingSystem],
        command: str,
        output: str,
    ) -> dict[str, Any]:
        """Parse CLI output into structured data with policy-based fallback."""
        resolved_os = resolve_os(os)
        if not output.strip():
            raise EmptyOutputError(resolved_os.value.name, command)

        execution_mode, candidate_order, candidates, fallback_on_invalid_result = (
            self._prepare_parse_candidates(os, command)
        )

        if not candidates:
            raise ParserNotFoundError(resolved_os.value.name, command)

        self._log_candidate_order(resolved_os, command, execution_mode, candidate_order)

        failure_reasons: list[str] = []

        for candidate in candidates:
            result, failure_reason = self._try_candidate(
                candidate,
                resolved_os,
                command,
                output,
                fallback_on_invalid_result,
            )
            if failure_reason is not None:
                failure_reasons.append(failure_reason)
                continue
            if result is not None:
                return result

        failure_summary = "; ".join(failure_reasons)
        if not failure_summary:
            failure_summary = "no parser candidates produced a valid result"
        raise ParseError(
            resolved_os.value.name,
            command,
            f"all parser candidates failed. {failure_summary}",
        )


class ParseCallable(Protocol):
    """Callable protocol preserving parse parameter names for type checkers."""

    def __call__(
        self,
        os: str | OS | type[OperatingSystem],
        command: str,
        output: str,
    ) -> dict[str, Any]:
        """Parse CLI output using positional or keyword arguments."""


class _ParseDispatcher:
    """Descriptor enabling `Muninn.parse(...)` and `mn.parse(...)` usage."""

    def __get__(
        self,
        instance: Muninn | None,
        owner: type[Muninn],
    ) -> ParseCallable:
        if instance is None:

            def parse_via_class(
                os: str | OS | type[OperatingSystem],
                command: str,
                output: str,
            ) -> dict[str, Any]:
                return owner()._parse(os, command, output)

            return parse_via_class

        return instance._parse


class Muninn(MuninnRuntime):
    """User-facing parser engine for local and built-in parsers."""

    parse = _ParseDispatcher()

    def _parse(
        self,
        os: str | OS | type[OperatingSystem],
        command: str,
        output: str,
    ) -> dict[str, Any]:
        return super().parse(os, command, output)
