"""Core parsing functionality."""

import logging
from typing import Any

from muninn.config import (
    ExecutionMode,
    get_execution_mode,
    get_fallback_on_invalid_result,
)
from muninn.exceptions import EmptyOutputError, ParseError, ParserNotFoundError
from muninn.os import OS, OperatingSystem, resolve_os
from muninn.registry import ParserSource, get_parser_candidates

logger = logging.getLogger(__name__)


def _source_order_for_mode(mode: ExecutionMode) -> tuple[ParserSource, ...]:
    if mode is ExecutionMode.CENTRALIZED_FIRST_FALLBACK:
        return ("built_in", "local")
    if mode is ExecutionMode.LOCAL_FIRST_FALLBACK:
        return ("local", "built_in")
    return ("local",)


def _is_invalid_result(result: object) -> bool:
    return result is None or result == {}


def parse(
    os: str | OS | type[OperatingSystem], command: str, output: str
) -> dict[str, Any]:
    """Parse CLI output into structured data.

    Args:
        os: Operating system identifier. Can be:
            - A string alias (e.g., "nxos", "ios-xe")
            - An OS enum member (e.g., OS.CISCO_NXOS)
            - An OperatingSystem class (e.g., CiscoNXOS)
        command: The command that produced the output (e.g., "show ip ospf neighbor").
        output: Raw CLI output string to parse.

    Returns:
        Parsed structured data as a dictionary.

    Raises:
        ParserNotFoundError: No parser exists for the OS/command combination.
        ParseError: The parser failed to parse the output.
        EmptyOutputError: The CLI output is empty or whitespace only.
        ValueError: If the OS input cannot be resolved.

    Example:
        >>> import muninn
        >>> result = muninn.parse("nxos", "show ip ospf neighbor", raw_output)
        >>> print(result["10.1.1.1"]["state"])
        'FULL/DR'

        # Using enum:
        >>> from muninn import OS
        >>> result = muninn.parse(OS.CISCO_NXOS, "show ip ospf neighbor", raw_output)
    """
    resolved_os = resolve_os(os)

    if not output.strip():
        raise EmptyOutputError(resolved_os.value.name, command)

    execution_mode = get_execution_mode()
    source_order = _source_order_for_mode(execution_mode)
    candidates = get_parser_candidates(os, command, source_order=source_order)
    fallback_on_invalid_result = get_fallback_on_invalid_result()

    if not candidates:
        raise ParserNotFoundError(resolved_os.value.name, command)

    candidate_order = [
        f"{candidate.source}:{candidate.parser_cls.__name__}"
        for candidate in candidates
    ]
    logger.debug(
        "Parser candidate order for os=%s command=%r mode=%s: %s",
        resolved_os.value.name,
        command,
        execution_mode.value,
        candidate_order,
    )

    failure_reasons: list[str] = []

    for candidate in candidates:
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
            failure_reasons.append(f"{source}:{parser_cls.__name__}:{reason}")
            logger.debug(
                "Fallback triggered for parser %s source=%s reason=%s",
                parser_cls.__name__,
                source,
                reason,
                exc_info=True,
            )
            continue

        if fallback_on_invalid_result and _is_invalid_result(result):
            reason = "invalid_result"
            failure_reasons.append(f"{source}:{parser_cls.__name__}:{reason}")
            logger.debug(
                "Fallback triggered for parser %s source=%s reason=%s",
                parser_cls.__name__,
                source,
                reason,
            )
            continue

        logger.debug(
            "Parser selected %s source=%s for os=%s command=%r",
            parser_cls.__name__,
            source,
            resolved_os.value.name,
            command,
        )
        return result

    failure_summary = "; ".join(failure_reasons)
    if not failure_summary:
        failure_summary = "no parser candidates produced a valid result"
    raise ParseError(
        resolved_os.value.name,
        command,
        f"all parser candidates failed. {failure_summary}",
    )
