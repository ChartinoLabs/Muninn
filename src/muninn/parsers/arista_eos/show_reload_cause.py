"""Parser for 'show reload cause' command on Arista EOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_RE
from muninn.registry import register
from muninn.tags import ParserTag


class ReloadCauseEntry(TypedDict):
    """One reload cause record from 'show reload cause' on Arista EOS."""

    cause: str
    reload_time: NotRequired[str]
    recommended_action: NotRequired[str]
    debugging_information: NotRequired[str]


class ShowReloadCauseResult(TypedDict):
    """Schema for 'show reload cause' parsed output on Arista EOS."""

    causes: dict[str, ReloadCauseEntry]


_RELOAD_CAUSE_HEADER_RE = re.compile(r"^Reload Cause (?P<index>\d+):")
_RELOAD_TIME_RE = re.compile(r"^Reload occurred at (?P<time>.+)\.$")

# Subsection header labels mapped to internal field keys on ReloadCauseEntry.
_SUBSECTION_HEADERS: dict[str, str] = {
    "Reload Time:": "reload_time",
    "Recommended Action:": "recommended_action",
    "Debugging Information:": "debugging_information",
}

# Optional fields whose values are dropped when they match a no-data sentinel.
_OPTIONAL_SENTINEL_FIELDS = (
    "recommended_action",
    "debugging_information",
)

_NO_VALUE_SENTINELS = frozenset({"none available", "no information available"})


@register(OS.ARISTA_EOS, "show reload cause")
class ShowReloadCauseParser(BaseParser[ShowReloadCauseResult]):
    """Parser for 'show reload cause' command on Arista EOS.

    Parses one or more reload-cause records.  Each record carries a numeric
    index from ``Reload Cause N:``, the cause description, and optional
    ``Reload Time``, ``Recommended Action``, and ``Debugging Information``
    subsections.  Sentinel values such as ``None available`` are omitted.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @staticmethod
    def _is_meaningful(value: str) -> bool:
        """Return True when *value* is not a no-data sentinel."""
        return value.lower().rstrip(".") not in _NO_VALUE_SENTINELS

    @staticmethod
    def _detect_subsection(line: str) -> str | None:
        """Return the subsection field key for *line*, or None."""
        for header, key in _SUBSECTION_HEADERS.items():
            if line.startswith(header):
                return key
        return None

    @classmethod
    def _finalize_subsection(
        cls, entry: dict[str, str], field: str, lines: list[str]
    ) -> None:
        """Store *lines* into *entry* under *field*, normalizing per-field."""
        if not lines:
            return
        value = "\n".join(lines).strip()
        if not value:
            return
        if field == "reload_time":
            if match := _RELOAD_TIME_RE.match(value):
                entry[field] = match.group("time")
            return
        if field in _OPTIONAL_SENTINEL_FIELDS and not cls._is_meaningful(value):
            return
        entry[field] = value

    @classmethod
    def _flush_record(
        cls,
        causes: dict[str, ReloadCauseEntry],
        index: str | None,
        cause_lines: list[str],
        current_field: str | None,
        current_lines: list[str],
        subsections: dict[str, str],
    ) -> None:
        """Finalize the in-progress record and append it to *causes*."""
        if index is None:
            return
        if current_field is not None:
            scratch: dict[str, str] = {}
            cls._finalize_subsection(scratch, current_field, current_lines)
            subsections.update(scratch)
        cause_text = "\n".join(cause_lines).strip()
        if not cause_text:
            return
        entry: ReloadCauseEntry = {"cause": cause_text}
        for field in ("reload_time", "recommended_action", "debugging_information"):
            if field in subsections:
                entry[field] = subsections[field]  # type: ignore[literal-required]
        causes[index] = entry

    @classmethod
    def _parse_records(cls, output: str) -> dict[str, ReloadCauseEntry]:
        """Walk *output* and return a mapping of cause index to entry."""
        causes: dict[str, ReloadCauseEntry] = {}
        index: str | None = None
        cause_lines: list[str] = []
        subsections: dict[str, str] = {}
        current_field: str | None = None
        current_lines: list[str] = []

        for raw_line in output.splitlines():
            stripped = raw_line.strip()
            if not stripped or SEPARATOR_DASH_RE.match(stripped):
                continue

            if cause_match := _RELOAD_CAUSE_HEADER_RE.match(stripped):
                cls._flush_record(
                    causes,
                    index,
                    cause_lines,
                    current_field,
                    current_lines,
                    subsections,
                )
                index = cause_match.group("index")
                cause_lines = []
                subsections = {}
                current_field = None
                current_lines = []
                continue

            if (subsection := cls._detect_subsection(stripped)) is not None:
                if current_field is not None:
                    cls._finalize_subsection(subsections, current_field, current_lines)
                current_field = subsection
                current_lines = []
                continue

            if current_field is None:
                cause_lines.append(stripped)
            else:
                current_lines.append(stripped)

        cls._flush_record(
            causes, index, cause_lines, current_field, current_lines, subsections
        )
        return causes

    @classmethod
    def parse(cls, output: str) -> ShowReloadCauseResult:
        """Parse 'show reload cause' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed reload-cause records keyed by cause index.

        Raises:
            ValueError: If no reload cause can be found in the output.
        """
        causes = cls._parse_records(output)
        if not causes:
            msg = "No reload cause found in output"
            raise ValueError(msg)
        return {"causes": causes}
