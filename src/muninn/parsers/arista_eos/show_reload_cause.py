"""Parser for 'show reload cause' command on Arista EOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowReloadCauseResult(TypedDict):
    """Schema for 'show reload cause' parsed output on Arista EOS."""

    reload_cause: str
    reload_time: NotRequired[str]
    recommended_action: NotRequired[str]
    debugging_information: NotRequired[str]


# Section header labels mapped to internal section keys.
_SECTION_HEADERS: dict[str, str] = {
    "Reload Time:": "reload_time",
    "Recommended Action:": "recommended_action",
    "Debugging Information:": "debugging_information",
}

# Optional result keys that should be omitted when their value is a sentinel.
_OPTIONAL_SENTINEL_KEYS = ("recommended_action", "debugging_information")


@register(OS.ARISTA_EOS, "show reload cause")
class ShowReloadCauseParser(BaseParser[ShowReloadCauseResult]):
    """Parser for 'show reload cause' command on Arista EOS.

    Parses reload cause, timestamp, recommended action, and debugging
    information from the command output.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    _RELOAD_CAUSE_HEADER = re.compile(r"^Reload Cause \d+:")
    _RELOAD_TIME = re.compile(r"^Reload occurred at (?P<time>.+)\.$")
    _SEPARATOR = re.compile(r"^-{2,}$")

    # Values that indicate "no data" and should be omitted from output.
    _NO_VALUE_SENTINELS = frozenset({"none available", "no information available"})

    @classmethod
    def _detect_section(cls, line: str) -> str | None:
        """Return the section key if *line* is a section header, else None."""
        if cls._RELOAD_CAUSE_HEADER.match(line):
            return "reload_cause"
        for header, key in _SECTION_HEADERS.items():
            if line.startswith(header):
                return key
        return None

    @classmethod
    def _is_meaningful(cls, value: str) -> bool:
        """Return True when *value* is not a no-data sentinel."""
        return value.lower().rstrip(".") not in cls._NO_VALUE_SENTINELS

    @classmethod
    def _extract_sections(cls, output: str) -> dict[str, str]:
        """Walk the output and return a mapping of section key to content."""
        current_section: str | None = None
        sections: dict[str, str] = {}

        for line in output.splitlines():
            stripped = line.strip()

            if not stripped or cls._SEPARATOR.match(stripped):
                continue

            detected = cls._detect_section(stripped)
            if detected is not None:
                current_section = detected
                continue

            if current_section is not None and current_section not in sections:
                cls._store_section_value(current_section, stripped, sections)

        return sections

    @classmethod
    def _store_section_value(
        cls, section: str, line: str, sections: dict[str, str]
    ) -> None:
        """Extract and store the value for the given *section*."""
        if section == "reload_time":
            if match := cls._RELOAD_TIME.match(line):
                sections[section] = match.group("time")
        else:
            sections[section] = line

    @classmethod
    def _build_result(cls, sections: dict[str, str]) -> ShowReloadCauseResult:
        """Build the typed result dict from extracted sections."""
        result = ShowReloadCauseResult(reload_cause=sections["reload_cause"])

        if "reload_time" in sections:
            result["reload_time"] = sections["reload_time"]

        for key in _OPTIONAL_SENTINEL_KEYS:
            if key in sections and cls._is_meaningful(sections[key]):
                result[key] = sections[key]  # type: ignore[literal-required]

        return result

    @classmethod
    def parse(cls, output: str) -> ShowReloadCauseResult:
        """Parse 'show reload cause' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed reload cause information.

        Raises:
            ValueError: If no reload cause can be found in the output.
        """
        sections = cls._extract_sections(output)

        if "reload_cause" not in sections:
            msg = "No reload cause found in output"
            raise ValueError(msg)

        return cls._build_result(sections)
