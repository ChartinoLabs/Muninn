"""Parser for 'show configuration rollback changes last' on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class SectionChanges(TypedDict):
    """Schema for changes within a single configuration section."""

    additions: NotRequired[list[str]]
    removals: NotRequired[list[str]]


class ShowConfigurationRollbackChangesResult(TypedDict):
    """Schema for the rollback changes output.

    Top-level keys:
        ios_xr_version: The IOS XR configuration version string.
        sections: Dict keyed by hierarchical section path (e.g.
            "telemetry model-driven/sensor-group FOO"). The
            top-level scope uses "/" as the key.
    """

    ios_xr_version: str
    sections: dict[str, SectionChanges]


@register(
    OS.CISCO_IOSXR,
    r"show configuration rollback changes last (?P<count>\d+)",
)
class ShowConfigurationRollbackChangesParser(
    BaseParser["ShowConfigurationRollbackChangesResult"],
):
    """Parser for 'show configuration rollback changes last' on IOS-XR.

    Parses configuration rollback diff output into structured sections
    with additions and removals grouped by hierarchical config path.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    _VERSION_RE = re.compile(r"^!!\s*IOS\s+XR\s+Configuration\s+(?P<version>\S+)")
    _COMMENT_RE = re.compile(r"^!!")
    _END_RE = re.compile(r"^end\s*$")
    _SECTION_CLOSE_RE = re.compile(r"^\s*!\s*$")

    @classmethod
    def _count_indent(cls, line: str) -> int:
        """Return the number of leading spaces on a line."""
        return len(line) - len(line.lstrip())

    @classmethod
    def _section_key(cls, stack: list[tuple[int, str]]) -> str:
        """Build a section key from the current context stack."""
        if not stack:
            return "/"
        return "/".join(name for _, name in stack)

    @classmethod
    def _is_skippable(cls, line: str, config_started: bool) -> bool:
        """Return True if the line should be skipped during parsing."""
        if cls._COMMENT_RE.match(line):
            return True
        if not config_started:
            return True
        if cls._END_RE.match(line):
            return True
        if not line.strip():
            return True
        return False

    @classmethod
    def _record_change(
        cls,
        sections: dict[str, SectionChanges],
        key: str,
        action: str,
        config_line: str,
    ) -> None:
        """Record a single addition or removal into the sections dict."""
        if key not in sections:
            sections[key] = SectionChanges()

        if action == "add":
            additions = sections[key].setdefault("additions", [])
            additions.append(config_line)
        else:
            removals = sections[key].setdefault("removals", [])
            removals.append(config_line)

    @classmethod
    def _parse_action(cls, stripped: str) -> tuple[str, str]:
        """Determine action and config line content from a stripped line."""
        if stripped.startswith("no "):
            return "remove", stripped[3:]
        return "add", stripped

    @classmethod
    def _handle_config_line(
        cls,
        line: str,
        sections: dict[str, SectionChanges],
        section_stack: list[tuple[int, str]],
    ) -> None:
        """Process a configuration change line, updating sections and stack."""
        indent = cls._count_indent(line)
        stripped = line.strip()

        while section_stack and section_stack[-1][0] >= indent:
            section_stack.pop()

        action, config_line = cls._parse_action(stripped)

        key = cls._section_key(section_stack)
        cls._record_change(sections, key, action, config_line)

        if action == "add":
            section_stack.append((indent, config_line))

    @classmethod
    def parse(cls, output: str) -> "ShowConfigurationRollbackChangesResult":
        """Parse 'show configuration rollback changes last' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Dict with ios_xr_version and sections dict keyed by path.

        Raises:
            ValueError: If no IOS XR version header is found.
        """
        ios_xr_version = ""
        sections: dict[str, SectionChanges] = {}
        section_stack: list[tuple[int, str]] = []
        config_started = False

        for line in output.splitlines():
            version_match = cls._VERSION_RE.match(line)
            if version_match:
                ios_xr_version = version_match.group("version")
                config_started = True
                continue

            if cls._is_skippable(line, config_started):
                continue

            if cls._SECTION_CLOSE_RE.match(line):
                if section_stack:
                    section_stack.pop()
                continue

            cls._handle_config_line(line, sections, section_stack)

        if not ios_xr_version:
            msg = "No IOS XR Configuration version header found in output"
            raise ValueError(msg)

        return cast(
            ShowConfigurationRollbackChangesResult,
            {
                "ios_xr_version": ios_xr_version,
                "sections": sections,
            },
        )
