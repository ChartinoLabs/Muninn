"""Parser for 'show crypto tech-support' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

_SECTION_HEADER_RE = re.compile(r"^-{2,}\s+(?P<command>.+?)\s+-{2,}$")


class TechSupportSection(TypedDict):
    """A single section within show crypto tech-support output."""

    content: str


class ShowCryptoTechSupportResult(TypedDict):
    """Schema for 'show crypto tech-support' parsed output.

    Top-level dict keyed by sub-command name (e.g.
    ``"show crypto isakmp sa count"``). Each value contains the raw
    text content of that section.
    """

    sections: dict[str, TechSupportSection]


def _store_section(
    sections: dict[str, TechSupportSection],
    command: str,
    lines: list[str],
) -> None:
    """Store a section only if it has non-empty content."""
    content = "\n".join(lines).strip()
    if content:
        sections[command] = cast(TechSupportSection, {"content": content})


@register(OS.CISCO_IOSXE, "show crypto tech-support")
class ShowCryptoTechSupportParser(BaseParser[ShowCryptoTechSupportResult]):
    """Parser for 'show crypto tech-support' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.SECURITY, ParserTag.VPN}
    )

    @classmethod
    def parse(cls, output: str) -> ShowCryptoTechSupportResult:
        r"""Parse 'show crypto tech-support' output into structured data.

        The command aggregates output from multiple crypto sub-commands,
        each delimited by a dashed header line containing the sub-command
        name (e.g. ``--- show crypto isakmp sa count ---``).

        Args:
            output: Raw CLI output from the command.

        Returns:
            Dict with a ``sections`` key mapping sub-command names to
            their text content.

        Raises:
            ValueError: If no section headers are found in the output.
        """
        sections: dict[str, TechSupportSection] = {}
        current_command: str | None = None
        current_lines: list[str] = []

        for line in output.splitlines():
            header_match = _SECTION_HEADER_RE.match(line)
            if header_match:
                if current_command is not None:
                    _store_section(sections, current_command, current_lines)
                current_command = header_match.group("command")
                current_lines = []
            elif current_command is not None:
                current_lines.append(line)

        if current_command is not None:
            _store_section(sections, current_command, current_lines)

        if not sections:
            msg = "No section headers found in show crypto tech-support output"
            raise ValueError(msg)

        result: dict[str, object] = {"sections": sections}
        return cast(ShowCryptoTechSupportResult, result)
