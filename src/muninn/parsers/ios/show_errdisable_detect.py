"""Parser for 'show errdisable detect' command on IOS and IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_SPACE_RE
from muninn.registry import register
from muninn.tags import ParserTag

_HEADER_RE = re.compile(
    r"^\s*ErrDisable\s+Reason\s+Detection\s+Mode\s*$", re.IGNORECASE
)
_ROW_RE = re.compile(
    r"^(?P<reason>\S(?:.*?\S)?)\s{2,}(?P<detection>Enabled|Disabled)\s+(?P<mode>\S+)\s*$",
    re.IGNORECASE,
)
# Footer notes emitted by some IOS images after the reasons table, e.g.:
#   Recovery command: "clear errdisable interface IntName"
# These can be truncated by narrow terminals into shapes that resemble table
# rows; explicitly skip any line that starts with such a footer label.
_FOOTER_PREFIX_RE = re.compile(r"^\s*Recovery\s+command\s*:", re.IGNORECASE)


class ErrdisableReasonEntry(TypedDict):
    """Schema for a single errdisable-detect reason row."""

    detection: bool
    mode: str


class ShowErrdisableDetectResult(TypedDict):
    """Schema for 'show errdisable detect' parsed output."""

    reasons: dict[str, ErrdisableReasonEntry]


@register(OS.CISCO_IOS, "show errdisable detect")
@register(OS.CISCO_IOSXE, "show errdisable detect")
class ShowErrdisableDetectParser(BaseParser[ShowErrdisableDetectResult]):
    """Parser for 'show errdisable detect' on IOS and IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.SWITCHING,
            ParserTag.SYSTEM,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowErrdisableDetectResult:
        """Parse 'show errdisable detect' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Mapping of errdisable reason name to its detection state and
            recovery mode.

        Raises:
            ValueError: If no reason rows are parsed from the output.
        """
        reasons: dict[str, ErrdisableReasonEntry] = {}

        for line in output.splitlines():
            if (
                not line.strip()
                or _HEADER_RE.match(line)
                or SEPARATOR_DASH_SPACE_RE.match(line)
                or _FOOTER_PREFIX_RE.match(line)
            ):
                continue

            match = _ROW_RE.match(line)
            if match is None:
                continue

            reason = match.group("reason").strip()
            detection = match.group("detection").lower() == "enabled"
            mode = match.group("mode").strip()
            reasons[reason] = {"detection": detection, "mode": mode}

        if not reasons:
            msg = "No errdisable reasons parsed from 'show errdisable detect' output"
            raise ValueError(msg)

        return {"reasons": reasons}
