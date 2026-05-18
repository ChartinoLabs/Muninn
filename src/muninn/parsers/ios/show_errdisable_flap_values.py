"""Parser for 'show errdisable flap-values' command on IOS."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_SPACE_RE
from muninn.registry import register
from muninn.tags import ParserTag

_HEADER_RE = re.compile(
    r"^\s*ErrDisable Reason\s+Flaps\s+Time\s*\(sec\)\s*$",
    re.IGNORECASE,
)
_ROW_RE = re.compile(r"^(?P<reason>\S+)\s+(?P<flaps>\d+)\s+(?P<time_seconds>\d+)\s*$")


class ErrdisableFlapValue(TypedDict):
    """Per-reason flap detection parameters for err-disable."""

    flaps: int
    time_seconds: int


class ShowErrdisableFlapValuesResult(TypedDict):
    """Schema for 'show errdisable flap-values' parsed output."""

    reasons: dict[str, ErrdisableFlapValue]


@register(OS.CISCO_IOS, "show errdisable flap-values")
class ShowErrdisableFlapValuesParser(BaseParser[ShowErrdisableFlapValuesResult]):
    """Parser for 'show errdisable flap-values' on IOS."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INTERFACES,
            ParserTag.SWITCHING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowErrdisableFlapValuesResult:
        """Parse 'show errdisable flap-values' output.

        The command lists the flap detection thresholds for each
        err-disable reason. A reason becomes err-disabled when its
        associated event occurs ``flaps`` times within ``time_seconds``.

        Args:
            output: Raw CLI output from command.

        Returns:
            Mapping of err-disable reason name to its flap-detection
            parameters.
        """
        reasons: dict[str, ErrdisableFlapValue] = {}

        for line in output.splitlines():
            if (
                not line.strip()
                or _HEADER_RE.match(line)
                or SEPARATOR_DASH_SPACE_RE.match(line)
            ):
                continue

            match = _ROW_RE.match(line)
            if match is None:
                continue

            reasons[match.group("reason")] = {
                "flaps": int(match.group("flaps")),
                "time_seconds": int(match.group("time_seconds")),
            }

        return cast(ShowErrdisableFlapValuesResult, {"reasons": reasons})
