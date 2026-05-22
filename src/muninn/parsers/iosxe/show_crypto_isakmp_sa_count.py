"""Parser for 'show crypto isakmp sa count' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

_COUNTER_RE = re.compile(
    r"^\s*(?P<label>Active|Standby|Currently being negotiated|Dead)"
    r"\s+ISAKMP SA's:\s*(?P<count>\d+)\s*$"
)

_LABEL_TO_FIELD: dict[str, str] = {
    "Active": "active",
    "Standby": "standby",
    "Currently being negotiated": "negotiating",
    "Dead": "dead",
}


class ShowCryptoIsakmpSaCountResult(TypedDict):
    """Schema for 'show crypto isakmp sa count' parsed output."""

    active: int
    standby: int
    negotiating: int
    dead: int


@register(OS.CISCO_IOSXE, "show crypto isakmp sa count")
class ShowCryptoIsakmpSaCountParser(BaseParser[ShowCryptoIsakmpSaCountResult]):
    """Parser for 'show crypto isakmp sa count' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.SECURITY, ParserTag.VPN}
    )

    @classmethod
    def parse(cls, output: str) -> ShowCryptoIsakmpSaCountResult:
        """Parse 'show crypto isakmp sa count' output into structured data.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed ISAKMP SA counters (active, standby, negotiating, dead).

        Raises:
            ValueError: If any of the expected counter lines are missing.
        """
        result: dict[str, int] = {}
        for line in output.splitlines():
            match = _COUNTER_RE.match(line)
            if match is None:
                continue
            field = _LABEL_TO_FIELD[match.group("label")]
            result[field] = int(match.group("count"))

        for required in _LABEL_TO_FIELD.values():
            if required not in result:
                msg = f"Missing required ISAKMP SA counter line: {required}"
                raise ValueError(msg)

        return cast(ShowCryptoIsakmpSaCountResult, result)
