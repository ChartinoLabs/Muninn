"""Parser for 'show crypto ipsec sa count' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

_COUNT_LINE_RE = re.compile(
    r"^\s*IPsec\s+SA\s+total:\s*(?P<total>\d+),\s*"
    r"active:\s*(?P<active>\d+),\s*"
    r"rekeying:\s*(?P<rekeying>\d+),\s*"
    r"unused:\s*(?P<unused>\d+),\s*"
    r"invalid:\s*(?P<invalid>\d+)\s*$",
    re.IGNORECASE,
)


class ShowCryptoIpsecSaCountResult(TypedDict):
    """Schema for 'show crypto ipsec sa count' parsed output."""

    total: int
    active: int
    rekeying: int
    unused: int
    invalid: int


@register(OS.CISCO_IOSXE, "show crypto ipsec sa count")
class ShowCryptoIpsecSaCountParser(BaseParser[ShowCryptoIpsecSaCountResult]):
    """Parser for 'show crypto ipsec sa count' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.SECURITY, ParserTag.VPN}
    )

    @classmethod
    def parse(cls, output: str) -> ShowCryptoIpsecSaCountResult:
        """Parse 'show crypto ipsec sa count' output into structured data.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed IPsec SA counters (total, active, rekeying, unused, invalid).

        Raises:
            ValueError: If the expected counter summary line is not found.
        """
        for line in output.splitlines():
            match = _COUNT_LINE_RE.match(line)
            if not match:
                continue
            result: dict[str, int] = {
                "total": int(match.group("total")),
                "active": int(match.group("active")),
                "rekeying": int(match.group("rekeying")),
                "unused": int(match.group("unused")),
                "invalid": int(match.group("invalid")),
            }
            return cast(ShowCryptoIpsecSaCountResult, result)

        msg = "No 'IPsec SA total' counter summary line found in output"
        raise ValueError(msg)
