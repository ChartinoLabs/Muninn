"""Parser for 'show etherchannel load-balance' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

_PROTOCOL_RE = re.compile(r"^\s*(?P<protocol>Non-IP|IPv4|IPv6)\s*:\s*(?P<address>.+)$")

_CONFIG_HEADER = "EtherChannel Load-Balancing Configuration"


class ProtocolEntry(TypedDict):
    """Schema for per-protocol load-balancing address information."""

    address: str


class ShowEtherchannelLoadBalanceResult(TypedDict):
    """Schema for 'show etherchannel load-balance' parsed output."""

    method: str
    per_protocol: NotRequired[dict[str, ProtocolEntry]]


def _parse_per_protocol(lines: list[str]) -> dict[str, ProtocolEntry]:
    """Extract per-protocol load-balancing addresses from output lines."""
    per_protocol: dict[str, ProtocolEntry] = {}
    for line in lines:
        match = _PROTOCOL_RE.match(line)
        if match:
            protocol = match.group("protocol")
            address = match.group("address").strip()
            per_protocol[protocol] = ProtocolEntry(address=address)
    return per_protocol


def _parse_method(lines: list[str]) -> str | None:
    """Extract the load-balancing method from the configuration section."""
    in_config_section = False
    for line in lines:
        stripped = line.strip()
        if not stripped:
            in_config_section = False
            continue
        if stripped.startswith(_CONFIG_HEADER):
            in_config_section = True
            continue
        if in_config_section:
            return stripped
    return None


@register(OS.CISCO_IOSXE, "show etherchannel load-balance")
class ShowEtherchannelLoadBalanceParser(
    BaseParser[ShowEtherchannelLoadBalanceResult],
):
    """Parser for 'show etherchannel load-balance' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.LAG})

    @classmethod
    def parse(cls, output: str) -> ShowEtherchannelLoadBalanceResult:
        """Parse 'show etherchannel load-balance' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed load-balancing configuration and per-protocol details.

        Raises:
            ValueError: If required fields cannot be extracted.
        """
        lines = output.splitlines()

        method = _parse_method(lines)
        if method is None:
            msg = "Missing required field: method"
            raise ValueError(msg)

        result: dict[str, object] = {"method": method}

        per_protocol = _parse_per_protocol(lines)
        if per_protocol:
            result["per_protocol"] = per_protocol

        return cast(ShowEtherchannelLoadBalanceResult, result)
