"""Parser for 'show ip default-gateway' command on Cisco IOS."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag

_DEFAULT_GATEWAY_RE = re.compile(rf"^(?P<default_gateway>{IPV4_ADDRESS})$")


class ShowIpDefaultGatewayResult(TypedDict):
    """Schema for 'show ip default-gateway' parsed output."""

    default_gateway: str


@register(OS.CISCO_IOS, "show ip default-gateway")
class ShowIpDefaultGatewayParser(BaseParser[ShowIpDefaultGatewayResult]):
    """Parser for 'show ip default-gateway' command on Cisco IOS."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowIpDefaultGatewayResult:
        """Parse 'show ip default-gateway' output.

        The command emits a single line containing the IPv4 address of
        the configured default gateway, e.g.::

            192.0.2.1

        Args:
            output: Raw CLI output from the device.

        Returns:
            Parsed result with the default-gateway IPv4 address.

        Raises:
            ValueError: If no default-gateway IPv4 address is found in
                the output.
        """
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            match = _DEFAULT_GATEWAY_RE.match(stripped)
            if match:
                return ShowIpDefaultGatewayResult(
                    default_gateway=match.group("default_gateway"),
                )

        msg = "No default-gateway IPv4 address found in output"
        raise ValueError(msg)
