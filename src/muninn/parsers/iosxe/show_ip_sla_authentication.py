"""Parser for 'show ip sla authentication' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowIpSlaAuthenticationResult(TypedDict):
    """Schema for 'show ip sla authentication' parsed output.

    Reports the status of IP SLA control-message authentication. When
    authentication is not configured the device emits a single status
    line; when it is configured the device reports the bound key-chain.

    Attributes:
        authentication_enabled: Whether IP SLA control-message
            authentication is enabled on the device.
        key_chain: Name of the key-chain bound to IP SLA control-message
            authentication when enabled. Omitted when authentication is
            disabled or when no key-chain name is present in the output.
    """

    authentication_enabled: bool
    key_chain: NotRequired[str]


# IP SLAs control message authentication is disabled.
# IP SLAs control message authentication is enabled.
_STATUS_RE = re.compile(
    r"^\s*IP\s+SLAs?\s+control\s+message\s+authentication\s+is\s+"
    r"(?P<state>enabled|disabled)\.?\s*$",
    re.IGNORECASE,
)

# Key-chain name: <name>
_KEY_CHAIN_RE = re.compile(
    r"^\s*Key[-\s]?chain(?:\s+name)?\s*:\s*(?P<key_chain>\S+)\s*$",
    re.IGNORECASE,
)


def _match_status(line: str) -> bool | None:
    """Return enabled-state for an authentication status line, else None."""
    match = _STATUS_RE.match(line)
    if not match:
        return None
    return match.group("state").lower() == "enabled"


def _match_key_chain(line: str) -> str | None:
    """Return the key-chain name from a key-chain line, else None."""
    match = _KEY_CHAIN_RE.match(line)
    if not match:
        return None
    return match.group("key_chain")


@register(OS.CISCO_IOSXE, "show ip sla authentication")
class ShowIpSlaAuthenticationParser(BaseParser[ShowIpSlaAuthenticationResult]):
    """Parser for 'show ip sla authentication' on Cisco IOS-XE.

    Parses the status of IP SLA control-message authentication. The
    command produces a single status line when authentication is not
    configured. When it is configured, an additional key-chain line is
    emitted that identifies the bound key-chain.

    Example output when disabled::

        IP SLAs control message authentication is disabled.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.SYSTEM, ParserTag.SECURITY}
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpSlaAuthenticationResult:
        """Parse 'show ip sla authentication' output.

        Args:
            output: Raw CLI output from 'show ip sla authentication'.

        Returns:
            Parsed authentication status. ``authentication_enabled`` is
            always populated. ``key_chain`` is populated only when the
            output names a key-chain.

        Raises:
            ValueError: If the output does not contain a recognised
                authentication status line.
        """
        enabled: bool | None = None
        key_chain: str | None = None

        for raw_line in output.splitlines():
            line = raw_line.rstrip()
            if not line.strip():
                continue
            state = _match_status(line)
            if state is not None:
                enabled = state
                continue
            name = _match_key_chain(line)
            if name is not None:
                key_chain = name

        if enabled is None:
            msg = "Output does not match 'show ip sla authentication' format"
            raise ValueError(msg)

        result: ShowIpSlaAuthenticationResult = {"authentication_enabled": enabled}
        if key_chain is not None:
            result["key_chain"] = key_chain
        return result
