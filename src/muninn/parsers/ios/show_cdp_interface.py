"""Parser for 'show cdp interface' command on Cisco IOS and IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

# Header line for each interface block, e.g.:
#   GigabitEthernet1/0/1 is up, line protocol is up
_INTERFACE_HEADER_RE = re.compile(
    r"^(?P<interface>\S+)\s+is\s+(?P<status>[\w-]+(?:\s[\w-]+)*),\s+"
    r"line\s+protocol\s+is\s+(?P<line_protocol>[\w-]+(?:\s[\w-]+)*)\s*$",
)

# Encapsulation line, e.g.:
#   Encapsulation ARPA
_ENCAPSULATION_RE = re.compile(r"^\s*Encapsulation\s+(?P<encapsulation>\S.*?)\s*$")

# Send-interval line, e.g.:
#   Sending CDP packets every 60 seconds
_SEND_INTERVAL_RE = re.compile(
    r"^\s*Sending\s+CDP\s+packets\s+every\s+(?P<interval>\d+)\s+seconds?\s*$",
    re.IGNORECASE,
)

# Holdtime line, e.g.:
#   Holdtime is 180 seconds
_HOLDTIME_RE = re.compile(
    r"^\s*Holdtime\s+is\s+(?P<holdtime>\d+)\s+seconds?\s*$",
    re.IGNORECASE,
)

# Summary footer lines, e.g.:
#   cdp enabled interfaces : 139
#   interfaces up          : 8
#   interfaces down        : 131
_CDP_ENABLED_COUNT_RE = re.compile(
    r"^\s*cdp\s+enabled\s+interfaces\s*:\s*(?P<count>\d+)\s*$",
    re.IGNORECASE,
)
_INTERFACES_UP_RE = re.compile(
    r"^\s*interfaces\s+up\s*:\s*(?P<count>\d+)\s*$",
    re.IGNORECASE,
)
_INTERFACES_DOWN_RE = re.compile(
    r"^\s*interfaces\s+down\s*:\s*(?P<count>\d+)\s*$",
    re.IGNORECASE,
)


class CdpInterfaceEntry(TypedDict):
    """Schema for a single 'show cdp interface' per-interface entry."""

    status: str
    line_protocol: str
    encapsulation: NotRequired[str]
    send_interval_seconds: NotRequired[int]
    holdtime_seconds: NotRequired[int]


class ShowCdpInterfaceResult(TypedDict):
    """Schema for 'show cdp interface' parsed output."""

    interfaces: dict[str, CdpInterfaceEntry]
    cdp_enabled_interfaces: NotRequired[int]
    interfaces_up: NotRequired[int]
    interfaces_down: NotRequired[int]


def _try_match_summary(line: str, result: dict[str, object]) -> bool:
    """Attempt to match a summary-footer line and record it.

    Returns True if the line matched any summary pattern.
    """
    match = _CDP_ENABLED_COUNT_RE.match(line)
    if match:
        result["cdp_enabled_interfaces"] = int(match.group("count"))
        return True

    match = _INTERFACES_UP_RE.match(line)
    if match:
        result["interfaces_up"] = int(match.group("count"))
        return True

    match = _INTERFACES_DOWN_RE.match(line)
    if match:
        result["interfaces_down"] = int(match.group("count"))
        return True

    return False


def _try_match_attribute(line: str, entry: CdpInterfaceEntry) -> bool:
    """Attempt to match an attribute line of the current interface block.

    Updates ``entry`` in place. Returns True if the line was consumed.
    """
    match = _ENCAPSULATION_RE.match(line)
    if match:
        entry["encapsulation"] = match.group("encapsulation")
        return True

    match = _SEND_INTERVAL_RE.match(line)
    if match:
        entry["send_interval_seconds"] = int(match.group("interval"))
        return True

    match = _HOLDTIME_RE.match(line)
    if match:
        entry["holdtime_seconds"] = int(match.group("holdtime"))
        return True

    return False


@register(OS.CISCO_IOS, "show cdp interface")
@register(OS.CISCO_IOSXE, "show cdp interface")
class ShowCdpInterfaceParser(BaseParser[ShowCdpInterfaceResult]):
    """Parser for 'show cdp interface' on Cisco IOS and IOS-XE.

    Output consists of a block per CDP-enabled interface followed by a
    footer with aggregate counts. Each interface block looks like::

        GigabitEthernet1/0/1 is up, line protocol is up
          Encapsulation ARPA
          Sending CDP packets every 60 seconds
          Holdtime is 180 seconds
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.CDP, ParserTag.INTERFACES}
    )

    @classmethod
    def parse(cls, output: str) -> ShowCdpInterfaceResult:
        """Parse 'show cdp interface' output on Cisco IOS and IOS-XE.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed result with interfaces keyed by canonical name and an
            optional summary footer.

        Raises:
            ValueError: If no interface blocks are found in the output.
        """
        result: dict[str, object] = {}
        interfaces: dict[str, CdpInterfaceEntry] = {}
        current_entry: CdpInterfaceEntry | None = None

        for raw_line in output.splitlines():
            line = raw_line.rstrip()
            if not line.strip():
                continue

            header_match = _INTERFACE_HEADER_RE.match(line)
            if header_match:
                interface_name = canonical_interface_name(
                    header_match.group("interface"), os=OS.CISCO_IOS
                )
                current_entry = {
                    "status": header_match.group("status"),
                    "line_protocol": header_match.group("line_protocol"),
                }
                interfaces[interface_name] = current_entry
                continue

            if current_entry is not None and _try_match_attribute(line, current_entry):
                continue

            if _try_match_summary(line, result):
                current_entry = None
                continue

        if not interfaces:
            msg = "No CDP interface blocks found in output"
            raise ValueError(msg)

        result["interfaces"] = interfaces
        return cast(ShowCdpInterfaceResult, result)
