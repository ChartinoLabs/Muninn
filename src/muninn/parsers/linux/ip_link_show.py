"""Parser for 'ip link show' command on Linux."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class LinkEntry(TypedDict):
    """Schema for a single interface's link-layer information."""

    index: int
    name: str
    flags: list[str]
    mtu: int
    qdisc: NotRequired[str]
    state: str
    group: NotRequired[str]
    qlen: NotRequired[int]
    master: NotRequired[str]
    link_type: str
    mac_address: NotRequired[str]
    broadcast_mac: NotRequired[str]
    permaddr: NotRequired[str]
    altname: NotRequired[str]


IpLinkShowResult = dict[str, LinkEntry]


# Pattern for the interface header line:
# N: name: <FLAGS> mtu N qdisc X state Y [group G] [qlen Q]
_IFACE_HEADER_RE = re.compile(
    r"^(?P<index>\d+):\s+(?P<name>\S+?):\s+"
    r"<(?P<flags>[^>]*)>\s+"
    r"mtu\s+(?P<mtu>\d+)\s+"
    r"qdisc\s+(?P<qdisc>\S+)\s+"
    r"(?:(?P<state_label>state)\s+(?P<state>\S+)\s*)?"
)

# Pattern for master keyword in the header line
_MASTER_RE = re.compile(r"\bmaster\s+(\S+)")

# Pattern for group keyword in the header line
_GROUP_RE = re.compile(r"\bgroup\s+(\S+)")

# Pattern for qlen keyword in the header line
_QLEN_RE = re.compile(r"\bqlen\s+(\d+)")

# Pattern for link layer info:
# link/ether AA:BB:CC:DD:EE:FF brd FF:FF:FF:FF:FF:FF [permaddr CC:CC:CC:CC:CC:CC]
# link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
# link/none
_LINK_RE = re.compile(
    r"^\s+link/(?P<type>\S+)"
    r"(?:\s+(?P<mac>[0-9a-f:]+))?"
    r"(?:\s+brd\s+(?P<brd>[0-9a-f:]+))?"
    r"(?:\s+permaddr\s+(?P<permaddr>[0-9a-f:]+))?"
)

# Pattern for altname
_ALTNAME_RE = re.compile(r"^\s+altname\s+(?P<altname>\S+)")


def _parse_header(line: str) -> LinkEntry | None:
    """Parse an interface header line into a LinkEntry."""
    header_match = _IFACE_HEADER_RE.match(line)
    if not header_match:
        return None

    entry: LinkEntry = {
        "index": int(header_match.group("index")),
        "name": header_match.group("name"),
        "flags": header_match.group("flags").split(","),
        "mtu": int(header_match.group("mtu")),
        "state": header_match.group("state") or "UNKNOWN",
        "link_type": "",
    }

    qdisc = header_match.group("qdisc")
    if qdisc:
        entry["qdisc"] = qdisc

    master_match = _MASTER_RE.search(line)
    if master_match:
        entry["master"] = master_match.group(1)

    group_match = _GROUP_RE.search(line)
    if group_match:
        entry["group"] = group_match.group(1)

    qlen_match = _QLEN_RE.search(line)
    if qlen_match:
        entry["qlen"] = int(qlen_match.group(1))

    return entry


def _parse_link(line: str, entry: LinkEntry) -> bool:
    """Parse a link layer info line. Returns True if matched."""
    link_match = _LINK_RE.match(line)
    if not link_match:
        return False

    entry["link_type"] = link_match.group("type")
    if link_match.group("mac"):
        entry["mac_address"] = link_match.group("mac")
    if link_match.group("brd"):
        entry["broadcast_mac"] = link_match.group("brd")
    if link_match.group("permaddr"):
        entry["permaddr"] = link_match.group("permaddr")
    return True


def _parse_altname(line: str, entry: LinkEntry) -> bool:
    """Parse an altname line. Returns True if matched."""
    altname_match = _ALTNAME_RE.match(line)
    if not altname_match:
        return False
    entry["altname"] = altname_match.group("altname")
    return True


@register(OS.LINUX, "ip link show")
class IpLinkShowParser(BaseParser[IpLinkShowResult]):
    """Parser for 'ip link show' command on Linux.

    Parses interface link-layer information including flags, MTU, state,
    link type, and MAC addresses. Unlike 'ip address show', this command
    does not include IP address information.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INTERFACES,
        }
    )

    @classmethod
    def parse(cls, output: str) -> IpLinkShowResult:
        """Parse 'ip link show' output on Linux.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict of link entries keyed by interface name.

        Raises:
            ValueError: If no interfaces can be parsed.
        """
        result: dict[str, LinkEntry] = {}
        current_entry: LinkEntry | None = None

        for line in output.splitlines():
            entry = _parse_header(line)
            if entry is not None:
                current_entry = entry
                result[entry["name"]] = entry
                continue

            if current_entry is None:
                continue

            if _parse_link(line, current_entry):
                continue

            _parse_altname(line, current_entry)

        if not result:
            msg = "No interfaces found in output"
            raise ValueError(msg)

        return cast(IpLinkShowResult, result)
