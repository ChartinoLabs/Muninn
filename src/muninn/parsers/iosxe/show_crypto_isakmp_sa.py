"""Parser for 'show crypto isakmp sa' command on Cisco IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# Section headers
_IPV4_HEADER_RE = re.compile(r"^\s*IPv4\s+Crypto\s+ISAKMP\s+SA\s*$")
_IPV6_HEADER_RE = re.compile(r"^\s*IPv6\s+Crypto\s+ISAKMP\s+SA\s*$")

# Column header line: "dst             src             state          conn-id status"
_COLUMN_HEADER_RE = re.compile(
    r"^\s*dst\s+src\s+state\s+conn-id\s+status\s*$",
    re.IGNORECASE,
)

# Entry row: "192.168.1.1     10.1.1.1        QM_IDLE         1001 ACTIVE"
# State token is a single non-whitespace word (e.g. QM_IDLE, MM_NO_STATE).
# Status is a single non-whitespace word (e.g. ACTIVE, STANDBY).
_ENTRY_RE = re.compile(
    r"^\s*(?P<dst>\S+)\s+(?P<src>\S+)\s+(?P<state>\S+)"
    r"\s+(?P<conn_id>\d+)\s+(?P<status>\S+)\s*$"
)


class IsakmpSaEntry(TypedDict):
    """Schema for a single ISAKMP Security Association entry."""

    dst: str
    src: str
    state: str
    conn_id: int
    status: str


class ShowCryptoIsakmpSaResult(TypedDict):
    """Schema for 'show crypto isakmp sa' parsed output.

    The output is split into two address-family sections. Each section
    maps the ISAKMP connection identifier (``conn-id``) to its entry.
    Connection identifiers are unique within a section, so using them
    as the dictionary key avoids collisions when multiple SAs share a
    destination address.
    """

    ipv4_sa: dict[str, IsakmpSaEntry]
    ipv6_sa: dict[str, IsakmpSaEntry]


def _parse_section(lines: list[str]) -> dict[str, IsakmpSaEntry]:
    """Parse a single address-family section into a dict of entries."""
    entries: dict[str, IsakmpSaEntry] = {}
    for line in lines:
        if not line.strip():
            continue
        if _COLUMN_HEADER_RE.match(line):
            continue
        m = _ENTRY_RE.match(line)
        if not m:
            continue
        conn_id = int(m.group("conn_id"))
        entries[str(conn_id)] = IsakmpSaEntry(
            dst=m.group("dst"),
            src=m.group("src"),
            state=m.group("state"),
            conn_id=conn_id,
            status=m.group("status"),
        )
    return entries


def _split_sections(output: str) -> tuple[list[str], list[str], bool, bool]:
    """Split raw output into IPv4 and IPv6 sections.

    Returns:
        Tuple of (ipv4 section lines, ipv6 section lines, ipv4 header
        seen, ipv6 header seen). The header-seen flags distinguish
        "section header absent" from "section header present but
        contains no entries" — both produce an empty list of lines.
    """
    ipv4_lines: list[str] = []
    ipv6_lines: list[str] = []
    ipv4_seen = False
    ipv6_seen = False
    current: list[str] | None = None

    for line in output.splitlines():
        if _IPV4_HEADER_RE.match(line):
            current = ipv4_lines
            ipv4_seen = True
            continue
        if _IPV6_HEADER_RE.match(line):
            current = ipv6_lines
            ipv6_seen = True
            continue
        if current is not None:
            current.append(line)

    return ipv4_lines, ipv6_lines, ipv4_seen, ipv6_seen


@register(OS.CISCO_IOSXE, "show crypto isakmp sa")
class ShowCryptoIsakmpSaParser(BaseParser[ShowCryptoIsakmpSaResult]):
    """Parser for 'show crypto isakmp sa' on Cisco IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.SECURITY, ParserTag.VPN}
    )

    @classmethod
    def parse(cls, output: str) -> ShowCryptoIsakmpSaResult:
        """Parse 'show crypto isakmp sa' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed structure with separate ``ipv4_sa`` and ``ipv6_sa``
            dictionaries keyed by ISAKMP connection identifier. Both
            keys are always present; empty dicts represent address
            families with no active SAs.

        Raises:
            ValueError: If neither the IPv4 nor IPv6 section header is
                present in the output (indicates the output is not
                from this command).
        """
        ipv4_lines, ipv6_lines, ipv4_seen, ipv6_seen = _split_sections(output)
        if not ipv4_seen and not ipv6_seen:
            msg = "No IPv4 or IPv6 Crypto ISAKMP SA section header found in output"
            raise ValueError(msg)

        result: dict = {
            "ipv4_sa": _parse_section(ipv4_lines),
            "ipv6_sa": _parse_section(ipv6_lines),
        }
        return cast(ShowCryptoIsakmpSaResult, result)
