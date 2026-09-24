"""Parser for 'show mpls forwarding-table' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class MplsForwardingPath(TypedDict):
    """Schema for one outgoing path of a local label."""

    outgoing_label: str
    prefix_or_id: str
    outgoing_interface: str
    next_hop: NotRequired[str]
    bytes_switched: NotRequired[int]
    lsp_tunnel: bool
    merged: bool


class MplsForwardingEntry(TypedDict):
    """Schema for a local label and its outgoing paths."""

    paths: list[MplsForwardingPath]


ShowMplsForwardingTableResult = dict[str, MplsForwardingEntry]


# Start of a table row; the local label is blank on extra paths.
# Examples:
#   16    [T]  Pop Label  65757/1[TE-Bind]               Tu65757    point2point
#              No Label   45.45.45.0/24    0             Te0/0/5    20.20.20.2
#   16022      Pop Label  0-2.2.2.2/32-2 (1:100:1:0)  \
_ROW_RE = re.compile(
    r"^(?:(?P<local_label>\d+|None)\s+|\s+)"
    r"(?:\[(?P<flag>[TM])\]\s+)?"
    r"(?P<outgoing_label>Pop Label|No Label|\d+)\s+"
    r"(?P<prefix>\S.*?)"
    r"(?:\s+\\|\s{2,}(?P<rest>\S.*?))\s*$"
)

# Second header line; table rows follow it until the first blank line.
_HEADER_RE = re.compile(r"^Label\s+Label\s+or Tunnel Id\s+Switched\s+interface\s*$")

# Trailing columns: bytes switched (optional), interface, next hop (optional).
_REST_RE = re.compile(
    r"^(?:(?P<bytes>\d+)\s+)?(?P<interface>\S+)(?:\s+(?P<next_hop>\S+))?$"
)


def _fill_rest(path: dict, rest: str) -> None:
    """Fill the bytes/interface/next-hop columns of a path from ``rest``."""
    match = _REST_RE.match(rest.strip())
    if not match:
        msg = f"Unrecognized forwarding columns: {rest!r}"
        raise ValueError(msg)
    if match.group("bytes"):
        path["bytes_switched"] = int(match.group("bytes"))
    path["outgoing_interface"] = canonical_interface_name(
        match.group("interface"), os=OS.CISCO_IOSXE
    )
    if match.group("next_hop"):
        path["next_hop"] = match.group("next_hop")


def _table_lines(output: str) -> list[str]:
    """Return the lines between the column header and the first blank line."""
    lines = output.splitlines()
    for index, line in enumerate(lines):
        if _HEADER_RE.match(line):
            table = lines[index + 1 :]
            blank = next((i for i, row in enumerate(table) if not row.strip()), None)
            return table[:blank]
    return []


def _parse_row(line: str) -> tuple[str | None, dict, bool]:
    """Return (local label or None, path, wrapped) for a table row."""
    match = _ROW_RE.match(line)
    if not match:
        msg = f"Unrecognized forwarding table row: {line!r}"
        raise ValueError(msg)
    flag = match.group("flag")
    path: dict = {
        "outgoing_label": match.group("outgoing_label"),
        "prefix_or_id": match.group("prefix"),
        "lsp_tunnel": flag == "T",
        "merged": flag == "M",
    }
    rest = match.group("rest")
    if rest is not None:
        _fill_rest(path, rest)
    return match.group("local_label"), path, rest is None


@register(OS.CISCO_IOSXE, "show mpls forwarding-table")
@register(OS.CISCO_IOSXE, r"show mpls forwarding-table vrf (?P<vrf>\S+)")
@register(OS.CISCO_IOSXE, rf"show mpls forwarding-table (?P<prefix>{IPV4_ADDRESS})")
@register(
    OS.CISCO_IOSXE,
    rf"show mpls forwarding-table (?P<prefix>{IPV4_ADDRESS}) "
    rf"(?P<mask>{IPV4_ADDRESS}) algo (?P<algo>\d+)",
)
class ShowMplsForwardingTableParser(BaseParser[ShowMplsForwardingTableResult]):
    """Parser for 'show mpls forwarding-table' on IOS-XE.

    Returns a dict keyed by local label; each label holds the list of
    outgoing paths printed for it (continuation rows with a blank local
    label belong to the preceding label). Every line between the column
    header and the first blank line must be a recognised table row;
    anything else raises ``ValueError`` rather than being dropped.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.MPLS, ParserTag.ROUTING}
    )

    @classmethod
    def parse(cls, output: str) -> ShowMplsForwardingTableResult:
        """Parse 'show mpls forwarding-table' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by local label with the outgoing paths of each label.

        Raises:
            ValueError: If no forwarding entries are found, or a table row
                is not recognised.
        """
        result: dict[str, dict] = {}
        local_label: str | None = None
        wrapped: dict | None = None

        for line in _table_lines(output):
            if wrapped is not None:
                _fill_rest(wrapped, line)
                wrapped = None
                continue
            row_label, path, is_wrapped = _parse_row(line)
            local_label = row_label or local_label
            if local_label is None:
                msg = f"Forwarding path has no preceding local label: {line!r}"
                raise ValueError(msg)
            if is_wrapped:
                wrapped = path
            result.setdefault(local_label, {"paths": []})["paths"].append(path)

        if wrapped is not None:
            msg = "Wrapped forwarding entry is missing its continuation line"
            raise ValueError(msg)
        if not result:
            msg = "No MPLS forwarding entries found in output"
            raise ValueError(msg)

        return cast(ShowMplsForwardingTableResult, result)
