"""Parser for 'show lacp interfaces' command on Juniper Junos."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class LacpRoleEntry(TypedDict):
    """Schema for an Actor or Partner LACP state entry."""

    expired: bool
    defaulted: bool
    distributing: bool
    collecting: bool
    synchronization: bool
    aggregation: bool
    timeout: str
    activity: str


class LacpProtocolEntry(TypedDict):
    """Schema for LACP protocol state of a member interface."""

    receive_state: str
    transmit_state: str
    mux_state: str


class MemberInterfaceEntry(TypedDict):
    """Schema for a member interface within an aggregated interface.

    All fields are ``NotRequired`` because each LACP state row (Actor /
    Partner) and the LACP protocol row are written independently by the
    parser. A given member is only guaranteed to have whichever rows the
    device actually emitted for it.
    """

    actor: NotRequired[LacpRoleEntry]
    partner: NotRequired[LacpRoleEntry]
    protocol: NotRequired[LacpProtocolEntry]


class ShowLacpInterfacesResult(TypedDict):
    """Schema for 'show lacp interfaces' parsed output.

    Dict-of-dicts keyed by aggregated interface, then by member interface.
    """

    aggregated_interfaces: dict[str, dict[str, MemberInterfaceEntry]]


@register(OS.JUNIPER_JUNOS, "show lacp interfaces")
class ShowLacpInterfacesParser(BaseParser[ShowLacpInterfacesResult]):
    """Parser for 'show lacp interfaces' command on Juniper Junos.

    Parses LACP state (Actor/Partner) and protocol information for each
    member interface within aggregated Ethernet bundles.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.LAG})

    _AGG_IF = re.compile(r"^Aggregated interface:\s+(?P<name>\S+)")

    _LACP_STATE = re.compile(
        r"^\s+(?P<member>\S+)\s+(?P<role>Actor|Partner)"
        r"\s+(?P<exp>\S+)\s+(?P<def>\S+)\s+(?P<dist>\S+)"
        r"\s+(?P<col>\S+)\s+(?P<syn>\S+)\s+(?P<aggr>\S+)"
        r"\s+(?P<timeout>\S+)\s+(?P<activity>\S+)\s*$"
    )

    _LACP_PROTOCOL = re.compile(
        r"^\s+(?P<member>\S+)"
        r"\s+(?P<rx_state>\S+)"
        r"\s+(?P<tx_state>\S+\s+\S+)"
        r"\s+(?P<mux_state>.+?)\s*$"
    )

    # Junos prompt lines like "{master:0}" or "{primary:node0}"
    _PROMPT = re.compile(r"^\{.+\}\s*$")

    # Section header lines to skip
    _STATE_HEADER = re.compile(r"^\s+LACP state:")
    _PROTOCOL_HEADER = re.compile(r"^\s+LACP protocol:")

    @classmethod
    def parse(cls, output: str) -> ShowLacpInterfacesResult:
        """Parse 'show lacp interfaces' output on Juniper Junos.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed LACP interface information.

        Raises:
            ValueError: If no aggregated interfaces can be parsed.
        """
        aggregated: dict[str, dict[str, MemberInterfaceEntry]] = {}
        current_agg: str | None = None
        current_members: dict[str, MemberInterfaceEntry] | None = None
        in_protocol_section = False

        for line in output.splitlines():
            stripped = line.strip()

            if not stripped or cls._PROMPT.match(stripped):
                continue

            # New aggregated interface
            match = cls._AGG_IF.match(stripped)
            if match:
                current_agg = match.group("name")
                current_members = {}
                aggregated[current_agg] = current_members
                in_protocol_section = False
                continue

            if current_members is None:
                continue

            # Detect section transitions
            if cls._STATE_HEADER.match(line):
                in_protocol_section = False
                continue

            if cls._PROTOCOL_HEADER.match(line):
                in_protocol_section = True
                continue

            if in_protocol_section:
                cls._parse_protocol_line(line, current_members)
            else:
                cls._parse_state_line(line, current_members)

        if not aggregated:
            msg = "No aggregated interfaces found in output"
            raise ValueError(msg)

        return cast(
            ShowLacpInterfacesResult,
            {"aggregated_interfaces": aggregated},
        )

    @classmethod
    def _parse_state_line(
        cls,
        line: str,
        members: dict[str, MemberInterfaceEntry],
    ) -> None:
        """Parse an LACP state line (Actor or Partner) into the members dict."""
        match = cls._LACP_STATE.match(line)
        if not match:
            return

        member_name = match.group("member")
        role = match.group("role").lower()

        role_entry = LacpRoleEntry(
            expired=_yes_no(match.group("exp")),
            defaulted=_yes_no(match.group("def")),
            distributing=_yes_no(match.group("dist")),
            collecting=_yes_no(match.group("col")),
            synchronization=_yes_no(match.group("syn")),
            aggregation=_yes_no(match.group("aggr")),
            timeout=match.group("timeout"),
            activity=match.group("activity"),
        )

        if member_name not in members:
            members[member_name] = cast(MemberInterfaceEntry, {})

        member_dict = cast(dict[str, object], members[member_name])
        member_dict[role] = role_entry

    @classmethod
    def _parse_protocol_line(
        cls,
        line: str,
        members: dict[str, MemberInterfaceEntry],
    ) -> None:
        """Parse an LACP protocol line into the members dict."""
        match = cls._LACP_PROTOCOL.match(line)
        if not match:
            return

        member_name = match.group("member")
        protocol_entry = LacpProtocolEntry(
            receive_state=match.group("rx_state"),
            transmit_state=match.group("tx_state").strip(),
            mux_state=match.group("mux_state").strip(),
        )

        if member_name not in members:
            members[member_name] = cast(MemberInterfaceEntry, {})

        member_dict = cast(dict[str, object], members[member_name])
        member_dict["protocol"] = protocol_entry


def _yes_no(value: str) -> bool:
    """Convert 'Yes'/'No' string to boolean."""
    return value.lower() == "yes"
