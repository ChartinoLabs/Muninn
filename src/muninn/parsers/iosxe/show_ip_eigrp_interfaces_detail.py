"""Parser for 'show ip eigrp interfaces detail' on IOS-XE.

Also handles 'show ipv6 eigrp interfaces detail'.
"""

import re
from collections.abc import Callable
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class EigrpInterfaceDetailEntry(TypedDict):
    """Schema for a single EIGRP interface detail entry."""

    peers: int
    xmit_q_unreliable: int
    xmit_q_reliable: int
    peer_q_unreliable: int
    peer_q_reliable: int
    mean_srtt: int
    pacing_time_unreliable: int
    pacing_time_reliable: int
    mcast_flow_timer: int
    pending_routes: int
    hello_interval: int
    hold_time: int
    split_horizon_enabled: bool
    next_xmit_serial: str
    packetized_sent: int
    packetized_expedited: int
    hellos_sent: int
    hellos_expedited: int
    unreliable_mcasts: int
    reliable_mcasts: int
    unreliable_ucasts: int
    reliable_ucasts: int
    mcast_exceptions: int
    cr_packets: int
    acks_suppressed: int
    retransmissions_sent: int
    out_of_sequence_rcvd: int
    authentication_mode: NotRequired[str]
    topologies_advertised: NotRequired[str]


class ShowIpEigrpInterfacesDetailResult(TypedDict):
    """Schema for 'show ip eigrp interfaces detail' parsed output."""

    as_number: int
    interfaces: dict[str, EigrpInterfaceDetailEntry]


_AS_PATTERN = re.compile(r"^EIGRP-IPv[46] Interfaces for AS\((?P<as_number>\d+)\)")

_INTERFACE_ROW_PATTERN = re.compile(
    r"^(?P<interface>\S+)\s+"
    r"(?P<peers>\d+)\s+"
    r"(?P<xmit_q_un>\d+)/(?P<xmit_q_rel>\d+)\s+"
    r"(?P<peer_q_un>\d+)/(?P<peer_q_rel>\d+)\s+"
    r"(?P<mean_srtt>\d+)\s+"
    r"(?P<pacing_un>\d+)/(?P<pacing_rel>\d+)\s+"
    r"(?P<mcast_flow>\d+)\s+"
    r"(?P<pend_routes>\d+)\s*$"
)


def _extract_hello_hold(match: re.Match[str], entry: dict[str, object]) -> None:
    """Extract hello interval and hold time."""
    entry["hello_interval"] = int(match.group("hello"))
    entry["hold_time"] = int(match.group("hold"))


def _extract_split_horizon(match: re.Match[str], entry: dict[str, object]) -> None:
    """Extract split horizon status."""
    entry["split_horizon_enabled"] = match.group("value") == "enabled"


def _extract_next_xmit(match: re.Match[str], entry: dict[str, object]) -> None:
    """Extract next xmit serial."""
    entry["next_xmit_serial"] = match.group("value").strip()


def _extract_packetized(match: re.Match[str], entry: dict[str, object]) -> None:
    """Extract packetized sent/expedited counters."""
    entry["packetized_sent"] = int(match.group("sent"))
    entry["packetized_expedited"] = int(match.group("expedited"))


def _extract_hellos(match: re.Match[str], entry: dict[str, object]) -> None:
    """Extract hello sent/expedited counters."""
    entry["hellos_sent"] = int(match.group("sent"))
    entry["hellos_expedited"] = int(match.group("expedited"))


def _extract_mcasts_ucasts(match: re.Match[str], entry: dict[str, object]) -> None:
    """Extract multicast and unicast counters."""
    entry["unreliable_mcasts"] = int(match.group("un_mcast"))
    entry["reliable_mcasts"] = int(match.group("rel_mcast"))
    entry["unreliable_ucasts"] = int(match.group("un_ucast"))
    entry["reliable_ucasts"] = int(match.group("rel_ucast"))


def _extract_mcast_cr_acks(match: re.Match[str], entry: dict[str, object]) -> None:
    """Extract mcast exceptions, CR packets, and ACKs suppressed."""
    entry["mcast_exceptions"] = int(match.group("mcast_ex"))
    entry["cr_packets"] = int(match.group("cr"))
    entry["acks_suppressed"] = int(match.group("acks"))


def _extract_retrans(match: re.Match[str], entry: dict[str, object]) -> None:
    """Extract retransmission and out-of-sequence counters."""
    entry["retransmissions_sent"] = int(match.group("retrans"))
    entry["out_of_sequence_rcvd"] = int(match.group("oos"))


def _extract_auth_mode(match: re.Match[str], entry: dict[str, object]) -> None:
    """Extract authentication mode if set."""
    value = match.group("value").strip()
    if value != "not set":
        entry["authentication_mode"] = value


def _extract_topologies_adv(match: re.Match[str], entry: dict[str, object]) -> None:
    """Extract advertised topologies if present."""
    value = match.group("value").strip()
    if value:
        entry["topologies_advertised"] = value


_DetailHandler = Callable[[re.Match[str], dict[str, object]], None]

_DETAIL_TABLE: tuple[tuple[re.Pattern[str], _DetailHandler], ...] = (
    (
        re.compile(
            r"Hello-interval is (?P<hello>\d+), "
            r"Hold-time is (?P<hold>\d+)"
        ),
        _extract_hello_hold,
    ),
    (
        re.compile(r"Split-horizon is (?P<value>\S+)"),
        _extract_split_horizon,
    ),
    (
        re.compile(r"Next xmit serial (?P<value>.+)"),
        _extract_next_xmit,
    ),
    (
        re.compile(
            r"Packetized sent/expedited:\s*"
            r"(?P<sent>\d+)/(?P<expedited>\d+)"
        ),
        _extract_packetized,
    ),
    (
        re.compile(
            r"Hello's sent/expedited:\s*"
            r"(?P<sent>\d+)/(?P<expedited>\d+)"
        ),
        _extract_hellos,
    ),
    (
        re.compile(
            r"Un/reliable mcasts:\s*(?P<un_mcast>\d+)/(?P<rel_mcast>\d+)"
            r"\s+Un/reliable ucasts:\s*"
            r"(?P<un_ucast>\d+)/(?P<rel_ucast>\d+)"
        ),
        _extract_mcasts_ucasts,
    ),
    (
        re.compile(
            r"Mcast exceptions:\s*(?P<mcast_ex>\d+)\s+"
            r"CR packets:\s*(?P<cr>\d+)\s+"
            r"ACKs suppressed:\s*(?P<acks>\d+)"
        ),
        _extract_mcast_cr_acks,
    ),
    (
        re.compile(
            r"Retransmissions sent:\s*(?P<retrans>\d+)\s+"
            r"Out-of-sequence rcvd:\s*(?P<oos>\d+)"
        ),
        _extract_retrans,
    ),
    (
        re.compile(r"Authentication mode is (?P<value>.+)"),
        _extract_auth_mode,
    ),
    (
        re.compile(r"Topologies advertised on this interface:\s*(?P<value>.+)"),
        _extract_topologies_adv,
    ),
)


def _parse_detail_line(
    entry: dict[str, object],
    line: str,
) -> None:
    """Match a detail line against the pattern table and apply handler."""
    for pattern, handler in _DETAIL_TABLE:
        match = pattern.match(line)
        if match:
            handler(match, entry)
            return


def _build_entry_from_row(match: re.Match[str]) -> dict[str, object]:
    """Build initial entry dict from the interface table row match."""
    return {
        "peers": int(match.group("peers")),
        "xmit_q_unreliable": int(match.group("xmit_q_un")),
        "xmit_q_reliable": int(match.group("xmit_q_rel")),
        "peer_q_unreliable": int(match.group("peer_q_un")),
        "peer_q_reliable": int(match.group("peer_q_rel")),
        "mean_srtt": int(match.group("mean_srtt")),
        "pacing_time_unreliable": int(match.group("pacing_un")),
        "pacing_time_reliable": int(match.group("pacing_rel")),
        "mcast_flow_timer": int(match.group("mcast_flow")),
        "pending_routes": int(match.group("pend_routes")),
    }


@register(OS.CISCO_IOSXE, "show ip eigrp interfaces detail")
@register(OS.CISCO_IOSXE, "show ipv6 eigrp interfaces detail")
class ShowIpEigrpInterfacesDetailParser(
    BaseParser[ShowIpEigrpInterfacesDetailResult],
):
    """Parser for EIGRP interface detail commands.

    Handles both IPv4 and IPv6 variants.

    Example output:
        EIGRP-IPv4 Interfaces for AS(10)
        Gi0/2          0    0/0   0/0   0   0/0   0   0
          Hello-interval is 5, Hold-time is 15
          Split-horizon is enabled
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.EIGRP,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpEigrpInterfacesDetailResult:
        """Parse EIGRP interfaces detail output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed EIGRP interface detail data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        as_number: int | None = None
        interfaces: dict[str, EigrpInterfaceDetailEntry] = {}
        current_entry: dict[str, object] | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if as_number is None:
                as_match = _AS_PATTERN.match(stripped)
                if as_match:
                    as_number = int(as_match.group("as_number"))
                continue

            row_match = _INTERFACE_ROW_PATTERN.match(stripped)
            if row_match:
                current_entry = _build_entry_from_row(row_match)
                iface = canonical_interface_name(
                    row_match.group("interface"), os=OS.CISCO_IOSXE
                )
                interfaces[iface] = cast(EigrpInterfaceDetailEntry, current_entry)
                continue

            if current_entry is not None:
                _parse_detail_line(current_entry, stripped)

        if as_number is None:
            msg = "No EIGRP AS number found in output"
            raise ValueError(msg)

        if not interfaces:
            msg = "No EIGRP interface entries found in output"
            raise ValueError(msg)

        return ShowIpEigrpInterfacesDetailResult(
            as_number=as_number,
            interfaces=interfaces,
        )
