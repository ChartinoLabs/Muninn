"""Parser for 'show bgp neighbor' command on Juniper Junos."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class TablePrefixes(TypedDict):
    """Schema for per-table prefix counts."""

    active_prefixes: int
    received_prefixes: int
    accepted_prefixes: int
    suppressed_due_to_damping: int
    advertised_prefixes: int
    rib_state: NotRequired[str]
    send_state: NotRequired[str]
    bit: NotRequired[int]


class MessageCounts(TypedDict):
    """Schema for BGP message counters."""

    total: int
    updates: int
    refreshes: int
    octets: int


class TrafficSeconds(TypedDict):
    """Schema for last-traffic seconds."""

    received: int
    sent: int
    checked: int


class BgpNeighborEntry(TypedDict):
    """Schema for a single BGP neighbor entry.

    Attributes:
        peer_address: Peer address without port.
        peer_port: TCP port of the peer.
        peer_as: Peer autonomous system number.
        local_address: Local address without port.
        local_port: TCP port of the local side.
        local_as: Local autonomous system number.
        type: Session type (External, Internal).
        state: BGP session state (Established, Active, etc.).
        flags: Session flags list.
        last_state: Previous BGP state.
        last_event: Last BGP event.
        export_policies: Export policy names.
        options: Session options list.
        holdtime: Configured hold time in seconds.
        preference: Route preference value.
        number_of_flaps: Number of session flaps.
        peer_id: BGP peer router ID.
        local_id: Local BGP router ID.
        active_holdtime: Active (negotiated) hold time in seconds.
        keepalive_interval: Keepalive interval in seconds.
        peer_index: Peer index number.
        bfd_status: BFD operational status string.
        nlri_configured_on_peer: NLRI for restart configured on peer.
        nlri_advertised_by_peer: NLRI advertised by peer.
        nlri_session: NLRI for this session.
        peer_supports_refresh: Whether peer supports refresh capability.
        stale_routes_kept_for: Stale route retention time in seconds.
        peer_supports_restarter: Whether peer supports restarter functionality.
        nlri_restart_negotiated: NLRI that restart is negotiated for.
        nlri_received_eor: NLRI of received end-of-rib markers.
        nlri_sent_eor: NLRI of all end-of-rib markers sent.
        peer_supports_4byte_as: Whether peer supports 4-byte AS extension.
        peer_supports_addpath: Whether peer supports Addpath.
        tables: Per-table prefix statistics.
        last_traffic: Last traffic timestamps in seconds.
        input_messages: Input message counters.
        output_messages: Output message counters.
        output_queues: Output queue depths keyed by queue index.
    """

    peer_address: str
    peer_port: int
    peer_as: int | str
    local_address: str
    local_port: int
    local_as: int | str
    type: NotRequired[str]
    state: NotRequired[str]
    flags: NotRequired[list[str]]
    last_state: NotRequired[str]
    last_event: NotRequired[str]
    export_policies: NotRequired[list[str]]
    options: NotRequired[list[str]]
    holdtime: NotRequired[int]
    preference: NotRequired[int]
    number_of_flaps: NotRequired[int]
    peer_id: NotRequired[str]
    local_id: NotRequired[str]
    active_holdtime: NotRequired[int]
    keepalive_interval: NotRequired[int]
    peer_index: NotRequired[int]
    bfd_status: NotRequired[str]
    local_interface: NotRequired[str]
    nlri_configured_on_peer: NotRequired[str]
    nlri_advertised_by_peer: NotRequired[str]
    nlri_session: NotRequired[str]
    peer_supports_refresh: NotRequired[bool]
    stale_routes_kept_for: NotRequired[int]
    peer_supports_restarter: NotRequired[bool]
    nlri_restart_negotiated: NotRequired[str]
    nlri_received_eor: NotRequired[str]
    nlri_sent_eor: NotRequired[str]
    peer_supports_4byte_as: NotRequired[bool]
    peer_supports_addpath: NotRequired[bool]
    tables: NotRequired[dict[str, TablePrefixes]]
    last_traffic: NotRequired[TrafficSeconds]
    input_messages: NotRequired[MessageCounts]
    output_messages: NotRequired[MessageCounts]
    output_queues: NotRequired[dict[str, int]]
    last_error: NotRequired[str]


class ShowBgpNeighborResult(TypedDict):
    """Schema for 'show bgp neighbor' parsed output on Juniper Junos.

    Dict-of-dicts keyed by peer address (without port).
    """

    neighbors: dict[str, BgpNeighborEntry]


# --- Peer header line ---
# Peer: 10.145.0.3+64180 AS 30000  Local: 10.145.0.1+179 AS 1
_PEER_HEADER_RE = re.compile(
    r"Peer:\s+(?P<peer_addr>\S+?)\+(?P<peer_port>\d+)\s+"
    r"AS\s+(?P<peer_as>[\d.]+)\s+"
    r"Local:\s+(?P<local_addr>\S+?)\+(?P<local_port>\d+)\s+"
    r"AS\s+(?P<local_as>[\d.]+)"
)

# Type: External    State: Established    Flags: <ImportEval Sync>
_TYPE_STATE_FLAGS_RE = re.compile(
    r"Type:\s+(?P<type>\S+)\s+"
    r"State:\s+(?P<state>\S+)\s+"
    r"Flags:\s+<(?P<flags>[^>]*)>"
)

# Last State: OpenConfirm   Last Event: RecvKeepAlive
_LAST_STATE_EVENT_RE = re.compile(
    r"Last State:\s+(?P<last_state>\S+)\s+"
    r"Last Event:\s+(?P<last_event>\S+)"
)

# Last Error: None
_LAST_ERROR_RE = re.compile(r"Last Error:\s+(.+)")

# Export: [ export2bgp ]
_EXPORT_RE = re.compile(r"Export:\s+\[\s*(.+?)\s*\]")

# Options: <Preference PeerAS Refresh>
_OPTIONS_RE = re.compile(r"Options:\s+<([^>]*)>")

# Holdtime: 90 Preference: 170
_HOLDTIME_PREF_RE = re.compile(
    r"Holdtime:\s+(?P<holdtime>\d+)\s+Preference:\s+(?P<preference>\d+)"
)

# Number of flaps: 0
_FLAPS_RE = re.compile(r"Number of flaps:\s+(?P<flaps>\d+)")

# Peer ID: 10.16.2.2         Local ID: 10.4.1.1           Active Holdtime: 90
_PEER_LOCAL_ID_RE = re.compile(
    r"Peer ID:\s+(?P<peer_id>\S+)\s+"
    r"Local ID:\s+(?P<local_id>\S+)\s+"
    r"Active Holdtime:\s+(?P<active_holdtime>\d+)"
)

# Keepalive Interval: 30         Peer index: 0
_KEEPALIVE_INDEX_RE = re.compile(
    r"Keepalive Interval:\s+(?P<keepalive>\d+)\s+"
    r"Peer index:\s+(?P<peer_index>\d+)"
)

# BFD: disabled, down
_BFD_RE = re.compile(r"BFD:\s+(.+)")

# Local Interface: ge-0/0/1.0
_LOCAL_INTF_RE = re.compile(r"Local Interface:\s+(\S+)")

# NLRI lines
_NLRI_RESTART_CONFIGURED_RE = re.compile(r"NLRI for restart configured on peer:\s+(.+)")
_NLRI_ADVERTISED_BY_PEER_RE = re.compile(r"NLRI advertised by peer:\s+(.+)")
_NLRI_SESSION_RE = re.compile(r"NLRI for this session:\s+(.+)")
_NLRI_RESTART_NEGOTIATED_RE = re.compile(r"NLRI that restart is negotiated for:\s+(.+)")
_NLRI_RECEIVED_EOR_RE = re.compile(r"NLRI of received end-of-rib markers:\s+(.+)")
_NLRI_SENT_EOR_RE = re.compile(r"NLRI of all end-of-rib markers sent:\s+(.+)")

# Peer supports Refresh capability (2)
_REFRESH_RE = re.compile(r"Peer supports Refresh capability")

# Stale routes from peer are kept for: 300
_STALE_ROUTES_RE = re.compile(r"Stale routes from peer are kept for:\s+(\d+)")

# Peer does not support Restarter functionality
_RESTARTER_SUPPORT_RE = re.compile(r"Peer does not support Restarter")
_RESTARTER_YES_RE = re.compile(r"Peer supports Restarter")

# Peer supports 4 byte AS extension (peer-as 30000)
_4BYTE_AS_RE = re.compile(r"Peer supports 4 byte AS extension")
_NO_4BYTE_AS_RE = re.compile(r"Peer does not support 4 byte AS")

# Peer does not support Addpath
_ADDPATH_RE = re.compile(r"Peer supports Addpath")
_NO_ADDPATH_RE = re.compile(r"Peer does not support Addpath")

# Table inet.0 Bit: 10000
_TABLE_RE = re.compile(r"Table\s+(?P<name>\S+)\s+Bit:\s+(?P<bit>\d+)")

# RIB State: BGP restart is complete
_RIB_STATE_RE = re.compile(r"RIB State:\s+(.+)")

# Send state: in sync
_SEND_STATE_RE = re.compile(r"Send state:\s+(.+)")

# Active prefixes:              1
_TABLE_COUNTER_RE = re.compile(r"(?P<key>[\w\s]+?):\s+(?P<val>\d+)\s*$")

# Last traffic (seconds): Received 6    Sent 1    Checked 52
_LAST_TRAFFIC_RE = re.compile(
    r"Last traffic \(seconds\):\s+"
    r"Received\s+(?P<received>\d+)\s+"
    r"Sent\s+(?P<sent>\d+)\s+"
    r"Checked\s+(?P<checked>\d+)"
)

# Input messages:  Total 9      Updates 2       Refreshes 0     Octets 244
_MSG_COUNTS_RE = re.compile(
    r"(?P<direction>Input|Output) messages:\s+"
    r"Total\s+(?P<total>\d+)\s+"
    r"Updates\s+(?P<updates>\d+)\s+"
    r"Refreshes\s+(?P<refreshes>\d+)\s+"
    r"Octets\s+(?P<octets>\d+)"
)

# Output Queue[0]: 0
_OUTPUT_QUEUE_RE = re.compile(r"Output Queue\[(?P<idx>\d+)\]:\s+(?P<depth>\d+)")


def _coerce_as(raw: str) -> int | str:
    """Return an AS number as ``int`` for asplain, or ``str`` for asdot.

    Junos can render 4-byte AS numbers either as a plain integer
    (``65000``) or in dotted form (``1.100``).  The dotted form must be
    preserved verbatim because it cannot be losslessly represented as an
    ``int``.
    """
    if "." in raw:
        return raw
    return int(raw)


def _split_into_peer_blocks(output: str) -> list[list[str]]:
    """Split output into per-peer line blocks."""
    blocks: list[list[str]] = []
    current: list[str] = []

    for line in output.splitlines():
        stripped = line.strip()
        if _PEER_HEADER_RE.search(stripped):
            if current:
                blocks.append(current)
            current = [stripped]
        elif current:
            current.append(line)

    if current:
        blocks.append(current)

    return blocks


def _parse_peer_header(lines: list[str]) -> BgpNeighborEntry | None:
    """Parse the peer header line and return a base entry, or None."""
    if not lines:
        return None

    m = _PEER_HEADER_RE.search(lines[0])
    if not m:
        return None

    entry: BgpNeighborEntry = {
        "peer_address": m.group("peer_addr"),
        "peer_port": int(m.group("peer_port")),
        "peer_as": _coerce_as(m.group("peer_as")),
        "local_address": m.group("local_addr"),
        "local_port": int(m.group("local_port")),
        "local_as": _coerce_as(m.group("local_as")),
    }
    return entry


def _parse_session_info(entry: BgpNeighborEntry, stripped: str) -> bool:
    """Parse type/state/flags, last state/event, and last error lines.

    Returns True if the line was consumed.
    """
    if m := _TYPE_STATE_FLAGS_RE.search(stripped):
        entry["type"] = m.group("type")
        entry["state"] = m.group("state")
        flags_str = m.group("flags").strip()
        entry["flags"] = flags_str.split() if flags_str else []
        return True

    if m := _LAST_STATE_EVENT_RE.search(stripped):
        entry["last_state"] = m.group("last_state")
        entry["last_event"] = m.group("last_event")
        return True

    if m := _LAST_ERROR_RE.search(stripped):
        error_val = m.group(1).strip()
        # "None" means no error -- omit per sentinel rules
        if error_val.lower() != "none":
            entry["last_error"] = error_val
        return True

    return False


def _parse_policy_and_timers(entry: BgpNeighborEntry, stripped: str) -> bool:
    """Parse export policies, options, holdtime, preference, and flaps.

    Returns True if the line was consumed.
    """
    if m := _EXPORT_RE.search(stripped):
        entry["export_policies"] = m.group(1).split()
        return True
    if m := _OPTIONS_RE.search(stripped):
        opts = m.group(1).strip()
        entry["options"] = opts.split() if opts else []
        return True
    if m := _HOLDTIME_PREF_RE.search(stripped):
        entry["holdtime"] = int(m.group("holdtime"))
        entry["preference"] = int(m.group("preference"))
        return True
    if m := _FLAPS_RE.search(stripped):
        entry["number_of_flaps"] = int(m.group("flaps"))
        return True
    return False


def _parse_id_and_interface(entry: BgpNeighborEntry, stripped: str) -> bool:
    """Parse peer/local IDs, keepalive, BFD, and local interface.

    Returns True if the line was consumed.
    """
    if m := _PEER_LOCAL_ID_RE.search(stripped):
        entry["peer_id"] = m.group("peer_id")
        entry["local_id"] = m.group("local_id")
        entry["active_holdtime"] = int(m.group("active_holdtime"))
        return True
    if m := _KEEPALIVE_INDEX_RE.search(stripped):
        entry["keepalive_interval"] = int(m.group("keepalive"))
        entry["peer_index"] = int(m.group("peer_index"))
        return True
    if m := _BFD_RE.search(stripped):
        entry["bfd_status"] = m.group(1).strip()
        return True
    if m := _LOCAL_INTF_RE.search(stripped):
        entry["local_interface"] = m.group(1)
        return True
    return False


def _parse_nlri_fields(entry: BgpNeighborEntry, stripped: str) -> bool:
    """Parse NLRI-related lines.

    Returns True if the line was consumed.
    """
    if m := _NLRI_RESTART_CONFIGURED_RE.search(stripped):
        entry["nlri_configured_on_peer"] = m.group(1).strip()
        return True
    if m := _NLRI_ADVERTISED_BY_PEER_RE.search(stripped):
        entry["nlri_advertised_by_peer"] = m.group(1).strip()
        return True
    if m := _NLRI_SESSION_RE.search(stripped):
        entry["nlri_session"] = m.group(1).strip()
        return True
    if m := _NLRI_RESTART_NEGOTIATED_RE.search(stripped):
        entry["nlri_restart_negotiated"] = m.group(1).strip()
        return True
    if m := _NLRI_RECEIVED_EOR_RE.search(stripped):
        entry["nlri_received_eor"] = m.group(1).strip()
        return True
    if m := _NLRI_SENT_EOR_RE.search(stripped):
        entry["nlri_sent_eor"] = m.group(1).strip()
        return True
    return False


def _parse_capabilities(entry: BgpNeighborEntry, stripped: str) -> bool:
    """Parse BGP capability advertisement lines.

    Returns True if the line was consumed.
    """
    if _REFRESH_RE.search(stripped):
        entry["peer_supports_refresh"] = True
        return True
    if m := _STALE_ROUTES_RE.search(stripped):
        entry["stale_routes_kept_for"] = int(m.group(1))
        return True
    if _RESTARTER_SUPPORT_RE.search(stripped):
        entry["peer_supports_restarter"] = False
        return True
    if _RESTARTER_YES_RE.search(stripped):
        entry["peer_supports_restarter"] = True
        return True
    if _4BYTE_AS_RE.search(stripped):
        entry["peer_supports_4byte_as"] = True
        return True
    if _NO_4BYTE_AS_RE.search(stripped):
        entry["peer_supports_4byte_as"] = False
        return True
    if _ADDPATH_RE.search(stripped):
        entry["peer_supports_addpath"] = True
        return True
    if _NO_ADDPATH_RE.search(stripped):
        entry["peer_supports_addpath"] = False
        return True
    return False


def _apply_table_counter(table: TablePrefixes, key_raw: str, val: int) -> bool:
    """Apply a table counter value by raw label name.

    Returns True if the key was recognized.
    """
    if key_raw == "Active prefixes":
        table["active_prefixes"] = val
    elif key_raw == "Received prefixes":
        table["received_prefixes"] = val
    elif key_raw == "Accepted prefixes":
        table["accepted_prefixes"] = val
    elif key_raw == "Suppressed due to damping":
        table["suppressed_due_to_damping"] = val
    elif key_raw == "Advertised prefixes":
        table["advertised_prefixes"] = val
    else:
        return False
    return True


def _parse_table_block(
    lines: list[str], start_idx: int
) -> tuple[str | None, TablePrefixes | None, int]:
    """Parse a Table block starting at start_idx.

    Returns (table_name, parsed TablePrefixes, index after block).
    """
    stripped = lines[start_idx].strip() if start_idx < len(lines) else ""
    m = _TABLE_RE.search(stripped)
    if not m:
        return None, None, start_idx

    table_name = m.group("name")
    table: TablePrefixes = {
        "bit": int(m.group("bit")),
        "active_prefixes": 0,
        "received_prefixes": 0,
        "accepted_prefixes": 0,
        "suppressed_due_to_damping": 0,
        "advertised_prefixes": 0,
    }

    idx = start_idx + 1
    while idx < len(lines):
        line = lines[idx].strip()
        if not line:
            idx += 1
            continue

        if rm := _RIB_STATE_RE.search(line):
            table["rib_state"] = rm.group(1).strip()
            idx += 1
            continue

        if sm := _SEND_STATE_RE.search(line):
            table["send_state"] = sm.group(1).strip()
            idx += 1
            continue

        if cm := _TABLE_COUNTER_RE.match(line):
            key = cm.group("key").strip()
            val = int(cm.group("val"))
            if _apply_table_counter(table, key, val):
                idx += 1
                continue

        # If we hit a line that doesn't belong to this table block, stop
        break

    return table_name, table, idx


def _parse_traffic_and_messages(
    entry: BgpNeighborEntry, lines: list[str], start_idx: int
) -> int:
    """Parse traffic, message counts, and output queues starting at index.

    Returns the index after all consumed lines.
    """
    idx = start_idx
    while idx < len(lines):
        stripped = lines[idx].strip()

        if m := _LAST_TRAFFIC_RE.search(stripped):
            entry["last_traffic"] = TrafficSeconds(
                received=int(m.group("received")),
                sent=int(m.group("sent")),
                checked=int(m.group("checked")),
            )
            idx += 1
            continue

        if m := _MSG_COUNTS_RE.search(stripped):
            counts = MessageCounts(
                total=int(m.group("total")),
                updates=int(m.group("updates")),
                refreshes=int(m.group("refreshes")),
                octets=int(m.group("octets")),
            )
            direction = m.group("direction")
            if direction == "Input":
                entry["input_messages"] = counts
            else:
                entry["output_messages"] = counts
            idx += 1
            continue

        if m := _OUTPUT_QUEUE_RE.search(stripped):
            if "output_queues" not in entry:
                entry["output_queues"] = {}
            entry["output_queues"][m.group("idx")] = int(m.group("depth"))
            idx += 1
            continue

        # Unrecognized line in the tail section -- skip
        idx += 1

    return idx


def _try_parse_text_line(entry: BgpNeighborEntry, stripped: str) -> bool:
    """Attempt to parse a single text line into the entry.

    Delegates to session, config, NLRI, and capability parsers.
    Returns True if the line was consumed.
    """
    if _parse_session_info(entry, stripped):
        return True
    if _parse_policy_and_timers(entry, stripped):
        return True
    if _parse_id_and_interface(entry, stripped):
        return True
    if _parse_nlri_fields(entry, stripped):
        return True
    return _parse_capabilities(entry, stripped)


def _parse_peer_block(lines: list[str]) -> BgpNeighborEntry | None:
    """Parse a single peer block into a BgpNeighborEntry."""
    entry = _parse_peer_header(lines)
    if entry is None:
        return None

    idx = 1
    tables: dict[str, TablePrefixes] = {}

    while idx < len(lines):
        stripped = lines[idx].strip()

        if not stripped:
            idx += 1
            continue

        if _try_parse_text_line(entry, stripped):
            idx += 1
            continue

        # Table prefix block
        if _TABLE_RE.search(stripped):
            table_name, table, idx = _parse_table_block(lines, idx)
            if table_name is not None and table is not None:
                tables[table_name] = table
            continue

        # Traffic, messages, output queues
        if _LAST_TRAFFIC_RE.search(stripped):
            _parse_traffic_and_messages(entry, lines, idx)
            break

        idx += 1

    if tables:
        entry["tables"] = tables

    return entry


@register(OS.JUNIPER_JUNOS, "show bgp neighbor")
class ShowBgpNeighborParser(BaseParser["ShowBgpNeighborResult"]):
    """Parser for 'show bgp neighbor' command on Juniper Junos.

    Parses detailed BGP neighbor information including session state,
    capabilities, NLRI details, per-table prefix counts, message
    counters, and traffic statistics.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BGP, ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowBgpNeighborResult:
        """Parse 'show bgp neighbor' output on Juniper Junos.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed BGP neighbor data keyed by peer address.

        Raises:
            ValueError: If no BGP neighbors found in output.
        """
        blocks = _split_into_peer_blocks(output)
        neighbors: dict[str, BgpNeighborEntry] = {}

        for block in blocks:
            entry = _parse_peer_block(block)
            if entry is not None:
                neighbors[entry["peer_address"]] = entry

        if not neighbors:
            msg = "No BGP neighbors found in output"
            raise ValueError(msg)

        return cast(ShowBgpNeighborResult, {"neighbors": neighbors})
