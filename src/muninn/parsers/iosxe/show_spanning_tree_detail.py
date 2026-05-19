"""Parser for 'show spanning-tree detail' command on IOS-XE."""

import re
from collections.abc import Callable
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

# --- Per-instance regex patterns ---

# VLAN0001 is executing the rstp compatible Spanning Tree protocol
# MST0    is executing the mstp compatible Spanning Tree protocol
_INSTANCE_HEADER_RE = re.compile(
    r"^(?P<instance>(?:VLAN|MST)\d+)\s+is\s+executing\s+the\s+"
    r"(?P<protocol>[\w\-]+)\s+compatible\s+Spanning\s+Tree\s+protocol\s*$"
)

# No spanning tree instance exists.
_NO_INSTANCE_RE = re.compile(
    r"^No\s+spanning\s+tree\s+(?:instance|instances)\s+exists?\.?\s*$",
    re.IGNORECASE,
)

# Bridge Identifier has priority 32768, sysid 1, address ac3a.6728.0f80
_BRIDGE_ID_RE = re.compile(
    r"^Bridge\s+Identifier\s+has\s+priority\s+(?P<priority>\d+),\s+"
    r"sysid\s+(?P<sysid>\d+),\s+address\s+(?P<address>[0-9a-fA-F.]+)\s*$"
)

# Configured hello time 2, max age 20, forward delay 15, transmit hold-count 6
# Configured hello time 2, max age 20, forward delay 15, tranmsit hold-count 6
# Configured hello time 2, max age 20, forward delay 15
_CONFIGURED_RE = re.compile(
    r"^Configured\s+hello\s+time\s+(?P<hello_time>\d+),\s+"
    r"max\s+age\s+(?P<max_age>\d+),\s+"
    r"forward\s+delay\s+(?P<forward_delay>\d+)"
    r"(?:,\s+(?:transmit|tranmsit)\s+hold-count\s+(?P<hold_count>\d+))?\s*$"
)

# We are the root of the spanning tree
_IS_ROOT_RE = re.compile(r"^We\s+are\s+the\s+root\s+of\s+the\s+spanning\s+tree\s*$")

# Current root has priority 24777, address 58bf.eaff.e5b6
_CURRENT_ROOT_RE = re.compile(
    r"^Current\s+root\s+has\s+priority\s+(?P<priority>\d+),\s+"
    r"address\s+(?P<address>[0-9a-fA-F.]+)\s*$"
)

# Root port is 2390 (Port-channel14), cost of root path is 3
_ROOT_PORT_RE = re.compile(
    r"^Root\s+port\s+is\s+(?P<port_num>\d+)\s+\((?P<port_name>\S+)\),\s+"
    r"cost\s+of\s+root\s+path\s+is\s+(?P<cost>\d+)\s*$"
)

# Topology change flag not set, detected flag not set
_TOPOLOGY_FLAGS_RE = re.compile(
    r"^Topology\s+change\s+flag\s+(?P<change>not\s+set|set),\s+"
    r"detected\s+flag\s+(?P<detected>not\s+set|set)\s*$"
)

# Number of topology changes 21 last change occurred 1w6d ago
# Number of topology changes 3 last change occurred 03:09:48 ago
_TOPOLOGY_CHANGES_RE = re.compile(
    r"^Number\s+of\s+topology\s+changes\s+(?P<count>\d+)\s+"
    r"last\s+change\s+occurred\s+(?P<since>\S+)(?:\s+ago)?\s*$"
)

# from GigabitEthernet1/0/5
_TOPOLOGY_FROM_RE = re.compile(r"^from\s+(?P<port>\S+)\s*$")

# Times:  hold 1, topology change 35, notification 2
_TIMES_LINE1_RE = re.compile(
    r"^Times:\s+hold\s+(?P<hold>\d+),\s+"
    r"topology\s+change\s+(?P<topology_change>\d+),\s+"
    r"notification\s+(?P<notification>\d+)\s*$"
)

# hello 2, max age 20, forward delay 15
_TIMES_LINE2_RE = re.compile(
    r"^hello\s+(?P<hello>\d+),\s+"
    r"max\s+age\s+(?P<max_age>\d+),\s+"
    r"forward\s+delay\s+(?P<forward_delay>\d+)\s*$"
)

# Timers: hello 0, topology change 0, notification 0, aging 300
# Timers: hello 0, topology change 0, notification 0
_TIMERS_RE = re.compile(
    r"^Timers:\s+hello\s+(?P<hello>\d+),\s+"
    r"topology\s+change\s+(?P<topology_change>\d+),\s+"
    r"notification\s+(?P<notification>\d+)"
    r"(?:,\s+aging\s+(?P<aging>\d+))?\s*$"
)

# --- Per-port regex patterns ---

# Port 65 (AppGigabitEthernet1/0/1) of VLAN0001 is designated forwarding
# Port 2390 (Port-channel14) of MST0 is broken  (PVST Sim. Inconsistent)
_PORT_HEADER_RE = re.compile(
    r"^Port\s+(?P<port_num>\d+)\s*\((?P<port_name>\S+)\)\s+"
    r"of\s+(?P<instance>(?:VLAN|MST)\d+)\s+is\s+(?P<status>.+?)\s*$"
)

# Port path cost 20000, Port priority 128, Port Identifier 128.65.
_PORT_COST_RE = re.compile(
    r"^Port\s+path\s+cost\s+(?P<cost>\d+),\s+"
    r"Port\s+priority\s+(?P<priority>\d+),\s+"
    r"Port\s+Identifier\s+(?P<identifier>[\w.]+?)\.?\s*$"
)

# Designated root has priority 32769, address ac3a.6728.0f80
_DESIGNATED_ROOT_RE = re.compile(
    r"^Designated\s+root\s+has\s+priority\s+(?P<priority>\d+),\s+"
    r"address\s+(?P<address>[0-9a-fA-F.]+)\s*$"
)

# Designated bridge has priority 32769, address ac3a.6728.0f80
_DESIGNATED_BRIDGE_RE = re.compile(
    r"^Designated\s+bridge\s+has\s+priority\s+(?P<priority>\d+),\s+"
    r"address\s+(?P<address>[0-9a-fA-F.]+)\s*$"
)

# Designated port id is 128.65, designated path cost 0
_DESIGNATED_PORT_RE = re.compile(
    r"^Designated\s+port\s+id\s+is\s+(?P<port_id>[\w.]+),\s+"
    r"designated\s+path\s+cost\s+(?P<cost>\d+)\s*$"
)

# Timers: message age 0, forward delay 0, hold 0
_PORT_TIMERS_RE = re.compile(
    r"^Timers:\s+message\s+age\s+(?P<message_age>\d+),\s+"
    r"forward\s+delay\s+(?P<forward_delay>\d+),\s+"
    r"hold\s+(?P<hold>\d+)\s*$"
)

# Number of transitions to forwarding state: 1
_FWD_TRANSITIONS_RE = re.compile(
    r"^Number\s+of\s+transitions\s+to\s+forwarding\s+state:\s+(?P<count>\d+)\s*$"
)

# Link type is point-to-point by default
# Link type is point-to-point by default, Internal
# Link type is point-to-point by default, Boundary PVST
# Link type is point-to-point by default, Peer is STP
_LINK_TYPE_RE = re.compile(
    r"^Link\s+type\s+is\s+(?P<link_type>[\w\-]+)\s+by\s+default"
    r"(?:,\s+(?P<extras>.+?))?\s*$"
)

# The port is in the portfast edge trunk mode
_PORTFAST_RE = re.compile(
    r"^The\s+port\s+is\s+in\s+the\s+portfast\s+(?P<mode>.+?)\s+mode\s*$"
)

# Loop guard is enabled by default on the port
_LOOP_GUARD_RE = re.compile(
    r"^Loop\s+guard\s+is\s+(?P<state>\w+)\s+by\s+default\s+on\s+the\s+port\s*$"
)

# BPDU: sent 608135, received 0
_BPDU_RE = re.compile(
    r"^BPDU:\s+sent\s+(?P<sent>\d+),\s+received\s+(?P<received>\d+)\s*$"
)


class StpTimes(TypedDict):
    """Schema for the 'Times:' configured/operational time values."""

    hold: int
    topology_change: int
    notification: int
    hello: int
    max_age: int
    forward_delay: int


class StpTimers(TypedDict):
    """Schema for the 'Timers:' live countdown values."""

    hello: int
    topology_change: int
    notification: int
    aging: NotRequired[int]


class RootInfo(TypedDict):
    """Schema for the 'Current root' / 'Root port' section (non-root only)."""

    priority: int
    address: str
    cost: NotRequired[int]
    port_num: NotRequired[int]
    port_name: NotRequired[str]


class PortTimers(TypedDict):
    """Schema for per-port 'Timers:' values."""

    message_age: int
    forward_delay: int
    hold: int


class PortBpdu(TypedDict):
    """Schema for per-port BPDU counters."""

    sent: int
    received: int


class PortEntry(TypedDict):
    """Schema for a single port in a spanning-tree instance."""

    name: str
    port_num: int
    status: str
    extra_status: NotRequired[str]
    port_path_cost: int
    port_priority: int
    port_identifier: str
    designated_root_priority: int
    designated_root_address: str
    designated_bridge_priority: int
    designated_bridge_address: str
    designated_port_id: str
    designated_path_cost: int
    timers: PortTimers
    forwarding_transitions: int
    link_type: str
    link_type_extras: NotRequired[list[str]]
    peer: NotRequired[str]
    portfast_mode: NotRequired[str]
    loop_guard: NotRequired[str]
    bpdu: PortBpdu


class InstanceEntry(TypedDict):
    """Schema for a single spanning-tree instance (VLAN or MST)."""

    name: str
    protocol: str
    bridge_priority: int
    sys_id_ext: int
    bridge_address: str
    hello_time: int
    max_age: int
    forward_delay: int
    transmit_hold_count: NotRequired[int]
    is_root: bool
    root_info: NotRequired[RootInfo]
    topology_change_flag: bool
    topology_detected_flag: bool
    topology_changes: int
    last_change: str
    topology_change_from: NotRequired[str]
    times: StpTimes
    timers: StpTimers
    ports: dict[str, PortEntry]


class ShowSpanningTreeDetailResult(TypedDict):
    """Schema for 'show spanning-tree detail' parsed output."""

    instances: dict[str, InstanceEntry]


def _split_instance_blocks(output: str) -> list[tuple[str, str, list[str]]]:
    """Split raw output into per-instance blocks.

    Returns a list of (instance_name, protocol, lines) tuples.
    """
    blocks: list[tuple[str, str, list[str]]] = []
    current_name: str | None = None
    current_protocol: str | None = None
    current_lines: list[str] = []

    for line in output.splitlines():
        header = _INSTANCE_HEADER_RE.match(line.strip())
        if header:
            if current_name is not None and current_protocol is not None:
                blocks.append((current_name, current_protocol, current_lines))
            current_name = header.group("instance")
            current_protocol = header.group("protocol")
            current_lines = []
        elif current_name is not None:
            current_lines.append(line)

    if current_name is not None and current_protocol is not None:
        blocks.append((current_name, current_protocol, current_lines))

    return blocks


def _split_port_blocks(lines: list[str]) -> tuple[list[str], list[list[str]]]:
    """Split an instance's lines into (instance_header_lines, [port_block, ...]).

    The instance header section is everything before the first ``Port ...`` line.
    Each port block is the ``Port ...`` line plus its indented continuation lines.
    """
    header_lines: list[str] = []
    port_blocks: list[list[str]] = []
    current_block: list[str] | None = None

    for line in lines:
        if _PORT_HEADER_RE.match(line.strip()):
            if current_block is not None:
                port_blocks.append(current_block)
            current_block = [line]
        elif current_block is not None:
            current_block.append(line)
        else:
            header_lines.append(line)

    if current_block is not None:
        port_blocks.append(current_block)

    return header_lines, port_blocks


def _parse_status(raw_status: str) -> tuple[str, str | None]:
    """Split the port status into a base status and an optional parenthetical.

    Examples:
        "designated forwarding" -> ("designated forwarding", None)
        "broken  (PVST Sim. Inconsistent)" ->
            ("broken", "PVST Sim. Inconsistent")
    """
    match = re.match(r"^(?P<base>[^()]+?)(?:\s+\((?P<extra>[^)]+)\))?\s*$", raw_status)
    if match is None:
        return raw_status.strip(), None
    base = match.group("base").strip()
    extra = match.group("extra")
    return base, (extra.strip() if extra else None)


def _try_parse_root_info(line: str, instance: dict, *, is_root: bool) -> bool:
    """Attempt to populate ``root_info`` from a non-root header line."""
    if is_root:
        return False

    current = _CURRENT_ROOT_RE.match(line)
    if current:
        root = cast(dict, instance.setdefault("root_info", {}))
        root["priority"] = int(current.group("priority"))
        root["address"] = current.group("address")
        return True

    root_port = _ROOT_PORT_RE.match(line)
    if root_port:
        root = cast(dict, instance.setdefault("root_info", {}))
        root["port_num"] = int(root_port.group("port_num"))
        root["port_name"] = canonical_interface_name(
            root_port.group("port_name"), os=OS.CISCO_IOSXE
        )
        root["cost"] = int(root_port.group("cost"))
        return True

    return False


def _apply_bridge_id(match: re.Match[str], instance: dict) -> None:
    """Populate bridge identifier fields on ``instance``."""
    instance["bridge_priority"] = int(match.group("priority"))
    instance["sys_id_ext"] = int(match.group("sysid"))
    instance["bridge_address"] = match.group("address")


def _apply_configured(match: re.Match[str], instance: dict) -> None:
    """Populate configured hello / max-age / forward-delay (+optional hold-count)."""
    instance["hello_time"] = int(match.group("hello_time"))
    instance["max_age"] = int(match.group("max_age"))
    instance["forward_delay"] = int(match.group("forward_delay"))
    hold = match.group("hold_count")
    if hold is not None:
        instance["transmit_hold_count"] = int(hold)


def _apply_topology_flags(match: re.Match[str], instance: dict) -> None:
    """Populate topology change / detected flags."""
    instance["topology_change_flag"] = match.group("change") == "set"
    instance["topology_detected_flag"] = match.group("detected") == "set"


def _apply_topology_changes(match: re.Match[str], instance: dict) -> None:
    """Populate topology change count and last-change timestamp."""
    instance["topology_changes"] = int(match.group("count"))
    instance["last_change"] = match.group("since")


def _apply_topology_from(match: re.Match[str], instance: dict) -> None:
    """Populate topology-change source interface (canonicalized)."""
    instance["topology_change_from"] = canonical_interface_name(
        match.group("port"), os=OS.CISCO_IOSXE
    )


def _apply_times_line1(match: re.Match[str], instance: dict) -> None:
    """Populate the first 'Times:' line (hold / topology change / notification)."""
    times = cast(dict, instance.setdefault("times", {}))
    times["hold"] = int(match.group("hold"))
    times["topology_change"] = int(match.group("topology_change"))
    times["notification"] = int(match.group("notification"))


def _apply_times_line2(match: re.Match[str], instance: dict) -> None:
    """Populate the second 'Times:' line (hello / max age / forward delay)."""
    times = cast(dict, instance.setdefault("times", {}))
    times["hello"] = int(match.group("hello"))
    times["max_age"] = int(match.group("max_age"))
    times["forward_delay"] = int(match.group("forward_delay"))


def _apply_timers(match: re.Match[str], instance: dict) -> None:
    """Populate the live 'Timers:' line (hello / topology change / notification)."""
    timers: dict = {
        "hello": int(match.group("hello")),
        "topology_change": int(match.group("topology_change")),
        "notification": int(match.group("notification")),
    }
    aging = match.group("aging")
    if aging is not None:
        timers["aging"] = int(aging)
    instance["timers"] = timers


_InstanceHandler = Callable[[re.Match[str], dict], None]

_INSTANCE_HANDLERS: tuple[tuple[re.Pattern[str], _InstanceHandler], ...] = (
    (_BRIDGE_ID_RE, _apply_bridge_id),
    (_CONFIGURED_RE, _apply_configured),
    (_TOPOLOGY_FLAGS_RE, _apply_topology_flags),
    (_TOPOLOGY_CHANGES_RE, _apply_topology_changes),
    (_TOPOLOGY_FROM_RE, _apply_topology_from),
    (_TIMES_LINE1_RE, _apply_times_line1),
    (_TIMES_LINE2_RE, _apply_times_line2),
    (_TIMERS_RE, _apply_timers),
)


def _consume_instance_line(line: str, instance: dict) -> bool:
    """Dispatch a single (non-port) instance header line to its handler.

    Returns True if the line was handled.
    """
    if _IS_ROOT_RE.match(line):
        instance["is_root"] = True
        return True

    if _try_parse_root_info(line, instance, is_root=instance["is_root"]):
        return True

    for pattern, handler in _INSTANCE_HANDLERS:
        match = pattern.match(line)
        if match:
            handler(match, instance)
            return True

    return False


def _parse_instance_header(name: str, protocol: str, lines: list[str]) -> dict:
    """Parse the per-instance header lines (everything before first 'Port ...')."""
    instance: dict = {
        "name": name,
        "protocol": protocol,
        "is_root": False,
        "ports": {},
    }

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        _consume_instance_line(line, instance)

    return instance


def _parse_link_type_extras(extras: str) -> tuple[list[str], dict[str, str]]:
    """Split the comma-separated post-default link-type extras.

    Returns a list of unrecognized tokens and a dict of recognized keyed
    attributes (currently ``peer`` for ``Peer is X``).
    """
    items = [piece.strip() for piece in extras.split(",") if piece.strip()]
    keyed: dict[str, str] = {}
    remaining: list[str] = []
    for item in items:
        peer = re.match(r"^Peer\s+is\s+(?P<peer>.+)$", item)
        if peer:
            keyed["peer"] = peer.group("peer").strip()
            continue
        remaining.append(item)
    return remaining, keyed


def _parse_port_block(lines: list[str]) -> PortEntry | None:
    """Parse a single port block (the header plus its continuation lines)."""
    header = _PORT_HEADER_RE.match(lines[0].strip())
    if header is None:
        return None

    base_status, extra_status = _parse_status(header.group("status"))
    port: dict = {
        "name": canonical_interface_name(header.group("port_name"), os=OS.CISCO_IOSXE),
        "port_num": int(header.group("port_num")),
        "status": base_status,
    }
    if extra_status:
        port["extra_status"] = extra_status

    for raw_line in lines[1:]:
        line = raw_line.strip()
        if not line:
            continue

        if _consume_port_line(line, port):
            continue

    return cast(PortEntry, port)


def _apply_port_cost(match: re.Match[str], port: dict) -> None:
    """Populate ``port path cost`` / priority / identifier."""
    port["port_path_cost"] = int(match.group("cost"))
    port["port_priority"] = int(match.group("priority"))
    port["port_identifier"] = match.group("identifier")


def _apply_designated_root(match: re.Match[str], port: dict) -> None:
    """Populate designated-root priority and address."""
    port["designated_root_priority"] = int(match.group("priority"))
    port["designated_root_address"] = match.group("address")


def _apply_designated_bridge(match: re.Match[str], port: dict) -> None:
    """Populate designated-bridge priority and address."""
    port["designated_bridge_priority"] = int(match.group("priority"))
    port["designated_bridge_address"] = match.group("address")


def _apply_designated_port(match: re.Match[str], port: dict) -> None:
    """Populate designated-port id and path cost."""
    port["designated_port_id"] = match.group("port_id")
    port["designated_path_cost"] = int(match.group("cost"))


def _apply_port_timers(match: re.Match[str], port: dict) -> None:
    """Populate per-port message-age / forward-delay / hold timers."""
    port["timers"] = {
        "message_age": int(match.group("message_age")),
        "forward_delay": int(match.group("forward_delay")),
        "hold": int(match.group("hold")),
    }


def _apply_fwd_transitions(match: re.Match[str], port: dict) -> None:
    """Populate the forwarding-state transition counter."""
    port["forwarding_transitions"] = int(match.group("count"))


def _apply_link_type(match: re.Match[str], port: dict) -> None:
    """Populate link type plus optional extras (Internal, Boundary, Peer is ...)."""
    port["link_type"] = match.group("link_type")
    extras = match.group("extras")
    if not extras:
        return
    tokens, keyed = _parse_link_type_extras(extras)
    if tokens:
        port["link_type_extras"] = tokens
    for key, value in keyed.items():
        port[key] = value


def _apply_portfast(match: re.Match[str], port: dict) -> None:
    """Populate the portfast mode (e.g. ``edge``, ``edge trunk``)."""
    port["portfast_mode"] = match.group("mode").strip()


def _apply_loop_guard(match: re.Match[str], port: dict) -> None:
    """Populate the loop-guard state (``enabled`` / ``disabled``)."""
    port["loop_guard"] = match.group("state")


def _apply_bpdu(match: re.Match[str], port: dict) -> None:
    """Populate BPDU sent/received counters."""
    port["bpdu"] = {
        "sent": int(match.group("sent")),
        "received": int(match.group("received")),
    }


_PortHandler = Callable[[re.Match[str], dict], None]

_PORT_HANDLERS: tuple[tuple[re.Pattern[str], _PortHandler], ...] = (
    (_PORT_COST_RE, _apply_port_cost),
    (_DESIGNATED_ROOT_RE, _apply_designated_root),
    (_DESIGNATED_BRIDGE_RE, _apply_designated_bridge),
    (_DESIGNATED_PORT_RE, _apply_designated_port),
    (_PORT_TIMERS_RE, _apply_port_timers),
    (_FWD_TRANSITIONS_RE, _apply_fwd_transitions),
    (_LINK_TYPE_RE, _apply_link_type),
    (_PORTFAST_RE, _apply_portfast),
    (_LOOP_GUARD_RE, _apply_loop_guard),
    (_BPDU_RE, _apply_bpdu),
)


def _consume_port_line(line: str, port: dict) -> bool:
    """Dispatch a single port detail line to the matching handler."""
    for pattern, handler in _PORT_HANDLERS:
        match = pattern.match(line)
        if match:
            handler(match, port)
            return True
    return False


def _is_no_instance_output(output: str) -> bool:
    """Detect the 'No spanning tree instance exists.' empty-state output."""
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        return bool(_NO_INSTANCE_RE.match(line))
    return False


@register(OS.CISCO_IOSXE, "show spanning-tree detail")
class ShowSpanningTreeDetailParser(BaseParser[ShowSpanningTreeDetailResult]):
    """Parser for 'show spanning-tree detail' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.STP,
            ParserTag.SWITCHING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowSpanningTreeDetailResult:
        """Parse 'show spanning-tree detail' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Mapping of instance name (``VLAN0001``, ``MST0``, ...) to its
            parsed bridge, topology, timer, and per-port information.
            Returns ``{"instances": {}}`` when the device reports no STP
            instances exist.
        """
        if _is_no_instance_output(output):
            return {"instances": {}}

        instances: dict[str, InstanceEntry] = {}
        for name, protocol, lines in _split_instance_blocks(output):
            header_lines, port_blocks = _split_port_blocks(lines)
            instance = _parse_instance_header(name, protocol, header_lines)

            ports: dict[str, PortEntry] = {}
            for block in port_blocks:
                entry = _parse_port_block(block)
                if entry is not None:
                    ports[entry["name"]] = entry
            instance["ports"] = ports

            instances[name] = cast(InstanceEntry, instance)

        return {"instances": instances}
