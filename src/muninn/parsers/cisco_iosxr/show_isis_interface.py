"""Parser for 'show isis interface' command on Cisco IOS-XR."""

import re
from dataclasses import dataclass, field
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class IsisTopologyEntry(TypedDict):
    """Schema for a per-topology section within an IS-IS interface."""

    enabled: bool
    adjacency_formation: NotRequired[str]
    prefix_advertisement: NotRequired[str]
    metric_l1: NotRequired[int]
    metric_l2: NotRequired[int]
    weight_l1: NotRequired[int]
    weight_l2: NotRequired[int]
    ldp_sync_l1: NotRequired[str]
    ldp_sync_l2: NotRequired[str]
    frr_l1: NotRequired[str]
    frr_l2: NotRequired[str]


class IsisInterfaceEntry(TypedDict):
    """Schema for a single IS-IS interface entry."""

    state: str
    adjacency_formation: NotRequired[str]
    prefix_advertisement: NotRequired[str]
    circuit_type: NotRequired[str]
    circuit_type_configured: NotRequired[str]
    media_type: NotRequired[str]
    circuit_number: NotRequired[int]
    extended_circuit_number: NotRequired[int]
    bandwidth: NotRequired[int]
    ipv4_bfd: NotRequired[str]
    ipv6_bfd: NotRequired[str]
    bfd_min_interval: NotRequired[int]
    bfd_multiplier: NotRequired[int]
    level2_adjacency_count: NotRequired[int]
    level2_hello_interval: NotRequired[str]
    level2_hello_multiplier: NotRequired[int]
    level1_adjacency_count: NotRequired[int]
    level1_hello_interval: NotRequired[str]
    level1_hello_multiplier: NotRequired[int]
    clns_protocol_state: NotRequired[str]
    clns_mtu: NotRequired[int]
    clns_snpa: NotRequired[str]
    topologies: NotRequired[dict[str, IsisTopologyEntry]]


class ShowIsisInterfaceResult(TypedDict):
    """Schema for 'show isis interface' parsed output.

    Top-level keys are IS-IS instance IDs. Each instance maps interface
    names to their IS-IS interface details.
    """

    instances: dict[str, dict[str, IsisInterfaceEntry]]


# Instance header: "IS-IS <tag> Interfaces"
_INSTANCE_PATTERN = re.compile(r"^IS-IS\s+(?P<instance>\S+)\s+Interfaces\s*$")

# Interface header: "<InterfaceName>  Enabled|Disabled ..."
_INTERFACE_PATTERN = re.compile(
    r"^(?P<interface>\S+)\s+"
    r"(?P<state>Enabled|Disabled)"
    r"(?:\s+\((?P<reason>[^)]+)\))?\s*$"
)

# Topology header: "IPv4 Unicast Topology:" or "IPv6 Unicast Topology:"
_TOPOLOGY_PATTERN = re.compile(
    r"^\s+(?P<topology>IPv[46]\s+\w+)\s+Topology:\s+(?P<state>\S+)"
)

# Metric pattern: "Metric (L1/L2):         10/10"
_METRIC_PATTERN = re.compile(r"^\s+Metric\s+\(L1/L2\):\s+(?P<l1>\d+)/(?P<l2>\d+)")

# Weight pattern: "Weight (L1/L2):         0/0"
_WEIGHT_PATTERN = re.compile(r"^\s+Weight\s+\(L1/L2\):\s+(?P<l1>\d+)/(?P<l2>\d+)")

# LDP Sync pattern: "MPLS LDP Sync (L1/L2):  Disabled/Disabled"
_LDP_SYNC_PATTERN = re.compile(
    r"^\s+MPLS LDP Sync\s+\(L1/L2\):\s+(?P<l1>\S+)/(?P<l2>\S+)"
)

# FRR pattern
_FRR_PATTERN = re.compile(
    r"^\s+FRR\s+\(L1/L2\):\s+L1\s+(?P<l1>.+?)\s{2,}L2\s+(?P<l2>.+?)\s*$"
)

# Circuit type
_CIRCUIT_TYPE_PATTERN = re.compile(
    r"^\s+Circuit Type:\s+(?P<type>\S+)"
    r"(?:\s+\(Configured:\s+(?P<configured>\S+)\))?\s*$"
)

# Level header: "Level-2" or "Level-1"
_LEVEL_PATTERN = re.compile(r"^\s+Level-(?P<level>[12])\s*$")

# Adjacency Count
_ADJ_COUNT_PATTERN = re.compile(r"^\s+Adjacency Count:\s+(?P<count>\d+)\s*$")

# Hello Interval
_HELLO_INTERVAL_PATTERN = re.compile(
    r"^\s+Hello Interval:\s+(?P<interval>\d+\s*\S*)\s*$"
)

# Hello Multiplier
_HELLO_MULTIPLIER_PATTERN = re.compile(
    r"^\s+Hello Multiplier:\s+(?P<multiplier>\d+)\s*$"
)

# Two-space indent section boundary (not four-space indented)
_SECTION_BOUNDARY = re.compile(r"^  \S")
_DEEP_INDENT = re.compile(r"^    ")

# Default instance ID when no header is found.
_DEFAULT_INSTANCE = "default"


@dataclass
class _ParseState:
    """Mutable parse state passed between helper methods."""

    instances: dict[str, dict[str, IsisInterfaceEntry]] = field(default_factory=dict)
    current_instance: str | None = None
    current_interface: IsisInterfaceEntry | None = None
    topology_name: str | None = None
    topology: IsisTopologyEntry | None = None
    current_level: int | None = None
    in_clns_section: bool = False


@register(OS.CISCO_IOSXR, "show isis interface")
class ShowIsisInterfaceParser(BaseParser["ShowIsisInterfaceResult"]):
    """Parser for 'show isis interface' command on IOS-XR.

    Parses IS-IS interface configuration and state information.
    Interfaces are grouped by IS-IS instance, then keyed by interface name.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ISIS,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> "ShowIsisInterfaceResult":
        """Parse 'show isis interface' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface data grouped by IS-IS instance.

        Raises:
            ValueError: If no interfaces found in output.
        """
        state = _ParseState()

        for line in output.splitlines():
            if not line.strip():
                continue
            cls._process_line(line, state)

        # Save final topology if pending
        if state.current_interface is not None:
            cls._save_topology(state)

        if not state.instances:
            msg = "No IS-IS interfaces found in output"
            raise ValueError(msg)

        return ShowIsisInterfaceResult(instances=state.instances)

    @classmethod
    def _process_line(cls, line: str, state: _ParseState) -> None:
        """Route a single line to the appropriate sub-parser."""
        # Instance header
        instance_match = _INSTANCE_PATTERN.match(line.strip())
        if instance_match:
            cls._handle_instance_header(instance_match, state)
            return

        # Interface header (non-indented line)
        if not line.startswith(" "):
            cls._handle_interface_header(line, state)
            return

        if state.current_interface is None:
            return

        # Topology section content
        if state.topology is not None:
            if cls._handle_topology_line(line, state):
                return

        # Level section content
        if state.current_level is not None:
            if cls._handle_level_line(line, state):
                return

        # CLNS I/O section
        if cls._handle_clns_and_sections(line, state):
            return

        # Top-level interface fields
        cls._handle_interface_field(line, state)

    @classmethod
    def _handle_instance_header(cls, match: re.Match[str], state: _ParseState) -> None:
        """Process an IS-IS instance header line."""
        state.current_instance = match.group("instance")
        if state.current_instance not in state.instances:
            state.instances[state.current_instance] = {}
        state.current_interface = None
        state.topology_name = None
        state.topology = None
        state.current_level = None
        state.in_clns_section = False

    @classmethod
    def _handle_interface_header(cls, line: str, state: _ParseState) -> None:
        """Process an interface header line."""
        intf_match = _INTERFACE_PATTERN.match(line)
        if not intf_match:
            return

        if state.current_instance is None:
            state.current_instance = _DEFAULT_INSTANCE
            state.instances[state.current_instance] = {}

        cls._save_topology(state)

        iface = canonical_interface_name(
            intf_match.group("interface"), os=OS.CISCO_IOSXR
        )
        raw_state = intf_match.group("state")
        reason = intf_match.group("reason")

        state_str = f"{raw_state} ({reason})" if reason else raw_state

        state.current_interface = IsisInterfaceEntry(state=state_str)
        state.instances[state.current_instance][iface] = state.current_interface
        state.topology_name = None
        state.topology = None
        state.current_level = None
        state.in_clns_section = False

    @classmethod
    def _handle_topology_line(cls, line: str, state: _ParseState) -> bool:
        """Parse a line within a topology section. Returns True if consumed."""
        stripped = line.strip()
        topo = state.topology
        assert topo is not None  # noqa: S101  # nosec B101

        if stripped.startswith("Adjacency Formation:"):
            topo["adjacency_formation"] = stripped.split(":", 1)[1].strip()
            return True

        if stripped.startswith("Prefix Advertisement:"):
            topo["prefix_advertisement"] = stripped.split(":", 1)[1].strip()
            return True

        metric_match = _METRIC_PATTERN.match(line)
        if metric_match:
            topo["metric_l1"] = int(metric_match.group("l1"))
            topo["metric_l2"] = int(metric_match.group("l2"))
            return True

        weight_match = _WEIGHT_PATTERN.match(line)
        if weight_match:
            topo["weight_l1"] = int(weight_match.group("l1"))
            topo["weight_l2"] = int(weight_match.group("l2"))
            return True

        ldp_match = _LDP_SYNC_PATTERN.match(line)
        if ldp_match:
            topo["ldp_sync_l1"] = ldp_match.group("l1")
            topo["ldp_sync_l2"] = ldp_match.group("l2")
            return True

        frr_match = _FRR_PATTERN.match(line)
        if frr_match:
            topo["frr_l1"] = frr_match.group("l1")
            topo["frr_l2"] = frr_match.group("l2")
            return True

        # Section boundary exits topology
        if _SECTION_BOUNDARY.match(line) and not _DEEP_INDENT.match(line):
            cls._save_topology(state)
            state.topology_name = None
            state.topology = None
            return False  # Let caller process this line

        return True  # Still in topology, skip unrecognized lines

    @classmethod
    def _handle_level_line(cls, line: str, state: _ParseState) -> bool:
        """Parse a line within a Level section. Returns True if consumed."""
        intf = state.current_interface
        assert intf is not None  # noqa: S101  # nosec B101
        lvl = state.current_level
        assert lvl is not None  # noqa: S101  # nosec B101

        adj_match = _ADJ_COUNT_PATTERN.match(line)
        if adj_match:
            count = int(adj_match.group("count"))
            key = f"level{lvl}_adjacency_count"
            intf[key] = count  # type: ignore[literal-required]  # ty: ignore[invalid-key]
            return True

        hello_int_match = _HELLO_INTERVAL_PATTERN.match(line)
        if hello_int_match:
            interval = hello_int_match.group("interval").strip()
            key = f"level{lvl}_hello_interval"
            intf[key] = interval  # type: ignore[literal-required]  # ty: ignore[invalid-key]
            return True

        hello_mult_match = _HELLO_MULTIPLIER_PATTERN.match(line)
        if hello_mult_match:
            mult = int(hello_mult_match.group("multiplier"))
            key = f"level{lvl}_hello_multiplier"
            intf[key] = mult  # type: ignore[literal-required]  # ty: ignore[invalid-key]
            return True

        # Section boundary exits level
        if _SECTION_BOUNDARY.match(line) and not _DEEP_INDENT.match(line):
            state.current_level = None
            return False

        return True  # Still in level section

    @classmethod
    def _handle_clns_and_sections(cls, line: str, state: _ParseState) -> bool:
        """Handle CLNS I/O, Level, and topology entry. Returns True if consumed."""
        stripped = line.strip()
        intf = state.current_interface
        assert intf is not None  # noqa: S101  # nosec B101

        # Topology header
        topo_match = _TOPOLOGY_PATTERN.match(line)
        if topo_match:
            cls._save_topology(state)
            state.current_level = None
            state.in_clns_section = False
            topo_name = topo_match.group("topology")
            is_enabled = topo_match.group("state") == "Enabled"
            state.topology_name = topo_name
            state.topology = IsisTopologyEntry(enabled=is_enabled)
            return True

        # Level header
        level_match = _LEVEL_PATTERN.match(line)
        if level_match:
            state.current_level = int(level_match.group("level"))
            state.in_clns_section = False
            return True

        # CLNS I/O section header
        if stripped == "CLNS I/O":
            state.in_clns_section = True
            state.current_level = None
            return True

        # CLNS I/O content
        if state.in_clns_section:
            return cls._handle_clns_content(line, stripped, state)

        return False

    @classmethod
    def _handle_clns_content(cls, line: str, stripped: str, state: _ParseState) -> bool:
        """Parse CLNS I/O section content. Returns True if consumed."""
        intf = state.current_interface
        assert intf is not None  # noqa: S101  # nosec B101

        if stripped.startswith("Protocol State:"):
            intf["clns_protocol_state"] = stripped.split(":", 1)[1].strip()
            return True
        if stripped.startswith("MTU:"):
            intf["clns_mtu"] = int(stripped.split(":", 1)[1].strip())
            return True
        if stripped.startswith("SNPA:"):
            intf["clns_snpa"] = stripped.split(":", 1)[1].strip()
            return True

        # Section boundary exits CLNS
        if _SECTION_BOUNDARY.match(line) and not _DEEP_INDENT.match(line):
            state.in_clns_section = False
            return False

        return True  # Still in CLNS, skip unrecognized sub-lines

    # Mapping from field prefix to (key, converter).
    # str = store as-is; int = convert to integer.
    _STR_FIELDS: ClassVar[list[tuple[str, str]]] = [
        ("Adjacency Formation:", "adjacency_formation"),
        ("Prefix Advertisement:", "prefix_advertisement"),
        ("IPv4 BFD:", "ipv4_bfd"),
        ("IPv6 BFD:", "ipv6_bfd"),
        ("Media Type:", "media_type"),
    ]
    _INT_FIELDS: ClassVar[list[tuple[str, str]]] = [
        ("BFD Min Interval:", "bfd_min_interval"),
        ("BFD Multiplier:", "bfd_multiplier"),
        ("Bandwidth:", "bandwidth"),
        ("Circuit Number:", "circuit_number"),
        ("Extended Circuit Number:", "extended_circuit_number"),
    ]

    @classmethod
    def _handle_interface_field(cls, line: str, state: _ParseState) -> None:
        """Parse top-level interface fields."""
        stripped = line.strip()
        intf = state.current_interface
        assert intf is not None  # noqa: S101  # nosec B101

        for prefix, key in cls._STR_FIELDS:
            if stripped.startswith(prefix):
                intf[key] = stripped.split(":", 1)[1].strip()  # type: ignore[literal-required]  # ty: ignore[invalid-key]
                return

        for prefix, key in cls._INT_FIELDS:
            if stripped.startswith(prefix):
                intf[key] = int(stripped.split(":", 1)[1].strip())  # type: ignore[literal-required]  # ty: ignore[invalid-key]
                return

        ct_match = _CIRCUIT_TYPE_PATTERN.match(line)
        if ct_match:
            intf["circuit_type"] = ct_match.group("type")
            configured = ct_match.group("configured")
            if configured:
                intf["circuit_type_configured"] = configured

    @classmethod
    def _save_topology(cls, state: _ParseState) -> None:
        """Save a completed topology entry into the interface dict."""
        intf = state.current_interface
        topo_name = state.topology_name
        topo = state.topology
        if intf is None or topo_name is None or topo is None:
            return
        if "topologies" not in intf:
            intf["topologies"] = {}
        intf["topologies"][topo_name] = topo
