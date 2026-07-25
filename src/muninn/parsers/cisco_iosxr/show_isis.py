"""Parser for 'show isis' command on Cisco IOS-XR."""

import re
from dataclasses import dataclass, field
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class IsisTopologyLevel(TypedDict):
    """Schema for a topology level entry (Level-1 or Level-2)."""

    metric_style_generate: NotRequired[str]
    metric_style_accept: NotRequired[str]
    metric: int
    te_enabled: NotRequired[bool]


class IsisTopology(TypedDict):
    """Schema for a topology (e.g., IPv4 Unicast) within an IS-IS instance."""

    rib_connected: bool
    levels: dict[str, IsisTopologyLevel]
    redistributed_protocols: list[str]
    distance: int
    advertise_passive_only: bool


class IsisSrMpls(TypedDict):
    """Schema for SR-MPLS configuration."""

    srlb_start: int
    srlb_end: int
    srgb_start: int
    srgb_end: int


class IsisSrv6Locator(TypedDict):
    """Schema for an SRv6 locator."""

    status: str


class IsisSrv6(TypedDict):
    """Schema for SRv6 configuration."""

    locators: dict[str, IsisSrv6Locator]


class IsisInterface(TypedDict):
    """Schema for an IS-IS interface entry."""

    running_state: str
    config_state: str


class IsisInstance(TypedDict):
    """Schema for a single IS-IS instance."""

    instance_id: str
    system_id: str
    hostname: NotRequired[str]
    is_levels: str
    manual_area_addresses: list[str]
    routing_area_addresses: list[str]
    multi_instance_id: int
    job_id: int
    pid: int
    respawn_count: int
    started: str
    null0_ready: str
    lsp_mtu: int
    lsp_full_level1: bool
    lsp_full_level2: bool
    non_stop_forwarding: str
    most_recent_startup_mode: str
    te_connection_status: str
    xtc_connection_status: str
    overload_bit: str
    maximum_metric: str
    topologies: dict[str, IsisTopology]
    sr_mpls: NotRequired[IsisSrMpls]
    srv6: NotRequired[IsisSrv6]
    interfaces: dict[str, IsisInterface]


class ShowIsisResult(TypedDict):
    """Schema for 'show isis' parsed output."""

    instances: dict[str, IsisInstance]


# Patterns
_INSTANCE_PATTERN = re.compile(r"^IS-IS\s+Router:\s+(?P<instance>\S+)\s*$")
_SYSTEM_ID_PATTERN = re.compile(r"^\s+System\s+Id:\s+(?P<val>\S+)\s*$")
_HOSTNAME_PATTERN = re.compile(r"^\s+Hostname:\s+(?P<val>\S+)\s*$")
_IS_LEVELS_PATTERN = re.compile(r"^\s+IS\s+Levels:\s+(?P<val>.+?)\s*$")
_MULTI_INSTANCE_PATTERN = re.compile(r"^\s+Multi-Instance\s+Id:\s+(?P<val>\d+)\s*$")
_JOB_ID_PATTERN = re.compile(r"^\s+Job\s+Id:\s+(?P<val>\d+)\s*$")
_PID_PATTERN = re.compile(r"^\s+PID:\s+(?P<val>\d+)\s*$")
_RESPAWN_PATTERN = re.compile(r"^\s+Respawn\s+count:\s+(?P<val>\d+)\s*$")
_STARTED_PATTERN = re.compile(r"^\s+Started:\s+(?P<val>.+?)\s*$")
_NULL0_PATTERN = re.compile(r"^\s+Null0\s+ready:\s+(?P<val>.+?)\s*$")
_LSP_MTU_PATTERN = re.compile(r"^\s+LSP\s+MTU:\s+(?P<val>\d+)\s*$")
_LSP_FULL_PATTERN = re.compile(
    r"^\s+LSP\s+Full:\s+level-1:\s+(?P<l1>Yes|No),\s+level-2:\s+(?P<l2>Yes|No)\s*$"
)
_NSF_PATTERN = re.compile(r"^\s+Non-stop\s+forwarding:\s+(?P<val>.+?)\s*$")
_STARTUP_MODE_PATTERN = re.compile(
    r"^\s+Most\s+recent\s+startup\s+mode:\s+(?P<val>.+?)\s*$"
)
_TE_CONNECTION_PATTERN = re.compile(r"^\s+TE\s+connection\s+status:\s+(?P<val>\S+)\s*$")
_XTC_CONNECTION_PATTERN = re.compile(
    r"^\s+XTC\s+connection\s+status:\s+(?P<val>\S+)\s*$"
)
_OVERLOAD_PATTERN = re.compile(r"^\s+Overload\s+Bit:\s+(?P<val>.+?)\s*$")
_MAX_METRIC_PATTERN = re.compile(r"^\s+Maximum\s+Metric:\s+(?P<val>.+?)\s*$")
_TOPOLOGY_HEADER_PATTERN = re.compile(r"^\s+(?P<name>IPv[46]\s+\w+)\s*$")
_RIB_CONNECTED_PATTERN = re.compile(r"^\s+Rib\s+connected\s*$")
_LEVEL_HEADER_PATTERN = re.compile(r"^\s+Level-(?P<level>[12])\s*$")
_METRIC_STYLE_PATTERN = re.compile(
    r"^\s+Metric\s+style\s+\(generate/accept\):\s+"
    r"(?P<generate>\S+)/(?P<accept>\S+)\s*$"
)
_METRIC_PATTERN = re.compile(r"^\s+Metric:\s+(?P<metric>\d+)\s*$")
_TE_ENABLED_PATTERN = re.compile(r"^\s+TE\s+Enabled\s*$")
_NO_REDISTRIBUTED_PATTERN = re.compile(r"^\s+No\s+protocols\s+redistributed\s*$")
_REDISTRIBUTED_PATTERN = re.compile(r"^\s+(?P<protocol>\S+)\s+redistributed\s*$")
_DISTANCE_PATTERN = re.compile(r"^\s+Distance:\s+(?P<distance>\d+)\s*$")
_ADVERTISE_PASSIVE_PATTERN = re.compile(
    r"^\s+Advertise\s+Passive\s+Interface\s+Prefixes\s+Only:\s+"
    r"(?P<val>Yes|No)\s*$"
)
_SRLB_PATTERN = re.compile(
    r"^\s+SRLB\s+allocated:\s+(?P<start>\d+)\s+-\s+(?P<end>\d+)\s*$"
)
_SRGB_PATTERN = re.compile(
    r"^\s+SRGB\s+allocated:\s+(?P<start>\d+)\s+-\s+(?P<end>\d+)\s*$"
)
_SRV6_LOCATOR_PATTERN = re.compile(r"^\s+(?P<name>\S+)\s+\((?P<status>[^)]+)\)\s*$")
_INTERFACE_PATTERN = re.compile(
    r"^\s+(?P<name>\S+)\s+is\s+(?P<running_state>running\s+\w+|disabled)"
    r"\s+\((?P<config_state>[^)]+)\)\s*$"
)
_AREA_ADDRESS_PATTERN = re.compile(r"^\s+[\d.]+$")
_INTERFACES_HEADER_PATTERN = re.compile(
    r"^\s+Interfaces\s+supported\s+by\s+IS-IS\s+\S+:\s*$"
)

# Dispatch table: (pattern, key, converter) for simple string/int fields.
# converter: "str" stores as string, "int" converts to integer.
_STR_FIELD_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_SYSTEM_ID_PATTERN, "system_id"),
    (_HOSTNAME_PATTERN, "hostname"),
    (_IS_LEVELS_PATTERN, "is_levels"),
    (_STARTED_PATTERN, "started"),
    (_NULL0_PATTERN, "null0_ready"),
    (_NSF_PATTERN, "non_stop_forwarding"),
    (_STARTUP_MODE_PATTERN, "most_recent_startup_mode"),
    (_TE_CONNECTION_PATTERN, "te_connection_status"),
    (_XTC_CONNECTION_PATTERN, "xtc_connection_status"),
    (_OVERLOAD_PATTERN, "overload_bit"),
    (_MAX_METRIC_PATTERN, "maximum_metric"),
]

_INT_FIELD_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_MULTI_INSTANCE_PATTERN, "multi_instance_id"),
    (_JOB_ID_PATTERN, "job_id"),
    (_PID_PATTERN, "pid"),
    (_RESPAWN_PATTERN, "respawn_count"),
    (_LSP_MTU_PATTERN, "lsp_mtu"),
]


@dataclass
class _ParseState:
    """Mutable parse state for the show isis parser."""

    instances: dict[str, IsisInstance] = field(default_factory=dict)
    current: IsisInstance | None = None
    section: str = ""
    current_topology_name: str | None = None
    current_topology: IsisTopology | None = None
    current_level: str | None = None
    current_level_entry: IsisTopologyLevel | None = None
    in_sr_mpls: bool = False
    in_srv6: bool = False
    in_srv6_locators: bool = False
    in_interfaces: bool = False
    in_manual_area: bool = False
    in_routing_area: bool = False
    sr_mpls_data: dict[str, int] = field(default_factory=dict)


@register(OS.CISCO_IOSXR, "show isis")
class ShowIsisParser(BaseParser["ShowIsisResult"]):
    """Parser for 'show isis' command on IOS-XR.

    Parses IS-IS instance overview information including system ID,
    process state, topologies, segment routing, and interface list.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ISIS,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> "ShowIsisResult":
        """Parse 'show isis' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed IS-IS instance data.

        Raises:
            ValueError: If no IS-IS instances found in output.
        """
        state = _ParseState()

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            cls._process_line(line, stripped, state)

        cls._save_pending_topology(state)
        cls._save_pending_sr_mpls(state)

        if not state.instances:
            msg = "No IS-IS instances found in output"
            raise ValueError(msg)

        return ShowIsisResult(instances=state.instances)

    @classmethod
    def _process_line(cls, line: str, stripped: str, state: _ParseState) -> None:
        """Route a single line to the appropriate handler."""
        m = _INSTANCE_PATTERN.match(stripped)
        if m:
            cls._handle_new_instance(m, state)
            return

        if state.current is None:
            return

        if cls._try_section_handlers(line, stripped, state):
            return

        cls._handle_instance_field(line, stripped, state)

    @classmethod
    def _try_section_handlers(
        cls, line: str, stripped: str, state: _ParseState
    ) -> bool:
        """Dispatch to active section handlers. Returns True if consumed."""
        if (state.in_manual_area or state.in_routing_area) and cls._handle_area_address(
            line, stripped, state
        ):
            return True

        if state.section == "topologies" and cls._handle_topology_section(
            line, stripped, state
        ):
            return True

        if state.in_sr_mpls and cls._handle_sr_mpls_line(line, state):
            return True

        if state.in_srv6 and cls._handle_srv6_line(line, stripped, state):
            return True

        return state.in_interfaces and cls._handle_interface_line(line, state)

    @classmethod
    def _handle_new_instance(cls, m: re.Match[str], state: _ParseState) -> None:
        """Handle IS-IS Router header, starting a new instance."""
        cls._save_pending_topology(state)
        cls._save_pending_sr_mpls(state)

        instance_id = m.group("instance")
        state.current = IsisInstance(
            instance_id=instance_id,
            system_id="",
            is_levels="",
            manual_area_addresses=[],
            routing_area_addresses=[],
            multi_instance_id=0,
            job_id=0,
            pid=0,
            respawn_count=0,
            started="",
            null0_ready="",
            lsp_mtu=0,
            lsp_full_level1=False,
            lsp_full_level2=False,
            non_stop_forwarding="",
            most_recent_startup_mode="",
            te_connection_status="",
            xtc_connection_status="",
            overload_bit="",
            maximum_metric="",
            topologies={},
            interfaces={},
        )
        state.instances[instance_id] = state.current
        cls._reset_section_flags(state)

    @classmethod
    def _reset_section_flags(cls, state: _ParseState) -> None:
        """Reset all section tracking flags."""
        state.section = ""
        state.current_topology_name = None
        state.current_topology = None
        state.current_level = None
        state.current_level_entry = None
        state.in_sr_mpls = False
        state.in_srv6 = False
        state.in_srv6_locators = False
        state.in_interfaces = False
        state.in_manual_area = False
        state.in_routing_area = False
        state.sr_mpls_data = {}

    @classmethod
    def _handle_area_address(cls, line: str, stripped: str, state: _ParseState) -> bool:
        """Handle area address collection. Returns True if line consumed."""
        if _AREA_ADDRESS_PATTERN.match(line):
            if state.in_manual_area:
                state.current["manual_area_addresses"].append(stripped)  # type: ignore[index]
            elif state.in_routing_area:
                state.current["routing_area_addresses"].append(stripped)  # type: ignore[index]
            return True
        state.in_manual_area = False
        state.in_routing_area = False
        return False

    @classmethod
    def _handle_topology_section(
        cls, line: str, stripped: str, state: _ParseState
    ) -> bool:
        """Handle lines in the topologies section. Returns True if consumed."""
        # New topology header
        m = _TOPOLOGY_HEADER_PATTERN.match(line)
        if m and not _RIB_CONNECTED_PATTERN.match(line):
            cls._start_new_topology(m, state)
            return True

        if state.current_topology is None:
            return False

        return cls._handle_topology_content(line, state)

    @classmethod
    def _start_new_topology(cls, m: re.Match[str], state: _ParseState) -> None:
        """Start a new topology, saving any pending one."""
        cls._save_pending_topology(state)
        state.current_topology_name = m.group("name")
        state.current_topology = IsisTopology(
            rib_connected=False,
            levels={},
            redistributed_protocols=[],
            distance=0,
            advertise_passive_only=False,
        )
        state.current_level = None
        state.current_level_entry = None

    @classmethod
    def _handle_topology_content(cls, line: str, state: _ParseState) -> bool:
        """Handle content within an active topology. Returns True if consumed."""
        topo = state.current_topology
        assert topo is not None  # noqa: S101

        if _RIB_CONNECTED_PATTERN.match(line):
            topo["rib_connected"] = True
            return True

        m = _LEVEL_HEADER_PATTERN.match(line)
        if m:
            state.current_level = f"Level-{m.group('level')}"
            state.current_level_entry = IsisTopologyLevel(metric=0)
            topo["levels"][state.current_level] = state.current_level_entry
            return True

        if state.current_level_entry is not None:
            if cls._handle_level_content(line, state):
                return True

        if _NO_REDISTRIBUTED_PATTERN.match(line):
            return True

        m = _REDISTRIBUTED_PATTERN.match(line)
        if m:
            topo["redistributed_protocols"].append(m.group("protocol"))
            return True

        m = _DISTANCE_PATTERN.match(line)
        if m:
            topo["distance"] = int(m.group("distance"))
            return True

        m = _ADVERTISE_PASSIVE_PATTERN.match(line)
        if m:
            topo["advertise_passive_only"] = m.group("val") == "Yes"
            return True

        return False

    @classmethod
    def _handle_level_content(cls, line: str, state: _ParseState) -> bool:
        """Handle metric style/metric/TE within a level. Returns True if consumed."""
        entry = state.current_level_entry
        assert entry is not None  # noqa: S101

        m = _METRIC_STYLE_PATTERN.match(line)
        if m:
            entry["metric_style_generate"] = m.group("generate")
            entry["metric_style_accept"] = m.group("accept")
            return True

        m = _METRIC_PATTERN.match(line)
        if m:
            entry["metric"] = int(m.group("metric"))
            return True

        if _TE_ENABLED_PATTERN.match(line):
            entry["te_enabled"] = True
            return True

        return False

    @classmethod
    def _handle_sr_mpls_line(cls, line: str, state: _ParseState) -> bool:
        """Handle SR-MPLS section lines. Returns True if consumed."""
        m = _SRLB_PATTERN.match(line)
        if m:
            state.sr_mpls_data["srlb_start"] = int(m.group("start"))
            state.sr_mpls_data["srlb_end"] = int(m.group("end"))
            return True
        m = _SRGB_PATTERN.match(line)
        if m:
            state.sr_mpls_data["srgb_start"] = int(m.group("start"))
            state.sr_mpls_data["srgb_end"] = int(m.group("end"))
            return True
        return False

    @classmethod
    def _handle_srv6_line(cls, line: str, stripped: str, state: _ParseState) -> bool:
        """Handle SRv6 section lines. Returns True if consumed."""
        if stripped == "Configured locators:":
            state.in_srv6_locators = True
            if "srv6" not in state.current:  # type: ignore[operator]
                state.current["srv6"] = IsisSrv6(locators={})  # type: ignore[index]
            return True
        if state.in_srv6_locators:
            m = _SRV6_LOCATOR_PATTERN.match(line)
            if m:
                name = m.group("name")
                state.current["srv6"]["locators"][name] = IsisSrv6Locator(  # type: ignore[index]
                    status=m.group("status")
                )
                return True
        return False

    @classmethod
    def _handle_interface_line(cls, line: str, state: _ParseState) -> bool:
        """Handle interface section lines. Returns True if consumed."""
        m = _INTERFACE_PATTERN.match(line)
        if m:
            name = canonical_interface_name(m.group("name"), os=OS.CISCO_IOSXR)
            state.current["interfaces"][name] = IsisInterface(  # type: ignore[index]
                running_state=m.group("running_state"),
                config_state=m.group("config_state"),
            )
            return True
        return False

    @classmethod
    def _handle_instance_field(
        cls, line: str, stripped: str, state: _ParseState
    ) -> None:
        """Handle top-level instance fields and section headers."""
        current = state.current
        assert current is not None  # noqa: S101

        if cls._handle_section_headers(line, stripped, state):
            return

        cls._match_simple_fields(line, current)

    @classmethod
    def _handle_section_headers(
        cls, line: str, stripped: str, state: _ParseState
    ) -> bool:
        """Handle section header transitions. Returns True if consumed."""
        if stripped == "Manual area address(es):":
            state.in_manual_area = True
            state.in_routing_area = False
            return True

        if stripped == "Routing for area address(es):":
            state.in_routing_area = True
            state.in_manual_area = False
            return True

        if stripped == "Topologies supported by IS-IS:":
            state.section = "topologies"
            state.in_interfaces = False
            state.in_sr_mpls = False
            state.in_srv6 = False
            return True

        if stripped == "SR-MPLS:":
            cls._save_pending_topology(state)
            state.section = ""
            state.in_sr_mpls = True
            state.in_srv6 = False
            state.in_interfaces = False
            return True

        if stripped == "SRv6:":
            cls._save_pending_sr_mpls(state)
            state.in_sr_mpls = False
            state.in_srv6 = True
            state.in_interfaces = False
            return True

        if _INTERFACES_HEADER_PATTERN.match(line):
            cls._save_pending_sr_mpls(state)
            state.in_interfaces = True
            state.in_sr_mpls = False
            state.in_srv6 = False
            state.section = ""
            return True

        return False

    @classmethod
    def _match_simple_fields(cls, line: str, current: IsisInstance) -> None:
        """Match simple key-value instance fields using dispatch tables."""
        for pattern, key in _STR_FIELD_PATTERNS:
            m = pattern.match(line)
            if m:
                current[key] = m.group("val")  # type: ignore[literal-required]
                return

        for pattern, key in _INT_FIELD_PATTERNS:
            m = pattern.match(line)
            if m:
                current[key] = int(m.group("val"))  # type: ignore[literal-required]
                return

        m = _LSP_FULL_PATTERN.match(line)
        if m:
            current["lsp_full_level1"] = m.group("l1") == "Yes"
            current["lsp_full_level2"] = m.group("l2") == "Yes"

    @classmethod
    def _save_pending_topology(cls, state: _ParseState) -> None:
        """Save any pending topology to the current instance."""
        if (
            state.current is not None
            and state.current_topology_name
            and state.current_topology
        ):
            state.current["topologies"][state.current_topology_name] = (
                state.current_topology
            )
            state.current_topology_name = None
            state.current_topology = None

    @classmethod
    def _save_pending_sr_mpls(cls, state: _ParseState) -> None:
        """Save any pending SR-MPLS data to the current instance."""
        if (
            state.current is not None
            and state.in_sr_mpls
            and state.sr_mpls_data
            and "sr_mpls" not in state.current
        ):
            state.current["sr_mpls"] = IsisSrMpls(
                srlb_start=state.sr_mpls_data.get("srlb_start", 0),
                srlb_end=state.sr_mpls_data.get("srlb_end", 0),
                srgb_start=state.sr_mpls_data.get("srgb_start", 0),
                srgb_end=state.sr_mpls_data.get("srgb_end", 0),
            )
            state.in_sr_mpls = False
