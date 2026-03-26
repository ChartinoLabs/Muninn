"""Parser for 'show policy-map control-plane' command on IOS-XE."""

import re
from dataclasses import dataclass, field
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class PoliceCounters(TypedDict):
    """Schema for police conformed/exceeded/violated counters."""

    packets: int
    bytes: int
    actions: dict[str, bool]
    bps: int


class PoliceEntry(TypedDict):
    """Schema for a police configuration and counters."""

    cir_bps: NotRequired[int]
    cir_bc_bytes: NotRequired[int]
    cir_be_bytes: NotRequired[int]
    police_bps: NotRequired[int]
    police_limit: NotRequired[int]
    extended_limit: NotRequired[int]
    conformed: NotRequired[PoliceCounters]
    exceeded: NotRequired[PoliceCounters]
    violated: NotRequired[PoliceCounters]


class RateEntry(TypedDict):
    """Schema for rate information."""

    interval: int
    offered_rate_bps: int
    drop_rate_bps: int


class QosSetValue(TypedDict):
    """Schema for a QoS set marker value."""

    marker_statistics: str


class ClassMapEntry(TypedDict):
    """Schema for a single class-map entry."""

    match_evaluation: str
    packets: int
    bytes: int
    rate: RateEntry
    match: list[str]
    police: NotRequired[PoliceEntry]
    qos_set: NotRequired[dict[str, dict[str, QosSetValue]]]


class PolicyMapEntry(TypedDict):
    """Schema for a single policy-map entry."""

    class_map: dict[str, ClassMapEntry]


class ShowPolicyMapControlPlaneResult(TypedDict):
    """Schema for 'show policy-map control-plane' parsed output."""

    policy_maps: dict[str, PolicyMapEntry]


# --- Regex patterns ---

_SERVICE_POLICY = re.compile(r"^\s*Service-policy\s+input:\s*(?P<policy_name>\S+)")

_CLASS_MAP = re.compile(
    r"^\s*Class-map:\s*(?P<name>\S+)\s+\((?P<evaluation>match-\w+)\)"
)

_PACKETS_BYTES = re.compile(
    r"^\s*(?P<packets>\d+)\s+packets?,\s*(?P<bytes>\d+)\s+bytes?"
)

_RATE = re.compile(
    r"^\s*(?P<interval>\d+)\s+minute\s+offered\s+rate\s+"
    r"(?P<offered>\d+)\s+bps,\s+drop\s+rate\s+(?P<drop>\d+)\s+bps"
)

_MATCH = re.compile(r"^\s*Match:\s*(?P<criteria>.+?)\s*$")

# police: cir 8000 bps, bc 1500 bytes
# police:  cir 64000 bps, bc 8000 bytes
_POLICE_CIR = re.compile(
    r"^\s*(?:police:)?\s*cir\s+(?P<cir>\d+)\s+bps,\s+"
    r"(?P<burst_type>bc|be)\s+(?P<burst>\d+)\s+bytes"
)

# police: 8000 bps, 1500 limit, 1500 extended limit
_POLICE_LEGACY = re.compile(
    r"^\s*(?P<bps>\d+)\s+bps,\s+(?P<limit>\d+)\s+limit,\s+"
    r"(?P<extended>\d+)\s+extended\s+limit"
)

# conformed 15 packets, 6210 bytes; action:transmit
# conformed 0 packets, 0 bytes; actions:
_COUNTER_LINE = re.compile(
    r"^\s*(?P<type>conformed|exceeded|violated)\s+"
    r"(?P<packets>\d+)\s+packets?,\s*(?P<bytes>\d+)\s+bytes;\s*"
    r"(?:actions?:\s*(?P<action>\S+)?)?"
)

# Action on its own line (transmit, drop)
_ACTION_LINE = re.compile(r"^\s*(?P<action>transmit|drop)\s*$")

# conformed 0000 bps, exceeded 0000 bps
# conformed 2000 bps, exceeded 15000 bps
_BPS_LINE = re.compile(
    r"^\s*conformed\s+(?P<conformed>\d+)\s+bps,\s+"
    r"exceed(?:ed)?\s+(?P<exceeded>\d+)\s+bps"
    r"(?:,\s+violat(?:ed?)?\s+(?P<violated>\d+)\s+bps)?"
)

# QoS Set / ip precedence 6
_QOS_SET_LINE = re.compile(r"^\s*QoS\s+Set\s*$")
_QOS_SET_VALUE = re.compile(
    r"^\s*(?P<field>ip\s+precedence|ip\s+dscp|dscp)\s+(?P<value>\S+)"
)
_MARKER_STATS = re.compile(r"^\s*Marker\s+statistics:\s+(?P<status>\S+)")

_SECONDS_PER_MINUTE = 60


@dataclass
class _ParserState:
    """Mutable state for the line-by-line parser."""

    policy_maps: dict[str, PolicyMapEntry] = field(default_factory=dict)
    current_policy: str | None = None
    current_class: ClassMapEntry | None = None
    current_police: PoliceEntry | None = None
    last_counter_type: str | None = None
    in_qos_set: bool = False
    last_qos_field: str | None = None

    def reset_for_policy(self, name: str) -> None:
        """Reset state when entering a new service-policy."""
        self.current_policy = name
        if name not in self.policy_maps:
            self.policy_maps[name] = PolicyMapEntry(class_map={})
        self.current_class = None
        self.current_police = None
        self.in_qos_set = False
        self.last_counter_type = None

    def reset_for_class(self, name: str, evaluation: str) -> None:
        """Reset state when entering a new class-map."""
        self.in_qos_set = False
        self.current_police = None
        self.last_counter_type = None
        self.current_class = ClassMapEntry(
            match_evaluation=evaluation,
            packets=0,
            bytes=0,
            rate=RateEntry(interval=0, offered_rate_bps=0, drop_rate_bps=0),
            match=[],
        )
        if self.current_policy is not None:
            self.policy_maps[self.current_policy]["class_map"][name] = (
                self.current_class
            )

    def start_police(self, police: PoliceEntry) -> None:
        """Attach a new police entry to the current class-map."""
        self.in_qos_set = False
        self.current_police = police
        self.last_counter_type = None
        if self.current_class is not None:
            self.current_class["police"] = police


def _handle_class_map_fields(state: _ParserState, line: str) -> bool:
    """Process packets/bytes, rate, and match lines for the current class-map."""
    cls_entry = state.current_class
    if cls_entry is None:
        return False

    if m := _PACKETS_BYTES.match(line):
        cls_entry["packets"] = int(m.group("packets"))
        cls_entry["bytes"] = int(m.group("bytes"))
        return True

    if m := _RATE.match(line):
        cls_entry["rate"] = RateEntry(
            interval=int(m.group("interval")) * _SECONDS_PER_MINUTE,
            offered_rate_bps=int(m.group("offered")),
            drop_rate_bps=int(m.group("drop")),
        )
        return True

    if m := _MATCH.match(line):
        cls_entry["match"].append(m.group("criteria"))
        return True

    return False


def _handle_qos_set(state: _ParserState, line: str) -> bool:
    """Process QoS Set header, value, and marker statistics lines."""
    if _QOS_SET_LINE.match(line):
        state.in_qos_set = True
        state.current_police = None
        state.last_qos_field = None
        return True

    if not state.in_qos_set or state.current_class is None:
        return False

    if m := _QOS_SET_VALUE.match(line):
        if "qos_set" not in state.current_class:
            state.current_class["qos_set"] = {}
        state.last_qos_field = m.group("field")
        qos_value = m.group("value")
        state.current_class["qos_set"].setdefault(state.last_qos_field, {})
        state.current_class["qos_set"][state.last_qos_field][qos_value] = QosSetValue(
            marker_statistics=""
        )
        return True

    if state.last_qos_field and (m := _MARKER_STATS.match(line)):
        qos_field_dict = state.current_class.get("qos_set", {}).get(
            state.last_qos_field, {}
        )
        for val_entry in qos_field_dict.values():
            val_entry["marker_statistics"] = m.group("status")
        return True

    return False


def _handle_police_config(state: _ParserState, line: str) -> bool:
    """Process police header and configuration lines (CIR or legacy format)."""
    if m := _POLICE_CIR.match(line):
        police = PoliceEntry()
        police["cir_bps"] = int(m.group("cir"))
        burst_type = m.group("burst_type")
        burst_key = "cir_bc_bytes" if burst_type == "bc" else "cir_be_bytes"
        police[burst_key] = int(m.group("burst"))
        state.start_police(police)
        return True

    if line.strip() == "police:":
        state.start_police(PoliceEntry())
        return True

    if state.current_police is not None and (m := _POLICE_LEGACY.match(line)):
        state.current_police["police_bps"] = int(m.group("bps"))
        state.current_police["police_limit"] = int(m.group("limit"))
        state.current_police["extended_limit"] = int(m.group("extended"))
        return True

    return False


def _handle_police_counters(state: _ParserState, line: str) -> bool:
    """Process police counter, action, and BPS summary lines."""
    if state.current_police is None:
        return False

    if m := _COUNTER_LINE.match(line):
        counter_type = m.group("type")
        state.last_counter_type = counter_type
        action = m.group("action")
        actions: dict[str, bool] = {}
        if action:
            actions[action] = True
        counters = PoliceCounters(
            packets=int(m.group("packets")),
            bytes=int(m.group("bytes")),
            actions=actions,
            bps=0,
        )
        state.current_police[counter_type] = counters
        return True

    if state.last_counter_type is not None and (m := _ACTION_LINE.match(line)):
        counter_entry = state.current_police.get(state.last_counter_type)
        if counter_entry is not None:
            counter_entry["actions"][m.group("action")] = True
        return True

    if m := _BPS_LINE.match(line):
        _apply_bps_summary(state.current_police, m)
        state.last_counter_type = None
        return True

    return False


def _apply_bps_summary(police: PoliceEntry, m: re.Match[str]) -> None:
    """Apply BPS summary values to police counter entries."""
    conformed_entry = police.get("conformed")
    if conformed_entry is not None:
        conformed_entry["bps"] = int(m.group("conformed"))
    exceeded_entry = police.get("exceeded")
    if exceeded_entry is not None:
        exceeded_entry["bps"] = int(m.group("exceeded"))
    violated_bps = m.group("violated")
    if violated_bps is not None:
        violated_entry = police.get("violated")
        if violated_entry is not None:
            violated_entry["bps"] = int(violated_bps)


def _process_line(state: _ParserState, line: str) -> None:
    """Dispatch a single non-empty line to the appropriate handler."""
    if m := _SERVICE_POLICY.match(line):
        state.reset_for_policy(m.group("policy_name"))
        return

    if state.current_policy is None:
        return

    if m := _CLASS_MAP.match(line):
        state.reset_for_class(m.group("name"), m.group("evaluation"))
        return

    if state.current_class is None:
        return

    if _handle_class_map_fields(state, line):
        return

    if _handle_qos_set(state, line):
        return

    if _handle_police_config(state, line):
        return

    _handle_police_counters(state, line)


@register(OS.CISCO_IOSXE, "show policy-map control-plane")
class ShowPolicyMapControlPlaneParser(
    BaseParser[ShowPolicyMapControlPlaneResult],
):
    """Parser for 'show policy-map control-plane' command.

    Parses CoPP (Control Plane Policing) policy-map information including
    class-maps, match criteria, police rates, and QoS settings.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.QOS})

    @classmethod
    def parse(cls, output: str) -> ShowPolicyMapControlPlaneResult:
        """Parse 'show policy-map control-plane' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed policy-map data keyed by policy-map name,
            then by class-map name.

        Raises:
            ValueError: If no policy-map data found in output.
        """
        state = _ParserState()

        for line in output.splitlines():
            if not line.strip():
                continue
            _process_line(state, line)

        if not state.policy_maps:
            msg = "No policy-map data found in output"
            raise ValueError(msg)

        return ShowPolicyMapControlPlaneResult(policy_maps=state.policy_maps)
