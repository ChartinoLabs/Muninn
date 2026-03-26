"""Parser for 'show policy-map' command on IOS."""

import re
from dataclasses import dataclass, field
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class PoliceEntry(TypedDict):
    """Schema for police action configuration."""

    cir_bps: int
    bc_bytes: NotRequired[int]
    be_bytes: NotRequired[int]
    conform_action: NotRequired[str]
    exceed_action: NotRequired[str]
    violate_action: NotRequired[str]
    conform_packets: NotRequired[int]
    conform_bytes: NotRequired[int]
    exceed_packets: NotRequired[int]
    exceed_bytes: NotRequired[int]
    violate_packets: NotRequired[int]
    violate_bytes: NotRequired[int]


class ShapeEntry(TypedDict):
    """Schema for shape action configuration."""

    type: str
    cir_bps: int
    bc_bits: NotRequired[int]
    be_bits: NotRequired[int]


class BandwidthEntry(TypedDict):
    """Schema for bandwidth allocation."""

    kbps: NotRequired[int]
    percent: NotRequired[int]


class QueueLimitEntry(TypedDict):
    """Schema for queue limit configuration."""

    packets: NotRequired[int]
    bytes: NotRequired[int]


class ClassEntry(TypedDict):
    """Schema for a single class within a policy-map."""

    match: NotRequired[list[str]]
    packets: NotRequired[int]
    bytes: NotRequired[int]
    rate_bps: NotRequired[int]
    offered_rate_bps: NotRequired[int]
    drop_rate_bps: NotRequired[int]
    police: NotRequired[PoliceEntry]
    shape: NotRequired[ShapeEntry]
    bandwidth: NotRequired[BandwidthEntry]
    queue_limit: NotRequired[QueueLimitEntry]
    service_policy: NotRequired[str]


class PolicyMapEntry(TypedDict):
    """Schema for a single policy-map."""

    classes: dict[str, ClassEntry]


class ShowPolicyMapResult(TypedDict):
    """Schema for 'show policy-map' parsed output."""

    policy_maps: dict[str, PolicyMapEntry]


# Regex patterns
_POLICY_MAP_HEADER = re.compile(r"^\s*Policy\s+Map\s+(?P<name>\S+)\s*$")
_CLASS_HEADER = re.compile(r"^\s*Class\s+(?P<name>\S+)\s*$")
_MATCH_LINE = re.compile(r"^\s*Match:\s+(?P<criteria>.+)\s*$")
_PACKETS_BYTES = re.compile(
    r"^\s*(?P<packets>\d+)\s+packets?,\s+(?P<bytes>\d+)\s+bytes?\s*$"
)
_RATE_BPS = re.compile(
    r"^\s*(?P<interval>\d+)\s+second\s+(?:offered\s+)?rate\s+(?P<rate>\d+)\s+bps\s*$"
)
_OFFERED_RATE = re.compile(
    r"^\s*(?:\d+)\s+second\s+offered\s+rate\s+(?P<rate>\d+)\s+bps\s*$"
)
_DROP_RATE = re.compile(r"^\s*(?:\d+)\s+second\s+drop\s+rate\s+(?P<rate>\d+)\s+bps\s*$")
_RATE_GENERAL = re.compile(r"^\s*\d+\s+second\s+rate\s+(?P<rate>\d+)\s+bps\s*$")
_POLICE_CIR = re.compile(
    r"^\s*police\s+(?:cir\s+)?(?P<cir>\d+)"
    r"(?:\s+bc\s+(?P<bc>\d+))?"
    r"(?:\s+be\s+(?P<be>\d+))?\s*$",
    re.IGNORECASE,
)
_POLICE_ACTION = re.compile(
    r"^\s*(?P<action_type>conform-action|exceed-action|violate-action)"
    r"\s+(?P<action>\S+)\s*$"
)
_POLICE_STATS = re.compile(
    r"^\s*(?P<type>conformed|exceeded|violated)\s+"
    r"(?P<packets>\d+)\s+packets?,\s+(?P<bytes>\d+)\s+bytes?\s*$"
)
_SHAPE_AVERAGE = re.compile(
    r"^\s*shape\s+(?P<type>average|peak)\s+(?P<cir>\d+)"
    r"(?:\s+(?P<bc>\d+))?"
    r"(?:\s+(?P<be>\d+))?\s*$",
    re.IGNORECASE,
)
_BANDWIDTH_KBPS = re.compile(r"^\s*bandwidth\s+(?P<kbps>\d+)\s*(?:\(kbps\))?\s*$")
_BANDWIDTH_PERCENT = re.compile(r"^\s*bandwidth\s+(?P<percent>\d+)\s*(?:%|percent)\s*$")
_QUEUE_LIMIT_PACKETS = re.compile(
    r"^\s*queue-limit\s+(?P<packets>\d+)\s*(?:packets?)?\s*$"
)
_QUEUE_LIMIT_BYTES = re.compile(r"^\s*queue-limit\s+(?P<bytes>\d+)\s+bytes?\s*$")
_SERVICE_POLICY = re.compile(r"^\s*service-policy\s+(?P<name>\S+)\s*$")


@dataclass
class _ClassState:
    """Mutable state for tracking the current class being parsed."""

    name: str | None = None
    entry: ClassEntry = field(default_factory=lambda: ClassEntry({}))
    match_clauses: list[str] = field(default_factory=list)
    in_police: bool = False
    police: PoliceEntry | None = None


@dataclass
class _ParseState:
    """Mutable parser state for policy-map parsing."""

    policy_maps: dict[str, PolicyMapEntry] = field(default_factory=dict)
    current_policy: str | None = None
    current_class: _ClassState = field(default_factory=_ClassState)

    def flush_class(self) -> None:
        """Save the current class into the current policy-map."""
        if self.current_policy is None or self.current_class.name is None:
            return

        entry = dict(self.current_class.entry)
        if self.current_class.match_clauses:
            entry["match"] = list(self.current_class.match_clauses)
        if self.current_class.police is not None:
            entry["police"] = self.current_class.police

        if self.current_policy not in self.policy_maps:
            self.policy_maps[self.current_policy] = PolicyMapEntry(classes={})

        self.policy_maps[self.current_policy]["classes"][self.current_class.name] = (
            ClassEntry(**entry)
        )

    def start_class(self, name: str) -> None:
        """Begin a new class, flushing any current one."""
        self.flush_class()
        self.current_class = _ClassState(name=name)

    def start_policy(self, name: str) -> None:
        """Begin a new policy-map, flushing any current class."""
        self.flush_class()
        self.current_policy = name
        self.current_class = _ClassState()


def _parse_police_line(line: str, state: _ParseState) -> bool:
    """Attempt to parse a police-related line. Returns True if handled."""
    cir_match = _POLICE_CIR.match(line)
    if cir_match:
        police: PoliceEntry = {"cir_bps": int(cir_match.group("cir"))}
        if cir_match.group("bc"):
            police["bc_bytes"] = int(cir_match.group("bc"))
        if cir_match.group("be"):
            police["be_bytes"] = int(cir_match.group("be"))
        state.current_class.police = police
        state.current_class.in_police = True
        return True

    if not state.current_class.in_police or state.current_class.police is None:
        return False

    action_match = _POLICE_ACTION.match(line)
    if action_match:
        action_type = action_match.group("action_type").replace("-", "_")
        state.current_class.police[action_type] = action_match.group("action")
        return True

    stats_match = _POLICE_STATS.match(line)
    if stats_match:
        stat_type = stats_match.group("type")
        prefix_map = {
            "conformed": "conform",
            "exceeded": "exceed",
            "violated": "violate",
        }
        prefix = prefix_map[stat_type]
        state.current_class.police[f"{prefix}_packets"] = int(  # type: ignore[literal-required]
            stats_match.group("packets")
        )
        state.current_class.police[f"{prefix}_bytes"] = int(  # type: ignore[literal-required]
            stats_match.group("bytes")
        )
        return True

    return False


def _parse_rate_line(line: str, entry: ClassEntry) -> bool:
    """Parse rate-related lines (packets/bytes, offered, drop, general rate).

    Returns True if the line was handled.
    """
    packets_m = _PACKETS_BYTES.match(line)
    if packets_m:
        entry["packets"] = int(packets_m.group("packets"))
        entry["bytes"] = int(packets_m.group("bytes"))
        return True

    offered_m = _OFFERED_RATE.match(line)
    if offered_m:
        entry["offered_rate_bps"] = int(offered_m.group("rate"))
        return True

    drop_m = _DROP_RATE.match(line)
    if drop_m:
        entry["drop_rate_bps"] = int(drop_m.group("rate"))
        return True

    rate_m = _RATE_GENERAL.match(line)
    if rate_m:
        entry["rate_bps"] = int(rate_m.group("rate"))
        return True

    return False


def _parse_qos_action_line(line: str, entry: ClassEntry) -> bool:
    """Parse QoS action lines (shape, bandwidth, queue-limit, service-policy).

    Returns True if the line was handled.
    """
    shape_m = _SHAPE_AVERAGE.match(line)
    if shape_m:
        shape: ShapeEntry = {
            "type": shape_m.group("type").lower(),
            "cir_bps": int(shape_m.group("cir")),
        }
        if shape_m.group("bc"):
            shape["bc_bits"] = int(shape_m.group("bc"))
        if shape_m.group("be"):
            shape["be_bits"] = int(shape_m.group("be"))
        entry["shape"] = shape
        return True

    bw_kbps_m = _BANDWIDTH_KBPS.match(line)
    if bw_kbps_m:
        entry["bandwidth"] = BandwidthEntry(kbps=int(bw_kbps_m.group("kbps")))
        return True

    bw_pct_m = _BANDWIDTH_PERCENT.match(line)
    if bw_pct_m:
        entry["bandwidth"] = BandwidthEntry(percent=int(bw_pct_m.group("percent")))
        return True

    ql_packets_m = _QUEUE_LIMIT_PACKETS.match(line)
    if ql_packets_m:
        entry["queue_limit"] = QueueLimitEntry(
            packets=int(ql_packets_m.group("packets"))
        )
        return True

    ql_bytes_m = _QUEUE_LIMIT_BYTES.match(line)
    if ql_bytes_m:
        entry["queue_limit"] = QueueLimitEntry(bytes=int(ql_bytes_m.group("bytes")))
        return True

    sp_m = _SERVICE_POLICY.match(line)
    if sp_m:
        entry["service_policy"] = sp_m.group("name")
        return True

    return False


def _parse_class_line(line: str, state: _ParseState) -> None:
    """Parse a line within a class context."""
    match_m = _MATCH_LINE.match(line)
    if match_m:
        state.current_class.match_clauses.append(match_m.group("criteria"))
        state.current_class.in_police = False
        return

    if _parse_police_line(line, state):
        return

    if _parse_rate_line(line, state.current_class.entry):
        return

    if _parse_qos_action_line(line, state.current_class.entry):
        state.current_class.in_police = False


@register(OS.CISCO_IOS, "show policy-map")
class ShowPolicyMapParser(BaseParser[ShowPolicyMapResult]):
    """Parser for 'show policy-map' command.

    Example output:
      Policy Map PARENT-POLICY
        Class VOICE
          Match: dscp ef
          police cir 128000 bc 8000
            conform-action transmit
            exceed-action drop
        Class class-default
          Match: any
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.QOS})

    @classmethod
    def parse(cls, output: str) -> ShowPolicyMapResult:
        """Parse 'show policy-map' output.

        Args:
            output: Raw CLI output from 'show policy-map' command.

        Returns:
            Parsed data with policy maps keyed by name.

        Raises:
            ValueError: If no policy maps found in output.
        """
        state = _ParseState()

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            policy_m = _POLICY_MAP_HEADER.match(line)
            if policy_m:
                state.start_policy(policy_m.group("name"))
                continue

            class_m = _CLASS_HEADER.match(line)
            if class_m:
                state.start_class(class_m.group("name"))
                continue

            if state.current_class.name is not None:
                _parse_class_line(line, state)

        state.flush_class()

        if not state.policy_maps:
            msg = "No policy-map entries found in output"
            raise ValueError(msg)

        return {"policy_maps": state.policy_maps}
