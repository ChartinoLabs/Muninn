"""Parser for 'show policy-map' command on IOS-XE."""

import re
from typing import Any, ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class PoliceEntry(TypedDict):
    """Schema for a police action."""

    cir_bps: NotRequired[int]
    cir_percent: NotRequired[int]
    bc_bytes: NotRequired[int]
    bc_ms: NotRequired[int]
    pir_bps: NotRequired[int]
    pir_percent: NotRequired[int]
    be_bytes: NotRequired[int]
    be_ms: NotRequired[int]
    rate_bps: NotRequired[int]
    rate_pps: NotRequired[int]
    rate_percent: NotRequired[int]
    conform_actions: NotRequired[list[str]]
    exceed_actions: NotRequired[list[str]]
    violate_actions: NotRequired[list[str]]


class ShapeEntry(TypedDict):
    """Schema for a traffic shaping action."""

    type: str
    cir_bps: NotRequired[int]
    bc_bits: NotRequired[int]
    be_bits: NotRequired[int]


class PriorityEntry(TypedDict):
    """Schema for a priority action (bare ``priority`` sets only ``enabled``)."""

    enabled: bool
    level: NotRequired[int]
    kbps: NotRequired[int]
    percent: NotRequired[int]


class BandwidthEntry(TypedDict):
    """Schema for a bandwidth allocation."""

    kbps: NotRequired[int]
    percent: NotRequired[int]
    remaining_percent: NotRequired[int]


class QueueLimitEntry(TypedDict):
    """Schema for a queue limit."""

    packets: NotRequired[int]
    bytes: NotRequired[int]


class WredClassEntry(TypedDict):
    """Schema for one row of the WRED threshold table."""

    min_threshold: NotRequired[int]
    max_threshold: NotRequired[int]
    mark_probability: str


class WredEntry(TypedDict):
    """Schema for WRED configuration."""

    type: str
    exponential_weight: int
    classes: NotRequired[dict[str, WredClassEntry]]


class ClassEntry(TypedDict):
    """Schema for a single class within a policy-map."""

    police: NotRequired[PoliceEntry]
    shape: NotRequired[ShapeEntry]
    priority: NotRequired[PriorityEntry]
    bandwidth: NotRequired[BandwidthEntry]
    queue_limit: NotRequired[QueueLimitEntry]
    wred: NotRequired[WredEntry]
    service_policy: NotRequired[str]


class PolicyMapEntry(TypedDict):
    """Schema for a single policy-map."""

    classes: dict[str, ClassEntry]


class ShowPolicyMapResult(TypedDict):
    """Schema for 'show policy-map' parsed output."""

    policy_maps: dict[str, PolicyMapEntry]


_POLICY_MAP_RE = re.compile(r"^\s*Policy Map (?P<name>\S+)\s*$")
_CLASS_RE = re.compile(r"^\s*Class (?P<name>\S+)\s*$")
_POLICE_RE = re.compile(r"^\s*police (?P<spec>.+?)\s*$")
_POLICE_CIR_RE = re.compile(
    r"^cir (?:percent (?P<cir_percent>\d+)|(?P<cir_bps>\d+))"
    r"(?: bc (?P<bc>\d+)(?P<bc_ms> ms)?)?"
    r"(?: pir (?:percent (?P<pir_percent>\d+)|(?P<pir_bps>\d+)))?"
    r"(?: be (?P<be>\d+)(?P<be_ms> ms)?)?$"
)
_POLICE_RATE_RE = re.compile(
    r"^rate (?:percent (?P<rate_percent>\d+)|(?P<rate>\d+)(?: (?P<unit>bps|pps))?)$"
)
_POLICE_POSITIONAL_RE = re.compile(
    r"^(?P<cir_bps>\d+)(?: (?P<bc_bytes>\d+))?(?: (?P<be_bytes>\d+))?$"
)
_POLICE_ACTION_RE = re.compile(
    r"^\s*(?P<kind>conform|exceed|violate)-action (?P<action>.+?)\s*$"
)
_SHAPE_RE = re.compile(r"^\s*(?P<type>\w+) Rate Traffic Shaping\s*$")
_SHAPE_CIR_RE = re.compile(
    r"^\s*cir (?P<cir>\d+) \(bps\)"
    r"(?: bc (?P<bc>\d+) \(bits\))?"
    r"(?: be (?P<be>\d+) \(bits\))?\s*$"
)
_PRIORITY_RE = re.compile(
    r"^\s*priority(?: level (?P<level>\d+))?"
    r"(?: (?P<value>\d+) \((?P<unit>kbps|%)\))?\s*$"
)
_BANDWIDTH_RE = re.compile(
    r"^\s*bandwidth (?P<remaining>remaining )?(?P<value>\d+) \((?P<unit>kbps|%)\)\s*$"
)
_QUEUE_LIMIT_RE = re.compile(
    r"^\s*queue-limit (?P<value>\d+) (?P<unit>packets|bytes)\s*$"
)
_SERVICE_POLICY_RE = re.compile(r"^\s*service-policy (?P<name>\S+)\s*$")
_WRED_RE = re.compile(r"^\s*(?P<type>\S+) wred, exponential weight (?P<weight>\d+)\s*$")
_WRED_ROW_RE = re.compile(
    r"^\s*(?P<cls>\d+|rsvp)\s+(?P<min>\d+|-)\s+(?P<max>\d+|-)"
    r"\s+(?P<prob>\d+/\d+)\s*$"
)


def _police_cir(m: re.Match[str]) -> dict[str, Any]:
    """Build police fields from a 'cir ... [pir ...]' spec match."""
    police: dict[str, Any] = {}
    for key in ("cir_percent", "cir_bps", "pir_percent", "pir_bps"):
        if m.group(key):
            police[key] = int(m.group(key))
    for key in ("bc", "be"):
        if m.group(key):
            unit = "ms" if m.group(f"{key}_ms") else "bytes"
            police[f"{key}_{unit}"] = int(m.group(key))
    return police


def _police_rate(m: re.Match[str]) -> dict[str, Any]:
    """Build police fields from a 'rate ...' spec match."""
    if m.group("rate_percent"):
        return {"rate_percent": int(m.group("rate_percent"))}
    return {f"rate_{m.group('unit') or 'bps'}": int(m.group("rate"))}


def _parse_police_spec(spec: str) -> PoliceEntry:
    """Parse the arguments following the 'police' keyword."""
    police: dict[str, Any] = {}
    if m := _POLICE_CIR_RE.match(spec):
        police = _police_cir(m)
    elif m := _POLICE_RATE_RE.match(spec):
        police = _police_rate(m)
    elif m := _POLICE_POSITIONAL_RE.match(spec):
        police = {k: int(v) for k, v in m.groupdict().items() if v}
    return cast(PoliceEntry, police)


def _try_police(line: str, entry: dict[str, Any]) -> bool:
    """Handle 'police ...' and its indented action lines."""
    if m := _POLICE_RE.match(line):
        entry["police"] = _parse_police_spec(m.group("spec"))
        return True
    if "police" in entry and (m := _POLICE_ACTION_RE.match(line)):
        key = f"{m.group('kind')}_actions"
        entry["police"].setdefault(key, []).append(m.group("action"))
        return True
    return False


def _try_shape(line: str, entry: dict[str, Any]) -> bool:
    """Handle '<Type> Rate Traffic Shaping' and its 'cir' line."""
    if m := _SHAPE_RE.match(line):
        entry["shape"] = {"type": m.group("type").lower()}
        return True
    if "shape" in entry and (m := _SHAPE_CIR_RE.match(line)):
        entry["shape"]["cir_bps"] = int(m.group("cir"))
        for key in ("bc", "be"):
            if m.group(key):
                entry["shape"][f"{key}_bits"] = int(m.group(key))
        return True
    return False


def _try_wred(line: str, entry: dict[str, Any]) -> bool:
    """Handle the WRED header line and threshold table rows."""
    if m := _WRED_RE.match(line):
        entry["wred"] = {
            "type": m.group("type"),
            "exponential_weight": int(m.group("weight")),
        }
        return True
    if "wred" in entry and (m := _WRED_ROW_RE.match(line)):
        row: dict[str, Any] = {"mark_probability": m.group("prob")}
        if m.group("min") != "-":
            row["min_threshold"] = int(m.group("min"))
        if m.group("max") != "-":
            row["max_threshold"] = int(m.group("max"))
        entry["wred"].setdefault("classes", {})[m.group("cls")] = row
        return True
    return False


def _try_priority(line: str, entry: dict[str, Any]) -> bool:
    """Handle 'priority [level N] [value (kbps|%)]'."""
    m = _PRIORITY_RE.match(line)
    if not m:
        return False
    priority: dict[str, Any] = {"enabled": True}
    if m.group("level"):
        priority["level"] = int(m.group("level"))
    if m.group("value"):
        unit = "kbps" if m.group("unit") == "kbps" else "percent"
        priority[unit] = int(m.group("value"))
    entry["priority"] = priority
    return True


def _try_simple(line: str, entry: dict[str, Any]) -> bool:
    """Handle bandwidth, queue-limit, and service-policy lines."""
    if m := _BANDWIDTH_RE.match(line):
        unit = "kbps" if m.group("unit") == "kbps" else "percent"
        key = f"remaining_{unit}" if m.group("remaining") else unit
        entry.setdefault("bandwidth", {})[key] = int(m.group("value"))
        return True
    if m := _QUEUE_LIMIT_RE.match(line):
        entry["queue_limit"] = {m.group("unit"): int(m.group("value"))}
        return True
    if m := _SERVICE_POLICY_RE.match(line):
        entry["service_policy"] = m.group("name")
        return True
    return False


_CLASS_HANDLERS = (_try_police, _try_shape, _try_wred, _try_priority, _try_simple)


@register(OS.CISCO_IOSXE, "show policy-map")
# Single-token subcommands are excluded so e.g. a bare `show policy-map session`
# never routes here; multi-token subcommands cannot match the single `\S+`.
@register(
    OS.CISCO_IOSXE,
    r"show policy-map (?P<policy_name>"
    r"(?!(?:interface|control-plane|multipoint|session|target|type|apn)$)\S+)",
    doc_template="show policy-map <policy-name>",
)
class ShowPolicyMapParser(BaseParser[ShowPolicyMapResult]):
    """Parser for 'show policy-map [<policy-name>]' on IOS-XE.

    Example output:
        Policy Map parent
            Class class-default
                Average Rate Traffic Shaping
                cir 10000000 (bps)
                service-policy child
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.QOS})

    @classmethod
    def parse(cls, output: str) -> ShowPolicyMapResult:
        """Parse 'show policy-map' output.

        Args:
            output: Raw CLI output from 'show policy-map'.

        Returns:
            Policy-maps keyed by name, each with its classes keyed by name.

        Raises:
            ValueError: If no policy-map is found in the output.
        """
        policy_maps: dict[str, dict[str, Any]] = {}
        classes: dict[str, Any] | None = None
        entry: dict[str, Any] | None = None

        for line in output.splitlines():
            if m := _POLICY_MAP_RE.match(line):
                classes = policy_maps.setdefault(m.group("name"), {"classes": {}})[
                    "classes"
                ]
                entry = None
            elif classes is not None and (m := _CLASS_RE.match(line)):
                entry = classes.setdefault(m.group("name"), {})
            elif entry is not None:
                any(handler(line, entry) for handler in _CLASS_HANDLERS)

        if not policy_maps:
            msg = "No policy-map entries found in output"
            raise ValueError(msg)

        return cast(ShowPolicyMapResult, {"policy_maps": policy_maps})
