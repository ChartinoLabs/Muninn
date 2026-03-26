"""Parser for 'show avb domain' command on IOS-XE."""

import re
from typing import Any, ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class AvbClassSummary(TypedDict):
    """Schema for an AVB traffic class summary (Class-A or Class-B)."""

    priority_code_point: int
    vlan: int
    core_ports: int
    boundary_ports: int


class AvbInterfaceClassEntry(TypedDict):
    """Schema for per-interface AVB class assignment."""

    role: str
    pcp: int
    vid: int


class AvbInterfaceEntry(TypedDict):
    """Schema for a single interface in the AVB domain."""

    state: str
    delay: NotRequired[str]
    information: NotRequired[str]
    class_a: NotRequired[AvbInterfaceClassEntry]
    class_b: NotRequired[AvbInterfaceClassEntry]


class ShowAvbDomainResult(TypedDict):
    """Schema for 'show avb domain' parsed output."""

    class_a: AvbClassSummary
    class_b: AvbClassSummary
    interfaces: dict[str, AvbInterfaceEntry]


# -- Summary section patterns --

_CLASS_HEADER_RE = re.compile(r"^AVB\s+(?P<cls>Class-[AB])\s*$", re.IGNORECASE)

# Each tuple: (compiled pattern, dict key for AvbClassSummary)
_SUMMARY_FIELD_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"^\s*Priority\s+Code\s+Point\s*:\s*(?P<value>\d+)", re.IGNORECASE),
        "priority_code_point",
    ),
    (
        re.compile(r"^\s*VLAN\s*:\s*(?P<value>\d+)", re.IGNORECASE),
        "vlan",
    ),
    (
        re.compile(r"^\s*Core\s+ports\s*:\s*(?P<value>\d+)", re.IGNORECASE),
        "core_ports",
    ),
    (
        re.compile(r"^\s*Boundary\s+ports\s*:\s*(?P<value>\d+)", re.IGNORECASE),
        "boundary_ports",
    ),
)

# -- Interface table patterns --

# Matches interface lines like: Te1/0/1  up  300ns
# or: Te1/0/4  down  N/A  Oper state not up
_INTERFACE_RE = re.compile(
    r"^\s*(?P<interface>[A-Za-z]+[\d/]+)\s+"
    r"(?P<state>up|down)\s+"
    r"(?P<delay>\S+)"
    r"(?:\s+(?P<info>.+?))?\s*$",
    re.IGNORECASE,
)

# Matches Class-A/B detail lines under an interface:
#    Class-  A        core             3    2
_CLASS_DETAIL_RE = re.compile(
    r"^\s*Class-\s*(?P<cls>[AB])\s+"
    r"(?P<role>\S+)\s+"
    r"(?P<pcp>\d+)\s+"
    r"(?P<vid>\d+)",
    re.IGNORECASE,
)

_SEPARATOR_RE = re.compile(r"^-{10,}$")


def _class_key(label: str) -> str:
    """Convert a class label like 'CLASS-A' to dict key 'class_a'."""
    return "class_a" if label == "CLASS-A" else "class_b"


def _build_summary(fields: dict[str, int]) -> AvbClassSummary:
    """Build an AvbClassSummary from collected field values."""
    return AvbClassSummary(
        priority_code_point=fields.get("priority_code_point", 0),
        vlan=fields.get("vlan", 0),
        core_ports=fields.get("core_ports", 0),
        boundary_ports=fields.get("boundary_ports", 0),
    )


def _match_summary_field(line: str, fields: dict[str, int]) -> None:
    """Try each summary field pattern against a line, updating fields."""
    for pattern, key in _SUMMARY_FIELD_PATTERNS:
        if m := pattern.match(line):
            fields[key] = int(m.group("value"))
            return


def _parse_summary(lines: list[str]) -> dict[str, AvbClassSummary]:
    """Parse the AVB Class-A and Class-B summary sections.

    Returns:
        Dict with keys 'class_a' and/or 'class_b'.
    """
    summaries: dict[str, AvbClassSummary] = {}
    current_key: str | None = None
    fields: dict[str, int] = {}

    for line in lines:
        match = _CLASS_HEADER_RE.match(line.strip())
        if match:
            if current_key is not None:
                summaries[current_key] = _build_summary(fields)
            current_key = _class_key(match.group("cls").upper())
            fields = {}
            continue

        if current_key is not None:
            _match_summary_field(line, fields)

    # Save last class
    if current_key is not None:
        summaries[current_key] = _build_summary(fields)

    return summaries


def _build_interface_entry(match: re.Match[str]) -> AvbInterfaceEntry:
    """Build an AvbInterfaceEntry from a regex match."""
    entry = AvbInterfaceEntry(state=match.group("state").lower())

    delay = match.group("delay")
    if delay.upper() != "N/A":
        entry["delay"] = delay

    info = match.group("info")
    if info and info.strip():
        entry["information"] = info.strip()

    return entry


def _build_class_entry(match: re.Match[str]) -> tuple[str, AvbInterfaceClassEntry]:
    """Build an AvbInterfaceClassEntry from a regex match.

    Returns:
        Tuple of (dict_key, entry) where dict_key is 'class_a' or 'class_b'.
    """
    cls_label = match.group("cls").upper()
    entry = AvbInterfaceClassEntry(
        role=match.group("role").lower(),
        pcp=int(match.group("pcp")),
        vid=int(match.group("vid")),
    )
    key = "class_a" if cls_label == "A" else "class_b"
    return key, entry


def _parse_interfaces(lines: list[str]) -> dict[str, AvbInterfaceEntry]:
    """Parse the per-interface AVB domain table.

    Returns:
        Dict keyed by interface name.
    """
    interfaces: dict[str, AvbInterfaceEntry] = {}
    current_intf: str | None = None

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("-"):
            continue

        intf_match = _INTERFACE_RE.match(line)
        if intf_match:
            current_intf = canonical_interface_name(
                intf_match.group("interface"), os=OS.CISCO_IOSXE
            )
            interfaces[current_intf] = _build_interface_entry(intf_match)
            continue

        cls_match = _CLASS_DETAIL_RE.match(stripped)
        if cls_match and current_intf is not None:
            key, cls_entry = _build_class_entry(cls_match)
            _d = cast(dict[str, Any], interfaces[current_intf])
            _d[key] = cls_entry

    return interfaces


def _find_separator(lines: list[str]) -> int:
    """Find the index of the first separator line (---...).

    Raises:
        ValueError: If no separator line is found.
    """
    for idx, line in enumerate(lines):
        if _SEPARATOR_RE.match(line.strip()):
            return idx

    msg = "No AVB domain table separator found in output"
    raise ValueError(msg)


def _extract_summaries(lines: list[str]) -> dict[str, Any]:
    """Extract and validate Class-A and Class-B summaries.

    Raises:
        ValueError: If either class summary is missing.
    """
    summaries = _parse_summary(lines)
    if "class_a" not in summaries or "class_b" not in summaries:
        msg = "Missing AVB Class-A or Class-B summary in output"
        raise ValueError(msg)
    return summaries


@register(OS.CISCO_IOSXE, "show avb domain")
class ShowAvbDomainParser(BaseParser[ShowAvbDomainResult]):
    """Parser for 'show avb domain' command.

    Parses Audio Video Bridging (AVB) domain status including
    Class-A and Class-B summary configuration and per-interface
    state, delay, and class role assignments.

    Example output:
        AVB Class-A
            Priority Code Point     : 3
            VLAN                    : 2
            Core ports              : 1
            Boundary ports          : 67

        AVB Class-B
            Priority Code Point     : 2
            VLAN                    : 2
            Core ports              : 1
            Boundary ports          : 67

        ---------------------------------------------------------------
        Interface    State       Delay    PCP  VID  Information
        ---------------------------------------------------------------
        Te1/0/1        down      N/A             Oper state not up
        Te1/0/39         up    507ns
           Class-  A        core             3    2
           Class-  B        core             2    2
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowAvbDomainResult:
        """Parse 'show avb domain' output.

        Args:
            output: Raw CLI output from 'show avb domain' command.

        Returns:
            Parsed AVB domain data with class summaries and interfaces.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        lines = output.splitlines()
        separator_idx = _find_separator(lines)

        summaries = _extract_summaries(lines[:separator_idx])
        interfaces = _parse_interfaces(lines[separator_idx:])

        return ShowAvbDomainResult(
            class_a=summaries["class_a"],
            class_b=summaries["class_b"],
            interfaces=interfaces,
        )
