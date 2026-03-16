"""Parser for 'show platform resources' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ResourceEntry(TypedDict):
    """Schema for a single resource measurement."""

    usage: float
    usage_unit: str
    usage_percent: NotRequired[int]
    max: float
    max_unit: str
    warning_percent: int
    critical_percent: int
    state: str


class SubComponentEntry(TypedDict):
    """Schema for a sub-component (e.g., QFP) that contains resources."""

    state: str
    resources: NotRequired[dict[str, ResourceEntry]]


class ComponentEntry(TypedDict):
    """Schema for a top-level component (e.g., RP0, ESP0)."""

    status: str
    role: str
    state: str
    resources: NotRequired[dict[str, ResourceEntry]]
    sub_components: NotRequired[dict[str, SubComponentEntry]]


class ShowPlatformResourcesResult(TypedDict):
    """Schema for 'show platform resources' parsed output."""

    components: dict[str, ComponentEntry]


# Component header: "RP0 (ok, active)" or "ESP0(ok, active)" or "SIP0"
_COMPONENT = re.compile(
    r"^(?P<name>(?:RP|ESP|SIP)\d+)"
    r"(?:\s*\((?P<status>\w+),\s*(?P<role>\w+)\))?"
    r"\s+(?P<state>[HWC])\s*$"
)

# Sub-component line (no usage data, just a name and state):
# "QFP                                                                 H"
# " Control Processor   12.43%   100%   80%   90%   H"
# We detect sub-components as lines with only a name and a state letter
_SUB_COMPONENT = re.compile(r"^(?P<name>[A-Z][A-Za-z ]+?)\s+(?P<state>[HWC])\s*$")

# Resource with value+unit and percentage:
# "DRAM    3665MB(48%)   7567MB   88%   93%   H"
# "TCAM    8cells(0%)    1048576cells   65%   85%   H"
# "B4Q Pool 124   15KB(0%)   1686KB   75%   85%   H"
# "B4Q PMD    33952KB(25%)   130944KB   75%   85%   H"
# "Pkt Buf Mem (0)   67KB(0%)   524288KB   85%   95%   H"
# "TMPFS    666MB(16%)   3919MB   40%   50%   H"
_RESOURCE_VALUE = re.compile(
    r"^(?P<name>.+?)\s+"
    r"(?P<usage>[\d.]+)(?P<usage_unit>[A-Za-z]+)"
    r"\((?P<pct>\d+)%\)\s+"
    r"(?P<max>[\d.]+)(?P<max_unit>[A-Za-z]+)\s+"
    r"(?P<warn>\d+)%\s+"
    r"(?P<crit>\d+)%\s+"
    r"(?P<state>[HWC])\s*$"
)

# Resource as percentage only:
# "Control Processor   12.43%   100%   80%   90%   H"
# "CPU Utilization     0.00%    100%   90%   95%   H"
# "Crypto Utilization  1.00%    100%   90%   95%   H"
_RESOURCE_PCT = re.compile(
    r"^(?P<name>.+?)\s+"
    r"(?P<usage>[\d.]+)%\s+"
    r"(?P<max>[\d.]+)%\s+"
    r"(?P<warn>\d+)%\s+"
    r"(?P<crit>\d+)%\s+"
    r"(?P<state>[HWC])\s*$"
)

# Header / separator / state acronym lines to skip
_SKIP = re.compile(r"^(?:\*\*State Acronym|Resource\s+Usage|---)", re.IGNORECASE)


def _parse_resource_value(match: re.Match[str]) -> tuple[str, ResourceEntry]:
    """Build a ResourceEntry from a value+unit resource match."""
    name = match.group("name").strip()
    entry = ResourceEntry(
        usage=float(match.group("usage")),
        usage_unit=match.group("usage_unit"),
        usage_percent=int(match.group("pct")),
        max=float(match.group("max")),
        max_unit=match.group("max_unit"),
        warning_percent=int(match.group("warn")),
        critical_percent=int(match.group("crit")),
        state=match.group("state"),
    )
    return name, entry


def _parse_resource_pct(match: re.Match[str]) -> tuple[str, ResourceEntry]:
    """Build a ResourceEntry from a percentage-only resource match."""
    name = match.group("name").strip()
    entry = ResourceEntry(
        usage=float(match.group("usage")),
        usage_unit="%",
        max=float(match.group("max")),
        max_unit="%",
        warning_percent=int(match.group("warn")),
        critical_percent=int(match.group("crit")),
        state=match.group("state"),
    )
    return name, entry


def _add_resource(
    component: ComponentEntry,
    sub_component: str | None,
    name: str,
    entry: ResourceEntry,
) -> None:
    """Add a resource entry to the appropriate component or sub-component."""
    if sub_component is not None:
        sub_comps = component.get("sub_components", {})
        if sub_component in sub_comps:
            resources = sub_comps[sub_component].get("resources", {})
            resources[name] = entry
            sub_comps[sub_component]["resources"] = resources
    else:
        if "resources" not in component:
            component["resources"] = {}
        component["resources"][name] = entry


def _process_line(
    line: str,
    components: dict[str, ComponentEntry],
    current_component: str | None,
    current_sub: str | None,
) -> tuple[str | None, str | None]:
    """Process a single stripped line, returning updated state."""
    if match := _COMPONENT.match(line):
        name = match.group("name")
        status = match.group("status") or "ok"
        role = match.group("role") or "unknown"
        components[name] = ComponentEntry(
            status=status,
            role=role,
            state=match.group("state"),
        )
        return name, None

    if current_component is None:
        return None, None

    if match := _RESOURCE_VALUE.match(line):
        res_name, entry = _parse_resource_value(match)
        _add_resource(components[current_component], current_sub, res_name, entry)
        return current_component, current_sub

    if match := _RESOURCE_PCT.match(line):
        res_name, entry = _parse_resource_pct(match)
        _add_resource(components[current_component], current_sub, res_name, entry)
        return current_component, current_sub

    if match := _SUB_COMPONENT.match(line):
        sub_name = match.group("name").strip()
        if "sub_components" not in components[current_component]:
            components[current_component]["sub_components"] = {}
        components[current_component]["sub_components"][sub_name] = SubComponentEntry(
            state=match.group("state")
        )
        return current_component, sub_name

    return current_component, current_sub


@register(OS.CISCO_IOSXE, "show platform resources")
class ShowPlatformResourcesParser(BaseParser[ShowPlatformResourcesResult]):
    """Parser for 'show platform resources' command.

    Example output::

        **State Acronym: H - Healthy, W - Warning, C - Critical
        Resource          Usage          Max       Warning  Critical  State
        RP0 (ok, active)                                               H
         Control Processor 12.43%        100%      80%      90%       H
          DRAM             3665MB(48%)   7567MB    88%      93%       H
        ESP0(ok, active)                                               H
         QFP                                                           H
          DRAM             233176KB(44%) 524288KB  85%      95%       H
    """

    tags: ClassVar[frozenset[str]] = frozenset({"platform", "system"})

    @classmethod
    def parse(cls, output: str) -> ShowPlatformResourcesResult:
        """Parse 'show platform resources' output.

        Args:
            output: Raw CLI output from 'show platform resources'.

        Returns:
            Parsed platform resource data keyed by component.

        Raises:
            ValueError: If no platform resource data is found.
        """
        components: dict[str, ComponentEntry] = {}
        current_component: str | None = None
        current_sub: str | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or _SKIP.match(stripped):
                continue
            if stripped.startswith("show platform"):
                continue

            current_component, current_sub = _process_line(
                stripped, components, current_component, current_sub
            )

        if not components:
            msg = "No platform resource data found in output"
            raise ValueError(msg)

        return ShowPlatformResourcesResult(components=components)
