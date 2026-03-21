"""Parser for 'show stack-power detail' command on IOS-XE."""

import re
from dataclasses import dataclass, field
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class SwitchPowerDetail(TypedDict):
    """Per-switch fields inside a power stack detail block."""

    switch_number: int
    power_budget: int
    power_allocated: int
    low_port_priority_value: int
    high_port_priority_value: int
    switch_priority_value: int
    port_status: dict[str, str]
    neighbor_on_port: dict[str, str]


class PowerStackDetailEntry(TypedDict):
    """Summary table row plus detail block for one power stack."""

    summary_mode: str
    summary_topology: str
    total_power: int
    reserved_power: int
    allocated_power: int
    switch_available_power: int
    num_switches: int
    num_power_supplies: int
    stack_mode: str
    stack_topology: str
    switch: SwitchPowerDetail


class ShowStackPowerDetailResult(TypedDict):
    """Schema for 'show stack-power detail' parsed output."""

    power_stacks: dict[str, PowerStackDetailEntry]


_SUMMARY_ROW = re.compile(
    r"^\s+(?P<name>Powerstack-\d+)\s+"
    r"(?P<mode>\S+)\s+"
    r"(?P<topo>\S+)\s+"
    r"(?P<total>\d+)\s+"
    r"(?P<rsvd>\d+)\s+"
    r"(?P<alloc>\d+)\s+"
    r"(?P<sw_avail>\d+)\s+"
    r"(?P<num_sw>\d+)\s+"
    r"(?P<num_ps>\d+)\s*$",
)

_STACK_NAME = re.compile(r"^Power stack name:\s*(?P<name>\S+)", re.IGNORECASE)
_SWITCH_HDR = re.compile(r"^Switch\s+(?P<num>\d+):\s*$", re.IGNORECASE)
_INT_FIELD = re.compile(
    r"^(?P<label>.+?):\s*(?P<val>-?\d+)\s*$",
    re.IGNORECASE,
)
_PORT_STATUS = re.compile(
    r"^Port\s+(?P<pnum>\d+)\s+status:\s*(?P<st>.+?)\s*$",
    re.IGNORECASE,
)
_NEIGHBOR = re.compile(
    r"^Neighbor on port\s+(?P<pnum>\d+):\s*(?P<mac>\S+)\s*$",
    re.IGNORECASE,
)


def _build_switch(
    acc: dict[str, int],
    port_status: dict[str, str],
    neighbors: dict[str, str],
) -> SwitchPowerDetail:
    return SwitchPowerDetail(
        switch_number=acc["switch_number"],
        power_budget=acc["power_budget"],
        power_allocated=acc["power_allocated"],
        low_port_priority_value=acc["low_port_priority_value"],
        high_port_priority_value=acc["high_port_priority_value"],
        switch_priority_value=acc["switch_priority_value"],
        port_status=dict(port_status),
        neighbor_on_port=dict(neighbors),
    )


@dataclass
class _DetailParseState:
    power_stacks: dict[str, PowerStackDetailEntry] = field(default_factory=dict)
    current_name: str | None = None
    acc: dict[str, int] = field(default_factory=dict)
    port_status: dict[str, str] = field(default_factory=dict)
    neighbors: dict[str, str] = field(default_factory=dict)
    in_switch: bool = False


_REQUIRED_FIELDS = (
    "switch_number",
    "power_budget",
    "power_allocated",
    "low_port_priority_value",
    "high_port_priority_value",
    "switch_priority_value",
)


def _flush_switch(state: _DetailParseState) -> None:
    if not state.in_switch or state.current_name is None:
        return
    name = state.current_name
    if name not in state.power_stacks:
        return
    if not all(k in state.acc for k in _REQUIRED_FIELDS):
        return
    state.power_stacks[name]["switch"] = _build_switch(
        state.acc,
        state.port_status,
        state.neighbors,
    )
    state.in_switch = False


def _add_summary_row(
    match: re.Match[str],
    stacks: dict[str, PowerStackDetailEntry],
) -> None:
    name = match.group("name")
    stacks[name] = PowerStackDetailEntry(
        summary_mode=match.group("mode"),
        summary_topology=match.group("topo"),
        total_power=int(match.group("total")),
        reserved_power=int(match.group("rsvd")),
        allocated_power=int(match.group("alloc")),
        switch_available_power=int(match.group("sw_avail")),
        num_switches=int(match.group("num_sw")),
        num_power_supplies=int(match.group("num_ps")),
        stack_mode="",
        stack_topology="",
        switch=SwitchPowerDetail(
            switch_number=0,
            power_budget=0,
            power_allocated=0,
            low_port_priority_value=0,
            high_port_priority_value=0,
            switch_priority_value=0,
            port_status={},
            neighbor_on_port={},
        ),
    )


def _apply_switch_block_line(state: _DetailParseState, stripped: str) -> None:
    if stripped.startswith("Power budget:"):
        state.acc["power_budget"] = int(stripped.split(":", 1)[1].strip())
        return
    if stripped.startswith("Power allocated:"):
        state.acc["power_allocated"] = int(stripped.split(":", 1)[1].strip())
        return
    if "priority value" in stripped.lower():
        if m2 := _INT_FIELD.match(stripped):
            label = m2.group("label").strip().lower()
            val = int(m2.group("val"))
            if "low port" in label:
                state.acc["low_port_priority_value"] = val
            elif "high port" in label:
                state.acc["high_port_priority_value"] = val
            elif label.startswith("switch priority"):
                state.acc["switch_priority_value"] = val
        return
    if m := _PORT_STATUS.match(stripped):
        state.port_status[m.group("pnum")] = m.group("st").strip()
        return
    if m := _NEIGHBOR.match(stripped):
        state.neighbors[m.group("pnum")] = m.group("mac")


def _process_detail_line(state: _DetailParseState, line: str) -> None:
    stripped = line.strip()
    if not stripped:
        return

    if m := _SUMMARY_ROW.match(line):
        _add_summary_row(m, state.power_stacks)
        return

    if m := _STACK_NAME.match(stripped):
        _flush_switch(state)
        state.current_name = m.group("name")
        state.acc = {}
        state.port_status = {}
        state.neighbors = {}
        state.in_switch = False
        return

    if state.current_name is None or state.current_name not in state.power_stacks:
        return

    if stripped.startswith("Stack mode:"):
        val = stripped.split(":", 1)[1].strip()
        state.power_stacks[state.current_name]["stack_mode"] = val
        return
    if stripped.startswith("Stack topology:"):
        val = stripped.split(":", 1)[1].strip()
        state.power_stacks[state.current_name]["stack_topology"] = val
        return

    if m := _SWITCH_HDR.match(stripped):
        _flush_switch(state)
        state.acc = {"switch_number": int(m.group("num"))}
        state.port_status = {}
        state.neighbors = {}
        state.in_switch = True
        return

    if state.in_switch:
        _apply_switch_block_line(state, stripped)


def _parse_stack_power_detail_lines(
    lines: list[str],
) -> dict[str, PowerStackDetailEntry]:
    state = _DetailParseState()
    for raw in lines:
        _process_detail_line(state, raw.rstrip())
    _flush_switch(state)
    return state.power_stacks


@register(OS.CISCO_IOSXE, "show stack-power detail")
class ShowStackPowerDetailParser(BaseParser[ShowStackPowerDetailResult]):
    """Parser for 'show stack-power detail' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ENVIRONMENT,
            ParserTag.SYSTEM,
        },
    )

    @classmethod
    def parse(cls, output: str) -> ShowStackPowerDetailResult:
        """Parse 'show stack-power detail' output."""
        power_stacks = _parse_stack_power_detail_lines(output.splitlines())

        if not power_stacks:
            msg = "No power stack data found in output"
            raise ValueError(msg)

        for name, entry in power_stacks.items():
            if entry["switch"]["switch_number"] == 0:
                msg = f"Incomplete detail for power stack {name}"
                raise ValueError(msg)

        return ShowStackPowerDetailResult(power_stacks=power_stacks)
