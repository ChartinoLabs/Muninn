"""Parser for 'show stack-power budgeting' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class StackPowerBudgetingSwitchEntry(TypedDict):
    """Per-switch budgeting row."""

    power_supply_a_w: int
    power_supply_b_w: int
    power_budget_w: int
    allocated_power_w: float
    poe_available_power_w: float
    consumed_sys_w: int
    consumed_poe_w: float


class StackPowerBudgetingTotals(TypedDict):
    """Aggregate totals line."""

    allocated_power_w: float
    poe_available_power_w: float
    consumed_sys_w: int
    consumed_poe_w: float


class StackPowerBudgetingEntry(TypedDict):
    """Budgeting data for one power stack."""

    mode: str
    topology: str
    total_power_w: int
    reserved_power_w: int
    allocated_power_w: int
    switch_available_power_w: int
    num_switches: int
    num_power_supplies: int
    switches: NotRequired[dict[str, StackPowerBudgetingSwitchEntry]]


class ShowStackPowerBudgetingResult(TypedDict):
    """Schema for 'show stack-power budgeting' parsed output."""

    power_stacks: dict[str, StackPowerBudgetingEntry]
    totals: NotRequired[StackPowerBudgetingTotals]


_SUMMARY_PATTERN = re.compile(
    r"^(?P<name>\S+)\s+"
    r"(?P<mode>\S+)\s+"
    r"(?P<topology>\S+)\s+"
    r"(?P<total>\d+)\s+"
    r"(?P<reserved>\d+)\s+"
    r"(?P<alloc>\d+)\s+"
    r"(?P<sw_avail>\d+)\s+"
    r"(?P<num_sw>\d+)\s+"
    r"(?P<num_ps>\d+)\s*$"
)

_SWITCH_PATTERN = re.compile(
    r"^(?P<sw>\d+)\s+"
    r"(?P<name>\S+)\s+"
    r"(?P<ps_a>\d+)\s+"
    r"(?P<ps_b>\d+)\s+"
    r"(?P<budget>\d+)\s+"
    r"(?P<alloc>\d+(?:\.\d+)?)\s+"
    r"(?P<poe_avail>\d+(?:\.\d+)?)\s+"
    r"(?P<sys>\d+)\s*/\s*(?P<poe>\d+(?:\.\d+)?)\s*$"
)

_TOTALS_PATTERN = re.compile(
    r"^Totals:\s+(?P<alloc>\d+(?:\.\d+)?)\s+"
    r"(?P<poe_avail>\d+(?:\.\d+)?)\s+"
    r"(?P<sys>\d+)\s*/\s*(?P<poe>\d+(?:\.\d+)?)\s*$"
)

_SKIP_PATTERN = re.compile(
    r"^(?:"
    r"Power\s+Stack|"
    r"Name\s|"
    r"SW\s|"
    r"-{2,}"
    r")"
)


def _is_skip_line(line: str) -> bool:
    if not line:
        return True
    return _SKIP_PATTERN.match(line) is not None


def _apply_summary(
    match: re.Match[str],
    power_stacks: dict[str, StackPowerBudgetingEntry],
) -> None:
    name = match.group("name")
    power_stacks[name] = StackPowerBudgetingEntry(
        mode=match.group("mode"),
        topology=match.group("topology"),
        total_power_w=int(match.group("total")),
        reserved_power_w=int(match.group("reserved")),
        allocated_power_w=int(match.group("alloc")),
        switch_available_power_w=int(match.group("sw_avail")),
        num_switches=int(match.group("num_sw")),
        num_power_supplies=int(match.group("num_ps")),
    )


def _apply_switch_row(
    match: re.Match[str],
    power_stacks: dict[str, StackPowerBudgetingEntry],
) -> None:
    name = match.group("name")
    sw_num = match.group("sw")
    if name not in power_stacks:
        return
    if "switches" not in power_stacks[name]:
        power_stacks[name]["switches"] = {}
    power_stacks[name]["switches"][sw_num] = StackPowerBudgetingSwitchEntry(
        power_supply_a_w=int(match.group("ps_a")),
        power_supply_b_w=int(match.group("ps_b")),
        power_budget_w=int(match.group("budget")),
        allocated_power_w=float(match.group("alloc")),
        poe_available_power_w=float(match.group("poe_avail")),
        consumed_sys_w=int(match.group("sys")),
        consumed_poe_w=float(match.group("poe")),
    )


def _parse_budgeting_output(output: str) -> ShowStackPowerBudgetingResult:
    power_stacks: dict[str, StackPowerBudgetingEntry] = {}
    aggregate_totals: StackPowerBudgetingTotals | None = None

    for raw in output.splitlines():
        line = raw.strip()
        totals_match = _TOTALS_PATTERN.match(line)
        if totals_match:
            aggregate_totals = StackPowerBudgetingTotals(
                allocated_power_w=float(totals_match.group("alloc")),
                poe_available_power_w=float(totals_match.group("poe_avail")),
                consumed_sys_w=int(totals_match.group("sys")),
                consumed_poe_w=float(totals_match.group("poe")),
            )
            continue

        if _is_skip_line(line):
            continue

        summary_match = _SUMMARY_PATTERN.match(line)
        if summary_match:
            _apply_summary(summary_match, power_stacks)
            continue

        switch_match = _SWITCH_PATTERN.match(line)
        if switch_match:
            _apply_switch_row(switch_match, power_stacks)

    if not power_stacks:
        msg = "No power stacks found in output"
        raise ValueError(msg)

    result = ShowStackPowerBudgetingResult(power_stacks=power_stacks)
    if aggregate_totals is not None:
        result["totals"] = aggregate_totals
    return result


@register(OS.CISCO_IOSXE, "show stack-power budgeting")
class ShowStackPowerBudgetingParser(BaseParser[ShowStackPowerBudgetingResult]):
    """Parser for 'show stack-power budgeting' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ENVIRONMENT,
            ParserTag.POE,
            ParserTag.SYSTEM,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowStackPowerBudgetingResult:
        """Parse 'show stack-power budgeting' output."""
        return _parse_budgeting_output(output)
