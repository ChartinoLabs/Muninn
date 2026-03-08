"""Parser for 'show stack-power' command on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class SwitchPowerEntry(TypedDict):
    """Schema for per-switch power allocation within a power stack."""

    power_supply_a: int
    power_supply_b: int
    power_budget: int
    allocated_power: int
    available_power: int
    consumed_power_sys: int
    consumed_power_poe: int


class PowerStackEntry(TypedDict):
    """Schema for a single power stack."""

    mode: str
    topology: str
    total_power: int
    reserved_power: int
    allocated_power: int
    available_power: int
    num_switches: int
    num_power_supplies: int
    switches: NotRequired[dict[str, SwitchPowerEntry]]


class ShowStackPowerResult(TypedDict):
    """Schema for 'show stack-power' parsed output."""

    power_stacks: dict[str, PowerStackEntry]


# Summary table row pattern:
# Powerstack-1  SP-PS  Stndaln  1100  0  575  525  1  1
_SUMMARY_PATTERN = re.compile(
    r"^(?P<name>\S+)\s+"
    r"(?P<mode>\S+)\s+"
    r"(?P<topology>\S+)\s+"
    r"(?P<total_power>\d+)\s+"
    r"(?P<reserved_power>\d+)\s+"
    r"(?P<allocated_power>\d+)\s+"
    r"(?P<available_power>\d+)\s+"
    r"(?P<num_switches>\d+)\s+"
    r"(?P<num_ps>\d+)\s*$"
)

# Per-switch detail row pattern:
# 1  Powerstack-1  1100  0  1100  575  525  155/0
# Handles optional spaces around the slash in consumed power
_SWITCH_PATTERN = re.compile(
    r"^(?P<sw_num>\d+)\s+"
    r"(?P<name>\S+)\s+"
    r"(?P<ps_a>\d+)\s+"
    r"(?P<ps_b>\d+)\s+"
    r"(?P<budget>\d+)\s+"
    r"(?P<alloc>\d+)\s+"
    r"(?P<avail>\d+)\s+"
    r"(?P<sys>\d+)\s*/\s*(?P<poe>\d+)\s*$"
)

_SKIP_PATTERN = re.compile(
    r"^(?:"
    r"Power\s|"  # Header lines like "Power Stack ..." or "Power       Stack ..."
    r"Name\s|"  # Column header continuation
    r"SW\s|"  # Per-switch section header
    r"Totals:|"  # Totals row
    r"-{2,}"  # Separator lines
    r")"
)


def _is_skip_line(line: str) -> bool:
    """Check if a line should be skipped (header, separator, totals, empty)."""
    if not line:
        return True
    return _SKIP_PATTERN.match(line) is not None


@register(OS.CISCO_IOSXE, "show stack-power")
class ShowStackPowerParser(BaseParser[ShowStackPowerResult]):
    """Parser for 'show stack-power' command.

    Example output:
        Power Stack  Stack  Stack   Total  Rsvd   Alloc  Unused Num Num
        Name         Mode   Topolgy Pwr(W) Pwr(W) Pwr(W) Pwr(W) SW  PS
        Powerstack-1 SP-PS  Stndaln 1100   0      575    525    1   1
    """

    @classmethod
    def parse(cls, output: str) -> ShowStackPowerResult:
        """Parse 'show stack-power' output.

        Args:
            output: Raw CLI output from 'show stack-power' command.

        Returns:
            Parsed data with power stacks keyed by stack name.

        Raises:
            ValueError: If no power stacks found in output.
        """
        power_stacks: dict[str, PowerStackEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if _is_skip_line(line):
                continue

            summary_match = _SUMMARY_PATTERN.match(line)
            if summary_match:
                _process_summary_match(summary_match, power_stacks)
                continue

            switch_match = _SWITCH_PATTERN.match(line)
            if switch_match:
                _process_switch_match(switch_match, power_stacks)

        if not power_stacks:
            msg = "No power stacks found in output"
            raise ValueError(msg)

        return ShowStackPowerResult(power_stacks=power_stacks)


def _process_summary_match(
    match: re.Match[str],
    power_stacks: dict[str, PowerStackEntry],
) -> None:
    """Process a summary table row match and add to power_stacks."""
    name = match.group("name")
    power_stacks[name] = PowerStackEntry(
        mode=match.group("mode"),
        topology=match.group("topology"),
        total_power=int(match.group("total_power")),
        reserved_power=int(match.group("reserved_power")),
        allocated_power=int(match.group("allocated_power")),
        available_power=int(match.group("available_power")),
        num_switches=int(match.group("num_switches")),
        num_power_supplies=int(match.group("num_ps")),
    )


def _process_switch_match(
    match: re.Match[str],
    power_stacks: dict[str, PowerStackEntry],
) -> None:
    """Process a per-switch detail row match and add to the parent stack."""
    name = match.group("name")
    sw_num = match.group("sw_num")

    if name not in power_stacks:
        return

    if "switches" not in power_stacks[name]:
        power_stacks[name]["switches"] = {}

    power_stacks[name]["switches"][sw_num] = SwitchPowerEntry(
        power_supply_a=int(match.group("ps_a")),
        power_supply_b=int(match.group("ps_b")),
        power_budget=int(match.group("budget")),
        allocated_power=int(match.group("alloc")),
        available_power=int(match.group("avail")),
        consumed_power_sys=int(match.group("sys")),
        consumed_power_poe=int(match.group("poe")),
    )
