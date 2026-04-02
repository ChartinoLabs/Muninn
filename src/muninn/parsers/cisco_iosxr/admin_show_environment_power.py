"""Parser for 'admin show environment power' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class PowerSupplyEntry(TypedDict):
    """Schema for a single power supply module."""

    supply_type: str
    input_voltage_a: float
    input_voltage_b: float
    input_current_a: float
    input_current_b: float
    output_voltage: float
    output_current: float
    status: str
    power_group: int


class PowerConsumerEntry(TypedDict):
    """Schema for a single power consumer (line card, RP, fabric, fan, etc.)."""

    card_type: NotRequired[str]
    power_allocated_watts: int
    power_used_watts: NotRequired[int]
    status: str


class ChassisPowerSummary(TypedDict):
    """Schema for chassis-level power summary."""

    total_capacity_watts: int
    total_required_watts: int
    total_input_watts: int
    total_output_watts: int


class AdminShowEnvironmentPowerResult(TypedDict):
    """Schema for 'admin show environment power' parsed output."""

    chassis_summary: ChassisPowerSummary
    power_supplies: dict[str, PowerSupplyEntry]
    power_consumers: dict[str, PowerConsumerEntry]


@register(OS.CISCO_IOSXR, "admin show environment power")
class AdminShowEnvironmentPowerParser(
    BaseParser[AdminShowEnvironmentPowerResult],
):
    """Parser for 'admin show environment power' on Cisco IOS-XR.

    Extracts chassis power summary, per-module power supply details,
    and per-slot power consumer information.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ENVIRONMENT})

    # Chassis summary patterns
    _TOTAL_CAPACITY = re.compile(
        r"Total output power capacity.*?:\s+(\d+)W\s*\+\s+(\d+)W",
    )
    _TOTAL_REQUIRED = re.compile(
        r"Total output power required\s*:\s+(\d+)W",
    )
    _TOTAL_INPUT = re.compile(
        r"Total power input\s*:\s+(\d+)W",
    )
    _TOTAL_OUTPUT = re.compile(
        r"Total power output\s*:\s+(\d+)W",
    )

    # Power Group header
    _POWER_GROUP = re.compile(r"^Power Group (\d+):")

    # Power supply module line, e.g.:
    #    0/PM0       3kW-DC      54.0/54.0   3.3/ 3.5    12.1     27.0    OK
    _SUPPLY_LINE = re.compile(
        r"^\s+(?P<location>\S+/PM\d+)\s+"
        r"(?P<type>\S+)\s+"
        r"(?P<vin_a>[\d.]+)/(?P<vin_b>[\d.]+)\s+"
        r"(?P<iin_a>[\d.]+)/\s*(?P<iin_b>[\d.]+)\s+"
        r"(?P<vout>[\d.]+)\s+"
        r"(?P<iout>[\d.]+)\s+"
        r"(?P<status>\S+)",
    )

    # Power consumer line, e.g.:
    #    0/0          NC55-36X100G           902         504       ON
    #    0/1                 -                25           -       RESERVED
    _CONSUMER_LINE = re.compile(
        r"^\s+(?P<location>\S+)\s+"
        r"(?P<card_type>\S+)\s+"
        r"(?P<allocated>\d+)\s+"
        r"(?P<used>\d+|-)\s+"
        r"(?P<status>\S+)\s*$",
    )

    @classmethod
    def _parse_chassis_summary(cls, output: str) -> ChassisPowerSummary:
        """Extract chassis-level power totals."""
        capacity = 0
        if match := cls._TOTAL_CAPACITY.search(output):
            capacity = int(match.group(1)) + int(match.group(2))

        required = 0
        if match := cls._TOTAL_REQUIRED.search(output):
            required = int(match.group(1))

        total_in = 0
        if match := cls._TOTAL_INPUT.search(output):
            total_in = int(match.group(1))

        total_out = 0
        if match := cls._TOTAL_OUTPUT.search(output):
            total_out = int(match.group(1))

        return ChassisPowerSummary(
            total_capacity_watts=capacity,
            total_required_watts=required,
            total_input_watts=total_in,
            total_output_watts=total_out,
        )

    @classmethod
    def _parse_power_supplies(
        cls,
        output: str,
    ) -> dict[str, PowerSupplyEntry]:
        """Extract per-module power supply entries."""
        supplies: dict[str, PowerSupplyEntry] = {}
        current_group = 0

        for line in output.splitlines():
            group_match = cls._POWER_GROUP.match(line.strip())
            if group_match:
                current_group = int(group_match.group(1))
                continue

            match = cls._SUPPLY_LINE.match(line)
            if match:
                location = match.group("location")
                supplies[location] = PowerSupplyEntry(
                    supply_type=match.group("type"),
                    input_voltage_a=float(match.group("vin_a")),
                    input_voltage_b=float(match.group("vin_b")),
                    input_current_a=float(match.group("iin_a")),
                    input_current_b=float(match.group("iin_b")),
                    output_voltage=float(match.group("vout")),
                    output_current=float(match.group("iout")),
                    status=match.group("status"),
                    power_group=current_group,
                )

        return supplies

    @classmethod
    def _parse_power_consumers(
        cls,
        output: str,
    ) -> dict[str, PowerConsumerEntry]:
        """Extract per-slot power consumer entries."""
        consumers: dict[str, PowerConsumerEntry] = {}

        # Find the consumer table by locating its header
        in_consumer_table = False
        separator_seen = False

        for line in output.splitlines():
            stripped = line.strip()

            # Detect consumer table header (Location / Card Type / ...)
            if "Location" in stripped and "Card Type" in stripped:
                in_consumer_table = True
                separator_seen = False
                continue

            if not in_consumer_table:
                continue

            # Wait for the separator line after the multi-line header
            if not separator_seen:
                if stripped.startswith("==="):
                    separator_seen = True
                continue

            match = cls._CONSUMER_LINE.match(line)
            if not match:
                continue

            location = match.group("location")
            card_type = match.group("card_type")
            used_str = match.group("used")

            entry = PowerConsumerEntry(
                power_allocated_watts=int(match.group("allocated")),
                status=match.group("status"),
            )

            if card_type != "-":
                entry["card_type"] = card_type

            if used_str != "-":
                entry["power_used_watts"] = int(used_str)

            consumers[location] = entry

        return consumers

    @classmethod
    def parse(cls, output: str) -> AdminShowEnvironmentPowerResult:
        """Parse 'admin show environment power' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed power environment information including chassis summary,
            power supply details, and power consumer data.

        Raises:
            ValueError: If no power supply or consumer data is found.
        """
        chassis_summary = cls._parse_chassis_summary(output)
        power_supplies = cls._parse_power_supplies(output)
        power_consumers = cls._parse_power_consumers(output)

        if not power_supplies and not power_consumers:
            msg = "No power supply or consumer data found in output"
            raise ValueError(msg)

        return cast(
            AdminShowEnvironmentPowerResult,
            {
                "chassis_summary": chassis_summary,
                "power_supplies": power_supplies,
                "power_consumers": power_consumers,
            },
        )
