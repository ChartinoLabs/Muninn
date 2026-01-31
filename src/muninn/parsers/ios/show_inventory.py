"""Parser for 'show inventory' command on IOS."""

import re
from typing import TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class InventoryItem(TypedDict):
    """Schema for a single inventory item."""

    name: str
    description: str
    pid: str | None
    vid: str | None
    serial_number: str | None


class ShowInventoryResult(TypedDict):
    """Schema for 'show inventory' parsed output."""

    inventory: dict[str, InventoryItem]


@register(OS.CISCO_IOS, "show inventory")
@register(OS.CISCO_IOSXE, "show inventory")
@register(OS.CISCO_NXOS, "show inventory")
class ShowInventoryParser(BaseParser[ShowInventoryResult]):
    """Parser for 'show inventory' command.

    Parses hardware inventory information including chassis, modules,
    power supplies, fans, and transceivers.
    """

    # Pattern for NAME/DESCR line: NAME: "...", DESCR: "..."
    _NAME_DESCR_PATTERN = re.compile(
        r'^NAME:\s*"(?P<name>[^"]+)"\s*,\s*DESCR:\s*"(?P<descr>[^"]*)"',
        re.IGNORECASE,
    )

    # Pattern for PID/VID/SN line: PID: ..., VID: ..., SN: ...
    _PID_VID_SN_PATTERN = re.compile(
        r"^PID:\s*(?P<pid>[^,]*?)\s*,\s*VID:\s*(?P<vid>[^,]*?)\s*,\s*SN:\s*(?P<sn>.*?)\s*$",
        re.IGNORECASE,
    )

    @classmethod
    def _normalize_value(cls, value: str) -> str | None:
        """Normalize a field value, converting empty/N/A to None.

        Args:
            value: Raw field value from CLI output.

        Returns:
            Normalized value or None if empty/N/A.
        """
        value = value.strip()
        if not value or value.upper() == "N/A":
            return None
        return value

    @classmethod
    def parse(cls, output: str) -> ShowInventoryResult:
        """Parse 'show inventory' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed inventory data keyed by component name.

        Raises:
            ValueError: If no inventory items found.
        """
        inventory: dict[str, InventoryItem] = {}
        lines = output.splitlines()

        current_name: str | None = None
        current_descr: str | None = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Try to match NAME/DESCR line
            name_match = cls._NAME_DESCR_PATTERN.match(line)
            if name_match:
                current_name = name_match.group("name")
                current_descr = name_match.group("descr")
                continue

            # Try to match PID/VID/SN line
            pid_match = cls._PID_VID_SN_PATTERN.match(line)
            if pid_match and current_name is not None:
                pid = cls._normalize_value(pid_match.group("pid"))
                vid = cls._normalize_value(pid_match.group("vid"))
                sn = cls._normalize_value(pid_match.group("sn"))

                inventory[current_name] = InventoryItem(
                    name=current_name,
                    description=current_descr or "",
                    pid=pid,
                    vid=vid,
                    serial_number=sn,
                )

                # Reset for next item
                current_name = None
                current_descr = None

        if not inventory:
            msg = "No inventory items found in output"
            raise ValueError(msg)

        return ShowInventoryResult(inventory=inventory)
