"""Parser for 'show inventory' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class InventoryItem(TypedDict):
    """Schema for a single inventory item."""

    name: str
    description: NotRequired[str]
    pid: NotRequired[str]
    vid: NotRequired[str]
    serial_number: NotRequired[str]


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

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INVENTORY,
            ParserTag.SYSTEM,
        }
    )

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
    def _build_item(
        cls, name: str, descr: str, pid_match: re.Match[str]
    ) -> InventoryItem:
        """Build an InventoryItem from a PID/VID/SN regex match."""
        pid = cls._normalize_value(pid_match.group("pid"))
        vid = cls._normalize_value(pid_match.group("vid"))
        sn = cls._normalize_value(pid_match.group("sn"))

        item: InventoryItem = {
            "name": name,
        }
        if descr:
            item["description"] = descr
        if pid:
            item["pid"] = pid
        if vid:
            item["vid"] = vid
        if sn:
            item["serial_number"] = sn
        return item

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
        current_name: str | None = None
        current_descr: str | None = None

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            name_match = cls._NAME_DESCR_PATTERN.match(line)
            if name_match:
                current_name = name_match.group("name")
                current_descr = name_match.group("descr")
                continue

            pid_match = cls._PID_VID_SN_PATTERN.match(line)
            if pid_match and current_name is not None:
                inventory[current_name] = cls._build_item(
                    current_name, current_descr or "", pid_match
                )
                current_name = None
                current_descr = None

        if not inventory:
            msg = "No inventory items found in output"
            raise ValueError(msg)

        return ShowInventoryResult(inventory=inventory)
