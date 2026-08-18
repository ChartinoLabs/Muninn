"""Parser for 'show inventory' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class InventoryItem(TypedDict):
    """Schema for a single inventory entry."""

    description: NotRequired[str]
    pid: NotRequired[str]
    vid: NotRequired[str]
    sn: NotRequired[str]


class ShowInventoryResult(TypedDict):
    """Schema for 'show inventory' parsed output.

    Dict keyed by inventory item NAME.
    """


# Sentinel values that mean "no data" in IOS-XR inventory output.
_NA_SENTINELS = frozenset({"N/A", "n/a", "NA", ""})


@register(OS.CISCO_IOSXR, "show inventory")
class ShowInventoryParser(BaseParser[dict[str, InventoryItem]]):
    """Parser for 'show inventory' command on Cisco IOS-XR.

    Produces a dict keyed by inventory item NAME. Each value contains
    the non-empty fields: description, pid, vid, sn.
    Fields whose raw value is empty or "N/A" are omitted.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INVENTORY})

    _NAME_DESCR_PATTERN = re.compile(
        r'^NAME:\s+"(?P<name>[^"]+)"'
        r',\s+DESCR:\s+"(?P<descr>[^"]*)"'
    )
    _PID_VID_SN_PATTERN = re.compile(
        r"^PID:\s*(?P<pid>[^,]*?)\s*"
        r",\s*VID:\s*(?P<vid>[^,]*?)\s*"
        r",\s*SN:\s*(?P<sn>.*?)\s*$"
    )

    @classmethod
    def _parse_pid_vid_sn(cls, line: str, item: InventoryItem) -> None:
        """Extract PID, VID, and SN fields from a PID line into *item*.

        Fields whose value is empty or a known sentinel are omitted.
        """
        pid_match = cls._PID_VID_SN_PATTERN.match(line)
        if not pid_match:
            return

        for field, group in (("pid", "pid"), ("vid", "vid"), ("sn", "sn")):
            value = pid_match.group(group).strip()
            if value and value not in _NA_SENTINELS:
                item[field] = value  # type: ignore[literal-required]

    @classmethod
    def parse(cls, output: str) -> dict[str, InventoryItem]:
        """Parse 'show inventory' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by inventory item NAME.

        Raises:
            ValueError: If no inventory entries are found.
        """
        result: dict[str, InventoryItem] = {}
        lines = output.splitlines()
        idx = 0

        while idx < len(lines):
            line = lines[idx].rstrip()
            name_match = cls._NAME_DESCR_PATTERN.match(line)
            if name_match:
                name = name_match.group("name")
                descr = name_match.group("descr").strip()
                item: InventoryItem = {}

                if descr and descr not in _NA_SENTINELS:
                    item["description"] = descr

                # Next non-blank line should be PID/VID/SN
                idx += 1
                while idx < len(lines) and not lines[idx].strip():
                    idx += 1

                if idx < len(lines):
                    cls._parse_pid_vid_sn(lines[idx].rstrip(), item)

                result[name] = item

            idx += 1

        if not result:
            msg = "No inventory entries found in output"
            raise ValueError(msg)

        return result
