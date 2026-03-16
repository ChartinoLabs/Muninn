"""Parser for 'show ip prefix-list' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class PrefixEntry(TypedDict):
    """Schema for a single prefix-list entry."""

    seq: int
    action: str
    network: str
    ge: NotRequired[int]
    le: NotRequired[int]


class PrefixListInfo(TypedDict):
    """Schema for a single prefix-list."""

    count: int
    entries: dict[str, PrefixEntry]


class ShowIpPrefixListResult(TypedDict):
    """Schema for 'show ip prefix-list' parsed output."""

    prefix_lists: dict[str, PrefixListInfo]


@register(OS.CISCO_IOS, "show ip prefix-list")
class ShowIpPrefixListParser(BaseParser[ShowIpPrefixListResult]):
    """Parser for 'show ip prefix-list' command.

    Example output:
        ip prefix-list OSPF_Redist: 2 entries
           seq 5 deny 10.0.0.0/24
           seq 10 permit 0.0.0.0/0 le 32
    """

    tags: ClassVar[frozenset[str]] = frozenset({"routing"})

    _HEADER_PATTERN = re.compile(
        r"^ip\s+prefix-list\s+(?P<name>\S+):\s+(?P<count>\d+)\s+entr",
    )

    _ENTRY_PATTERN = re.compile(
        r"^\s*seq\s+(?P<seq>\d+)\s+(?P<action>permit|deny)\s+"
        r"(?P<network>\S+)"
        r"(?:\s+ge\s+(?P<ge>\d+))?"
        r"(?:\s+le\s+(?P<le>\d+))?",
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpPrefixListResult:
        """Parse 'show ip prefix-list' output.

        Args:
            output: Raw CLI output from 'show ip prefix-list' command.

        Returns:
            Parsed prefix-list data keyed by list name.

        Raises:
            ValueError: If no prefix-list data found in output.
        """
        prefix_lists: dict[str, PrefixListInfo] = {}
        current_name: str | None = None

        for line in output.splitlines():
            if not line.strip():
                continue

            header_match = cls._HEADER_PATTERN.match(line)
            if header_match:
                current_name = header_match.group("name")
                count = int(header_match.group("count"))
                prefix_lists[current_name] = PrefixListInfo(
                    count=count,
                    entries={},
                )
                continue

            entry_match = cls._ENTRY_PATTERN.match(line)
            if entry_match and current_name is not None:
                seq = int(entry_match.group("seq"))
                entry: PrefixEntry = {
                    "seq": seq,
                    "action": entry_match.group("action"),
                    "network": entry_match.group("network"),
                }

                if entry_match.group("ge"):
                    entry["ge"] = int(entry_match.group("ge"))
                if entry_match.group("le"):
                    entry["le"] = int(entry_match.group("le"))

                prefix_lists[current_name]["entries"][str(seq)] = entry

        if not prefix_lists:
            msg = "No prefix-list data found in output"
            raise ValueError(msg)

        return ShowIpPrefixListResult(prefix_lists=prefix_lists)
