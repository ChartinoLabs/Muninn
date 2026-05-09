"""Parser for 'show interfaces summary' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class InterfaceTypeSummaryEntry(TypedDict):
    """Schema for a single interface type row in 'show interfaces summary' output."""

    total: int
    up: int
    down: int
    admin_down: int


class ShowInterfacesSummaryResult(TypedDict):
    """Schema for 'show interfaces summary' parsed output.

    Contains an ``all_types`` totals entry and a ``by_type`` dict-of-dicts
    keyed by the IOS-XR interface type identifier (e.g. ``IFT_ETHERBUNDLE``).
    """

    all_types: InterfaceTypeSummaryEntry
    by_type: dict[str, InterfaceTypeSummaryEntry]


@register(OS.CISCO_IOSXR, "show interfaces summary")
class ShowInterfacesSummaryParser(BaseParser[ShowInterfacesSummaryResult]):
    """Parser for 'show interfaces summary' command on Cisco IOS-XR.

    Parses the tabular interface type summary into structured counts
    with an overall total and per-type breakdown.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INTERFACES,
        }
    )

    # Matches the "ALL TYPES" aggregate row.
    _ALL_TYPES_PATTERN = re.compile(
        r"^\s*ALL\s+TYPES"
        r"\s+(?P<total>\d+)"
        r"\s+(?P<up>\d+)"
        r"\s+(?P<down>\d+)"
        r"\s+(?P<admin_down>\d+)"
        r"\s*$",
        re.IGNORECASE,
    )

    # Matches individual IFT_* rows (e.g. IFT_ETHERBUNDLE, IFT_TENGETHERNET).
    _IFT_PATTERN = re.compile(
        r"^\s*(?P<ift_name>IFT_\S+)"
        r"\s+(?P<total>\d+)"
        r"\s+(?P<up>\d+)"
        r"\s+(?P<down>\d+)"
        r"\s+(?P<admin_down>\d+)"
        r"\s*$",
        re.IGNORECASE,
    )

    @classmethod
    def parse(cls, output: str) -> ShowInterfacesSummaryResult:
        """Parse 'show interfaces summary' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface summary with overall totals and per-type breakdown.

        Raises:
            ValueError: If the ALL TYPES aggregate row cannot be found.
        """
        all_types: InterfaceTypeSummaryEntry | None = None
        by_type: dict[str, InterfaceTypeSummaryEntry] = {}

        for line in output.splitlines():
            all_match = cls._ALL_TYPES_PATTERN.match(line)
            if all_match:
                all_types = InterfaceTypeSummaryEntry(
                    total=int(all_match.group("total")),
                    up=int(all_match.group("up")),
                    down=int(all_match.group("down")),
                    admin_down=int(all_match.group("admin_down")),
                )
                continue

            ift_match = cls._IFT_PATTERN.match(line)
            if ift_match:
                name = ift_match.group("ift_name")
                entry = InterfaceTypeSummaryEntry(
                    total=int(ift_match.group("total")),
                    up=int(ift_match.group("up")),
                    down=int(ift_match.group("down")),
                    admin_down=int(ift_match.group("admin_down")),
                )
                by_type[name] = entry

        if all_types is None:
            msg = "No ALL TYPES summary row found in output"
            raise ValueError(msg)

        return ShowInterfacesSummaryResult(
            all_types=all_types,
            by_type=by_type,
        )
