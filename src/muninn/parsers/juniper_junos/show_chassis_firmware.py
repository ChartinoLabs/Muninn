"""Parser for 'show chassis firmware' command on Juniper Junos."""

import re
from typing import ClassVar, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class FirmwareEntry(TypedDict):
    """Schema for a single chassis component's firmware information.

    ``firmware`` maps firmware type names (e.g., ``ROM``, ``O/S``,
    ``U-Boot``, ``loader``) to their reported version strings.
    ``member`` identifies the multi-chassis member (e.g., ``lcc0-re0``)
    when the output came from a multi-chassis context, and is absent
    for single-chassis output.
    """

    member: NotRequired[str]
    firmware: dict[str, str]


# Top-level result is a dict keyed by part name (e.g. ``FPC 0``,
# ``Routing Engine 1``) mapping to its firmware entry.
ShowChassisFirmwareResult = dict[str, FirmwareEntry]


@register(OS.JUNIPER_JUNOS, "show chassis firmware")
class ShowChassisFirmwareParser(BaseParser[ShowChassisFirmwareResult]):
    """Parser for 'show chassis firmware' command on Juniper Junos.

    Handles single-chassis and multi-chassis (TX Matrix, LCC) output.
    Returns a dict keyed by part name (e.g., ``FPC 0``, ``Routing Engine 1``)
    where each value contains a ``firmware`` mapping of firmware type to
    version, and an optional ``member`` field for multi-chassis output.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INVENTORY})

    # Member/LCC header line, e.g. "lcc0-re0:"
    _MEMBER_HEADER = re.compile(r"^(?P<member>\S+):\s*$")

    # Column header or separator lines to skip
    _COLUMN_HEADER = re.compile(r"^\s*Part\s+Type\s+Version\s*$")
    _SEPARATOR = re.compile(r"^-{3,}\s*$")

    # Junos prompt lines like "{master:0}" or "{primary:node0}"
    _PROMPT = re.compile(r"^\{.+\}\s*$")

    # A line with a named part, firmware type, and version.
    _PART_LINE = re.compile(
        r"^(?P<part>\S.+?)\s{2,}(?P<type>\S+)\s{2,}(?P<version>\S.*)$"
    )

    # Continuation line: part name is blank, just type and version.
    _CONTINUATION_LINE = re.compile(r"^\s{2,}(?P<type>\S+)\s{2,}(?P<version>\S.*)$")

    @classmethod
    def _is_skippable(cls, stripped: str) -> bool:
        """Return True if the line should be skipped entirely."""
        if not stripped:
            return True
        if cls._COLUMN_HEADER.match(stripped):
            return True
        if cls._SEPARATOR.match(stripped):
            return True
        return bool(cls._PROMPT.match(stripped))

    @classmethod
    def _parse_line(
        cls,
        line: str,
        stripped: str,
        state: dict[str, str | None],
        result: ShowChassisFirmwareResult,
    ) -> None:
        """Parse a single content line, updating result and state in place."""
        member_match = cls._MEMBER_HEADER.match(stripped)
        if member_match:
            state["member"] = member_match.group("member")
            return

        part_match = cls._PART_LINE.match(line)
        if part_match:
            state["part"] = part_match.group("part").strip()
            cls._add_entry(
                result,
                state["part"],
                part_match.group("type"),
                part_match.group("version").strip(),
                state["member"],
            )
            return

        cont_match = cls._CONTINUATION_LINE.match(line)
        if cont_match and state["part"] is not None:
            cls._add_entry(
                result,
                state["part"],
                cont_match.group("type"),
                cont_match.group("version").strip(),
                state["member"],
            )

    @classmethod
    def parse(cls, output: str) -> ShowChassisFirmwareResult:
        """Parse 'show chassis firmware' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by part name with firmware type/version pairs.

        Raises:
            ValueError: If no firmware entries found.
        """
        result: ShowChassisFirmwareResult = {}
        state: dict[str, str | None] = {"member": None, "part": None}

        for line in output.splitlines():
            stripped = line.strip()
            if cls._is_skippable(stripped):
                continue
            cls._parse_line(line, stripped, state, result)

        if not result:
            msg = "No firmware entries found in output"
            raise ValueError(msg)

        return result

    @staticmethod
    def _add_entry(
        result: ShowChassisFirmwareResult,
        part: str,
        fw_type: str,
        version: str,
        member: str | None,
    ) -> None:
        """Add a firmware entry to the result dict, merging by part name."""
        if part not in result:
            entry: FirmwareEntry = {"firmware": {}}
            if member is not None:
                entry["member"] = member
            result[part] = entry
        result[part]["firmware"][fw_type] = version
