"""Parser for 'show isis database' command on Cisco IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class IsisLspEntry(TypedDict):
    """Schema for a single IS-IS LSP entry in the database summary.

    Attributes:
        sequence_number: LSP sequence number (hex string).
        checksum: LSP checksum (hex string).
        holdtime: LSP holdtime in seconds.
        holdtime_received: Received holdtime (omitted when local).
        att: Attached bit value.
        p_bit: Partition repair bit value.
        ol: Overload bit value.
        is_local: True if the LSP is locally originated.
    """

    sequence_number: str
    checksum: str
    holdtime: int
    holdtime_received: NotRequired[int]
    att: int
    p_bit: int
    ol: int
    is_local: NotRequired[bool]


class ShowIsisDatabaseResult(TypedDict):
    """Schema for 'show isis database' parsed output.

    Attributes:
        tag: IS-IS instance tag.
        levels: Mapping of level name to LSP entries keyed by LSPID.
    """

    tag: str
    levels: dict[str, dict[str, IsisLspEntry]]


# "Tag 1:" or "Tag 64512:" at start of output
_TAG_PATTERN = re.compile(r"^Tag\s+(?P<tag>\S+):\s*$")

# "IS-IS Level-1 Link State Database:" or "IS-IS Level-2 ..."
_LEVEL_HEADER_PATTERN = re.compile(
    r"^IS-IS\s+(?P<level>Level-[12])\s+Link\s+State\s+Database:\s*$"
)

# Column header line (skip it)
_COLUMN_HEADER_PATTERN = re.compile(r"^LSPID\s+LSP\s+Seq\s+Num")

# LSP entry on a single line:
# R1.00-00            * 0x000005A8   0xCD13                 489/*         0/0/0
_LSP_PATTERN = re.compile(
    r"^(?P<lsp_id>\S+\.\d+-\d+)\s+"
    r"(?P<local>\*)?\s*"
    r"(?P<seq>0x[0-9a-fA-F]+)\s+"
    r"(?P<checksum>0x[0-9a-fA-F]+)\s+"
    r"(?P<holdtime>\d+)/(?P<rcvd>\d+|\*)\s+"
    r"(?P<att>\d)/(?P<p>\d)/(?P<ol>\d)\s*$"
)


def _build_lsp_entry(
    seq: str,
    checksum: str,
    holdtime: str,
    rcvd: str,
    att: str,
    p: str,
    ol: str,
    local: str | None,
) -> IsisLspEntry:
    """Construct an LSP entry from parsed regex groups."""
    lsp: IsisLspEntry = {
        "sequence_number": seq,
        "checksum": checksum,
        "holdtime": int(holdtime),
        "att": int(att),
        "p_bit": int(p),
        "ol": int(ol),
    }
    if rcvd and rcvd != "*":
        lsp["holdtime_received"] = int(rcvd)
    if local:
        lsp["is_local"] = True
    return lsp


@register(OS.CISCO_IOSXE, "show isis database")
class ShowIsisDatabaseParser(BaseParser["ShowIsisDatabaseResult"]):
    """Parser for 'show isis database' command on IOS-XE.

    Parses the IS-IS link state database summary listing LSP headers
    with sequence number, checksum, holdtime, and ATT/P/OL flags.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ISIS,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> "ShowIsisDatabaseResult":
        """Parse 'show isis database' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed LSP data grouped by tag and level.

        Raises:
            ValueError: If no LSP entries found in output.
        """
        tag: str = "null"
        levels: dict[str, dict[str, IsisLspEntry]] = {}
        current_level: str | None = None

        for line in output.splitlines():
            if not line.strip():
                continue

            # Check for tag line
            tag_match = _TAG_PATTERN.match(line)
            if tag_match:
                tag = tag_match.group("tag")
                continue

            # Check for level header
            level_match = _LEVEL_HEADER_PATTERN.match(line)
            if level_match:
                current_level = level_match.group("level")
                levels.setdefault(current_level, {})
                continue

            # Skip column header
            if _COLUMN_HEADER_PATTERN.match(line):
                continue

            # Try to match an LSP entry
            lsp_match = _LSP_PATTERN.match(line)
            if lsp_match:
                if current_level is None:
                    current_level = "Level-2"
                    levels.setdefault(current_level, {})
                lsp_id = lsp_match.group("lsp_id")
                lsp = _build_lsp_entry(
                    seq=lsp_match.group("seq"),
                    checksum=lsp_match.group("checksum"),
                    holdtime=lsp_match.group("holdtime"),
                    rcvd=lsp_match.group("rcvd"),
                    att=lsp_match.group("att"),
                    p=lsp_match.group("p"),
                    ol=lsp_match.group("ol"),
                    local=lsp_match.group("local"),
                )
                levels[current_level][lsp_id] = lsp

        if not levels:
            msg = "No IS-IS LSP entries found in output"
            raise ValueError(msg)

        result = {"tag": tag, "levels": levels}
        return cast(ShowIsisDatabaseResult, result)
