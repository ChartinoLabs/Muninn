"""Parser for 'show service sdp-using' command on Nokia SR OS."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

_NULL_VALUES = frozenset({"none"})


class SdpBindingEntry(TypedDict):
    """Schema for a single SDP binding entry."""

    service_id: str
    sdp_id: str
    type: str
    far_end: str
    oper_state: str
    ingress_label: NotRequired[int]
    egress_label: NotRequired[int]


# Top-level result is a dict keyed by SDP binding ID (e.g. "1000:20001")
ShowServiceSdpUsingResult = dict[str, SdpBindingEntry]


@register(OS.NOKIA_SROS, "show service sdp-using")
class ShowServiceSdpUsingParser(BaseParser[ShowServiceSdpUsingResult]):
    """Parser for 'show service sdp-using' command on Nokia SR OS.

    Parses the tabular SDP binding summary output, returning a dict keyed
    by SDP binding ID with each value containing binding attributes.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.MPLS,
            ParserTag.VPN,
        }
    )

    # Non-data patterns to skip: separators, headers, title, summary
    _SKIP_PATTERNS = (
        re.compile(r"^[=\-]{10,}$"),
        re.compile(r"^\s*SvcId\s+SdpId\s+Type\s+Far End", re.I),
        re.compile(r"^\s*State\s*$", re.I),
        re.compile(r"^\s*SDP Using\s*$", re.I),
        re.compile(r"^\s*Number of SDPs\s*:", re.I),
    )

    # SDP data row pattern
    # SvcId  SdpId  Type  Far End  Opr  I.Label  E.Label
    _SDP_ROW = re.compile(
        r"^(?P<svc_id>\d+)\s+"
        r"(?P<sdp_id>\S+)\s+"
        r"(?P<type>\S+)\s+"
        r"(?P<far_end>\S+)\s+"
        r"(?P<oper>Up|Down)\s+"
        r"(?P<i_label>\S+)\s+"
        r"(?P<e_label>\S+)$"
    )

    @classmethod
    def _is_skip_line(cls, line: str) -> bool:
        """Return True for lines that are not data rows."""
        stripped = line.strip()
        if not stripped:
            return True
        return any(p.match(stripped) for p in cls._SKIP_PATTERNS)

    @classmethod
    def parse(cls, output: str) -> ShowServiceSdpUsingResult:
        """Parse 'show service sdp-using' output on Nokia SR OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by SDP binding ID, each value an SdpBindingEntry dict.

        Raises:
            ValueError: If no SDP binding entries can be parsed.
        """
        result: dict[str, SdpBindingEntry] = {}

        for line in output.splitlines():
            if cls._is_skip_line(line):
                continue

            match = cls._SDP_ROW.match(line.strip())
            if match is None:
                continue

            sdp_id = match.group("sdp_id")
            entry: SdpBindingEntry = {
                "service_id": match.group("svc_id"),
                "sdp_id": sdp_id.split(":")[0] if ":" in sdp_id else sdp_id,
                "type": match.group("type"),
                "far_end": match.group("far_end"),
                "oper_state": match.group("oper"),
            }

            i_label = match.group("i_label")
            if i_label.lower() not in _NULL_VALUES:
                entry["ingress_label"] = int(i_label)

            e_label = match.group("e_label")
            if e_label.lower() not in _NULL_VALUES:
                entry["egress_label"] = int(e_label)

            result[sdp_id] = entry

        if not result:
            msg = "No SDP binding entries found in output"
            raise ValueError(msg)

        return cast(ShowServiceSdpUsingResult, result)
