"""Parser for 'show ppp all' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class PppAllRow(TypedDict):
    """One PPP session row.

    ``interface`` is the canonical interface name.
    """

    interface: str
    open_nego: str
    stage: str
    peer_address: str


class ShowPppAllResult(TypedDict):
    """Schema for 'show ppp all' parsed output."""

    sessions: dict[str, PppAllRow]


def _split_ppp_columns(line: str) -> list[str] | None:
    parts = re.split(r"\s{2,}", line.strip())
    if len(parts) < 4:
        return None
    return parts


@register(OS.CISCO_IOSXE, "show ppp all")
class ShowPppAllParser(BaseParser[ShowPppAllResult]):
    """Parser for 'show ppp all' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowPppAllResult:
        """Parse 'show ppp all' output."""
        sessions: dict[str, PppAllRow] = {}
        for line in output.splitlines():
            s = line.strip()
            if not s or s.startswith("Interface") or set(s) <= {"-"}:
                continue
            parts = _split_ppp_columns(line)
            if not parts or len(parts) < 4:
                continue
            iface, open_nego, stage, peer = parts[0], parts[1], parts[2], parts[3]
            interface = canonical_interface_name(iface, os=OS.CISCO_IOSXE)
            row = PppAllRow(
                interface=interface,
                open_nego=open_nego,
                stage=stage,
                peer_address=peer,
            )
            sessions[interface] = row
        if not sessions:
            msg = "No PPP sessions parsed"
            raise ValueError(msg)
        return cast(ShowPppAllResult, {"sessions": sessions})
