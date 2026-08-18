"""Parser for 'show vlans' command on Juniper Junos."""

import re
from typing import ClassVar, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class VlanInterfaceEntry(TypedDict):
    """Schema for a VLAN member interface."""

    active: bool


class VlanEntry(TypedDict):
    """Schema for a single VLAN entry."""

    tag: int
    routing_instance: str
    description: NotRequired[str]
    interfaces: dict[str, VlanInterfaceEntry]


class ShowVlansResult(TypedDict):
    """Schema for 'show vlans' parsed output."""

    vlans: dict[str, VlanEntry]


# First line of a VLAN block: routing-instance, VLAN name, tag
_VLAN_HEADER = re.compile(r"^(?P<instance>\S+)\s+(?P<name>\S+)\s+(?P<tag>\d+)\s*$")

# Continuation line with only an interface name; trailing `*` indicates the
# interface is currently active/up in the VLAN.
_INTERFACE_LINE = re.compile(r"^\s+(?P<iface>\S+?)(?P<active>\*?)\s*$")

# Junos prompt lines like "{master:0}" or "{primary:node0}"
_PROMPT = re.compile(r"^\{.+\}\s*$")


def _is_skippable(stripped: str) -> bool:
    """Return True if the line should be skipped entirely."""
    if not stripped:
        return True
    if _PROMPT.match(stripped):
        return True
    return stripped.startswith("Routing instance")


@register(OS.JUNIPER_JUNOS, "show vlans")
class ShowVlansParser(BaseParser[ShowVlansResult]):
    """Parser for 'show vlans' command on Juniper Junos.

    Parses VLAN name, tag (ID), routing instance, and member interfaces
    from the tabular output of EX and QFX series switches. A trailing
    asterisk (``*``) on an interface indicates the interface is currently
    active in the VLAN; this is captured as ``active: bool`` rather than
    being kept in the interface name.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.VLAN})

    @classmethod
    def parse(cls, output: str) -> ShowVlansResult:
        """Parse 'show vlans' output on Juniper Junos.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by VLAN name with tag, routing instance,
            and interface membership.
        """
        vlans: dict[str, VlanEntry] = {}
        current_entry: VlanEntry | None = None

        for line in output.splitlines():
            stripped = line.strip()

            if _is_skippable(stripped):
                continue

            header_match = _VLAN_HEADER.match(stripped)
            if header_match:
                entry: VlanEntry = {
                    "tag": int(header_match.group("tag")),
                    "routing_instance": header_match.group("instance"),
                    "interfaces": {},
                }
                vlans[header_match.group("name")] = entry
                current_entry = entry
                continue

            iface_match = _INTERFACE_LINE.match(line)
            if iface_match and current_entry is not None:
                raw_iface = iface_match.group("iface")
                active = bool(iface_match.group("active"))
                iface_name = canonical_interface_name(raw_iface, os=OS.JUNIPER_JUNOS)
                current_entry["interfaces"][iface_name] = {"active": active}

        return {"vlans": vlans}
