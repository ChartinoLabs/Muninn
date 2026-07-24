"""Parser for 'show isis interface brief' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class InterfaceBriefEntry(TypedDict):
    """Schema for a single IS-IS interface brief entry."""

    type: str
    clns_state: NotRequired[str]
    mtu: NotRequired[int]
    adjacencies_l1: NotRequired[int]
    adjacencies_l2: NotRequired[int]
    priority_l1: NotRequired[int]
    priority_l2: NotRequired[int]
    configured_topologies: NotRequired[list[str]]
    running_topologies: NotRequired[list[str]]


class ShowIsisInterfaceBriefResult(TypedDict):
    """Schema for 'show isis interface brief' parsed output.

    Top-level keys are IS-IS instance IDs. Each instance maps canonical
    interface names to their brief IS-IS status.
    """

    instances: dict[str, dict[str, InterfaceBriefEntry]]


# Instance header: "IS-IS <tag> Interfaces"
_INSTANCE_RE = re.compile(r"^IS-IS\s+(?P<instance>\S+)\s+Interfaces")

# Interface data line.  The All-OK field (Yes/No) is always present;
# remaining columns are optional (missing when interface is in error).
_INTF_RE = re.compile(
    r"^(?P<intf>\S+)\s+(?P<type>Yes|No)"
    r"(?:"
    r"\s+(?P<adj_l1>\S+)"
    r"\s+(?P<adj_l2>\S+)"
    r"\s+(?P<adj_run>\d+)/(?P<adj_cfg>\d+)"
    r"\s+(?P<adv_run>\d+)/(?P<adv_cfg>\d+)"
    r"\s+(?P<clns>\S+)"
    r"\s+(?P<mtu>\d+)"
    r"\s+(?P<prio_l1>\S+)"
    r"\s+(?P<prio_l2>\S+)"
    r")?\s*$"
)

# Lines to skip: column headers, separator dashes, timestamps, command echo
_SKIP_RE = re.compile(
    r"^\s*$"
    r"|^\s*Interface"
    r"|^\s+OK"
    r"|^-{3,}"
    r"|^\w{3}\s+\w{3}\s+\d+"
    r"|^show\s+isis"
)


@register(OS.CISCO_IOSXR, "show isis interface brief")
class ShowIsisInterfaceBriefParser(
    BaseParser["ShowIsisInterfaceBriefResult"],
):
    """Parser for 'show isis interface brief' on IOS-XR.

    Parses the compact tabular output of IS-IS interface status.
    Interfaces are grouped by IS-IS instance, then keyed by canonical
    interface name.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ISIS})

    @classmethod
    def parse(cls, output: str) -> "ShowIsisInterfaceBriefResult":
        """Parse 'show isis interface brief' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface brief data grouped by IS-IS instance.

        Raises:
            ValueError: If no IS-IS instances found in output.
        """
        instances: dict[str, dict[str, InterfaceBriefEntry]] = {}
        current_instance: str | None = None

        for line in output.splitlines():
            if _SKIP_RE.match(line):
                continue

            inst_match = _INSTANCE_RE.match(line.strip())
            if inst_match:
                current_instance = inst_match.group("instance")
                if current_instance not in instances:
                    instances[current_instance] = {}
                continue

            if current_instance is None:
                continue

            intf_match = _INTF_RE.match(line.strip())
            if not intf_match:
                continue

            entry = cls._build_entry(intf_match)
            iface = canonical_interface_name(
                intf_match.group("intf"), os=OS.CISCO_IOSXR
            )
            instances[current_instance][iface] = entry

        if not instances:
            msg = "No IS-IS instances found in output"
            raise ValueError(msg)

        return cast(ShowIsisInterfaceBriefResult, {"instances": instances})

    @classmethod
    def _build_entry(cls, match: re.Match[str]) -> InterfaceBriefEntry:
        """Build an InterfaceBriefEntry from a regex match."""
        entry: InterfaceBriefEntry = {"type": match.group("type")}

        # Remaining columns are only present when the line has full data
        if match.group("clns") is None:
            return entry

        entry["clns_state"] = match.group("clns")
        entry["mtu"] = int(match.group("mtu"))

        # Adjacencies: dash means not applicable, strip trailing '*'
        adj_l1 = match.group("adj_l1")
        if adj_l1 != "-":
            entry["adjacencies_l1"] = int(adj_l1.rstrip("*"))

        adj_l2 = match.group("adj_l2")
        if adj_l2 != "-":
            entry["adjacencies_l2"] = int(adj_l2.rstrip("*"))

        # Priority: dash means not set
        prio_l1 = match.group("prio_l1")
        if prio_l1 != "-":
            entry["priority_l1"] = int(prio_l1)

        prio_l2 = match.group("prio_l2")
        if prio_l2 != "-":
            entry["priority_l2"] = int(prio_l2)

        # Topology counts
        entry["configured_topologies"] = [
            f"adj:{match.group('adj_cfg')}",
            f"adv:{match.group('adv_cfg')}",
        ]
        entry["running_topologies"] = [
            f"adj:{match.group('adj_run')}",
            f"adv:{match.group('adv_run')}",
        ]

        return entry
