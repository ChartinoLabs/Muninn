"""Parser for 'show ospf vrf all interface brief' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_PREFIX
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

_DEFAULT_PROCESS_ID = "default"


class OspfInterfaceEntry(TypedDict):
    """Schema for a single OSPF interface brief entry."""

    pid: int
    area: str
    ip_address_mask: str
    cost: int
    state: str
    neighbors_full: int
    neighbors_count: int


class OspfVrfEntry(TypedDict):
    """Schema for interfaces within a VRF."""

    interfaces: dict[str, OspfInterfaceEntry]


class ShowOspfVrfAllInterfaceBriefResult(TypedDict):
    """Schema for 'show ospf vrf all interface brief' parsed output.

    Keyed by OSPF process ID, then VRF name, then interface name.
    """

    processes: dict[str, dict[str, OspfVrfEntry]]


# Section header: "Interfaces for OSPF <process_id>, VRF <vrf_name>"
_SECTION_PATTERN = re.compile(
    r"^Interfaces for OSPF\s+(?P<process_id>\S+)"
    r"(?:,\s*VRF\s+(?P<vrf>\S+))?\s*$"
)

# Interface row:
# Interface  PID  Area  IP Address/Mask  Cost  State  Nbrs F/C
# BE1.10     1    0     192.0.2.1/30     1     DR     1/1
_INTERFACE_PATTERN = re.compile(
    r"^(?P<interface>\S+)\s+"
    r"(?P<pid>\d+)\s+"
    r"(?P<area>\S+)\s+"
    rf"(?P<ip_address_mask>{IPV4_PREFIX})\s+"
    r"(?P<cost>\d+)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<nbrs_full>\d+)/(?P<nbrs_count>\d+)\s*$"
)


@register(OS.CISCO_IOSXR, "show ospf vrf all interface brief")
class ShowOspfVrfAllInterfaceBriefParser(
    BaseParser["ShowOspfVrfAllInterfaceBriefResult"],
):
    """Parser for 'show ospf vrf all interface brief' on IOS-XR.

    Parses OSPF interface summary information grouped by process and VRF.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.OSPF,
            ParserTag.ROUTING,
            ParserTag.VRF,
        }
    )

    @classmethod
    def parse(cls, output: str) -> "ShowOspfVrfAllInterfaceBriefResult":
        """Parse 'show ospf vrf all interface brief' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface data grouped by OSPF process, VRF, and interface.

        Raises:
            ValueError: If no OSPF interface data found in output.
        """
        processes: dict[str, dict[str, OspfVrfEntry]] = {}
        current_process_id: str | None = None
        current_vrf: str | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            section_result = cls._try_section(stripped, processes)
            if section_result is not None:
                current_process_id, current_vrf = section_result
                continue

            if current_process_id is not None and current_vrf is not None:
                cls._try_interface(stripped, processes, current_process_id, current_vrf)

        if not processes:
            msg = "No OSPF interface data found in output"
            raise ValueError(msg)

        return cast("ShowOspfVrfAllInterfaceBriefResult", {"processes": processes})

    @staticmethod
    def _try_section(
        stripped: str,
        processes: dict[str, dict[str, OspfVrfEntry]],
    ) -> tuple[str, str] | None:
        """Try to parse a section header line.

        Returns:
            (process_id, vrf) tuple if matched, None otherwise.
        """
        match = _SECTION_PATTERN.match(stripped)
        if match is None:
            return None

        process_id = match.group("process_id") or _DEFAULT_PROCESS_ID
        vrf = match.group("vrf") or "default"
        processes.setdefault(process_id, {}).setdefault(vrf, {"interfaces": {}})
        return process_id, vrf

    @staticmethod
    def _try_interface(
        stripped: str,
        processes: dict[str, dict[str, OspfVrfEntry]],
        process_id: str,
        vrf: str,
    ) -> None:
        """Try to parse an interface row and add it to the results."""
        match = _INTERFACE_PATTERN.match(stripped)
        if match is None:
            return

        interface = canonical_interface_name(
            match.group("interface"),
            os=OS.CISCO_IOSXR,
        )
        entry: OspfInterfaceEntry = {
            "pid": int(match.group("pid")),
            "area": match.group("area"),
            "ip_address_mask": match.group("ip_address_mask"),
            "cost": int(match.group("cost")),
            "state": match.group("state"),
            "neighbors_full": int(match.group("nbrs_full")),
            "neighbors_count": int(match.group("nbrs_count")),
        }
        processes[process_id][vrf]["interfaces"][interface] = entry
