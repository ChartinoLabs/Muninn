"""Parser for 'show chassis cluster interfaces' command on Juniper Junos."""

import re
from collections.abc import Callable
from typing import Any, ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ControlInterface(TypedDict):
    """Schema for a control plane interface entry."""

    interface: str
    monitored_status: str
    internal_sa: str


class FabricInterface(TypedDict):
    """Schema for a fabric plane interface entry."""

    child_interface: str
    status_physical: str
    status_monitored: str


class RedundantEthernetInterface(TypedDict):
    """Schema for a redundant-ethernet (reth) interface entry."""

    status: str
    redundancy_group: NotRequired[int]


class RedundantPseudoInterface(TypedDict):
    """Schema for a redundant-pseudo-interface entry."""

    status: str
    redundancy_group: NotRequired[int]


class MonitoredInterface(TypedDict):
    """Schema for an interface monitoring entry."""

    weight: int
    status: str
    redundancy_group: NotRequired[int]


class ShowChassisClusterInterfacesResult(TypedDict):
    """Schema for 'show chassis cluster interfaces' parsed output.

    Captures control/fabric link status and interface details,
    redundant-ethernet interfaces, redundant-pseudo-interfaces,
    and interface monitoring from Juniper SRX cluster devices.
    """

    control_link_status: str
    control_interfaces: dict[str, ControlInterface]
    fabric_link_status: str
    fabric_interfaces: dict[str, FabricInterface]
    redundant_ethernet_interfaces: dict[str, RedundantEthernetInterface]
    redundant_pseudo_interfaces: dict[str, RedundantPseudoInterface]
    monitored_interfaces: dict[str, MonitoredInterface]


@register(OS.JUNIPER_JUNOS, "show chassis cluster interfaces")
class ShowChassisClusterInterfacesParser(
    BaseParser[ShowChassisClusterInterfacesResult],
):
    """Parser for 'show chassis cluster interfaces' on Juniper Junos.

    Parses control/fabric link status, redundancy group interfaces,
    and interface monitoring from SRX cluster output.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.REDUNDANCY})

    _CONTROL_LINK_STATUS = re.compile(
        r"^Control link status:\s+(?P<status>\S+)",
    )
    _FABRIC_LINK_STATUS = re.compile(
        r"^Fabric link status:\s+(?P<status>\S+)",
    )
    _CONTROL_IFACE = re.compile(
        r"^\s+(?P<index>\d+)\s+(?P<interface>\S+)"
        r"\s+(?P<monitored_status>\S+)\s+(?P<internal_sa>\S+)",
    )
    _FABRIC_IFACE = re.compile(
        r"^\s+(?P<name>\S+)\s+(?P<child>\S+)"
        r"\s+(?P<phys>\S+)\s*/\s*(?P<mon>\S+)",
    )
    _RETH_IFACE = re.compile(
        r"^\s+(?P<name>reth\d+)\s+(?P<status>\S+)"
        r"\s+(?P<rg>.+?)\s*$",
    )
    _PSEUDO_IFACE = re.compile(
        r"^\s+(?P<name>\S+)\s+(?P<status>\S+)"
        r"\s+(?P<rg>\d+)\s*$",
    )
    _MONITORING_IFACE = re.compile(
        r"^\s+(?P<interface>\S+)\s+(?P<weight>\d+)"
        r"\s+(?P<status>\S+)(?:\s+(?P<rg>\d+))?\s*$",
    )

    # Section headers mapped to section keys
    _SECTION_HEADERS: ClassVar[tuple[tuple[re.Pattern[str], str], ...]] = (
        (re.compile(r"^Control interfaces:"), "control"),
        (re.compile(r"^Fabric interfaces:"), "fabric"),
        (re.compile(r"^Redundant-ethernet Information:"), "reth"),
        (re.compile(r"^Redundant-pseudo-interface Information:"), "pseudo"),
        (re.compile(r"^Interface Monitoring:"), "monitoring"),
    )

    @classmethod
    def _detect_section(cls, stripped: str) -> str | None:
        """Return section key if line is a section header, else None."""
        for pattern, key in cls._SECTION_HEADERS:
            if pattern.match(stripped):
                return key
        return None

    @classmethod
    def parse(cls, output: str) -> ShowChassisClusterInterfacesResult:
        """Parse 'show chassis cluster interfaces' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed cluster interface information.

        Raises:
            ValueError: If required status fields cannot be parsed.
        """
        control_link_status = ""
        fabric_link_status = ""
        control_interfaces: dict[str, ControlInterface] = {}
        fabric_interfaces: dict[str, FabricInterface] = {}
        reth_interfaces: dict[str, RedundantEthernetInterface] = {}
        pseudo_interfaces: dict[str, RedundantPseudoInterface] = {}
        monitored_interfaces: dict[str, MonitoredInterface] = {}

        # Map section keys to their parse functions and data dicts
        dispatch: dict[str, tuple[Callable[..., Any], dict[str, Any]]] = {
            "control": (cls._parse_control_line, control_interfaces),
            "fabric": (cls._parse_fabric_line, fabric_interfaces),
            "reth": (cls._parse_reth_line, reth_interfaces),
            "pseudo": (cls._parse_pseudo_line, pseudo_interfaces),
            "monitoring": (cls._parse_monitoring_line, monitored_interfaces),
        }

        section = ""

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            # Check for link status lines
            if match := cls._CONTROL_LINK_STATUS.match(stripped):
                control_link_status = match.group("status")
                continue
            if match := cls._FABRIC_LINK_STATUS.match(stripped):
                fabric_link_status = match.group("status")
                continue

            # Check for section transitions
            new_section = cls._detect_section(stripped)
            if new_section is not None:
                section = new_section
                continue

            # Dispatch to section-specific parser
            if section in dispatch:
                handler, data = dispatch[section]
                handler(line, data)

        if not control_link_status:
            msg = "Control link status not found in output"
            raise ValueError(msg)
        if not fabric_link_status:
            msg = "Fabric link status not found in output"
            raise ValueError(msg)

        return ShowChassisClusterInterfacesResult(
            control_link_status=control_link_status,
            control_interfaces=control_interfaces,
            fabric_link_status=fabric_link_status,
            fabric_interfaces=fabric_interfaces,
            redundant_ethernet_interfaces=reth_interfaces,
            redundant_pseudo_interfaces=pseudo_interfaces,
            monitored_interfaces=monitored_interfaces,
        )

    @classmethod
    def _parse_control_line(
        cls,
        line: str,
        result: dict[str, ControlInterface],
    ) -> None:
        """Parse a control interface line into the result dict."""
        if match := cls._CONTROL_IFACE.match(line):
            index = match.group("index")
            result[index] = ControlInterface(
                interface=match.group("interface"),
                monitored_status=match.group("monitored_status"),
                internal_sa=match.group("internal_sa"),
            )

    @classmethod
    def _parse_fabric_line(
        cls,
        line: str,
        result: dict[str, FabricInterface],
    ) -> None:
        """Parse a fabric interface line into the result dict."""
        if match := cls._FABRIC_IFACE.match(line):
            name = match.group("name")
            result[name] = FabricInterface(
                child_interface=match.group("child"),
                status_physical=match.group("phys"),
                status_monitored=match.group("mon"),
            )

    @classmethod
    def _parse_reth_line(
        cls,
        line: str,
        result: dict[str, RedundantEthernetInterface],
    ) -> None:
        """Parse a redundant-ethernet interface line into the result dict."""
        if match := cls._RETH_IFACE.match(line):
            name = match.group("name")
            rg_str = match.group("rg").strip()
            entry = RedundantEthernetInterface(status=match.group("status"))
            if rg_str.isdigit():
                entry["redundancy_group"] = int(rg_str)
            result[name] = entry

    @classmethod
    def _parse_pseudo_line(
        cls,
        line: str,
        result: dict[str, RedundantPseudoInterface],
    ) -> None:
        """Parse a redundant-pseudo-interface line into the result dict."""
        if match := cls._PSEUDO_IFACE.match(line):
            name = match.group("name")
            entry = RedundantPseudoInterface(status=match.group("status"))
            rg_str = match.group("rg")
            entry["redundancy_group"] = int(rg_str)
            result[name] = entry

    @classmethod
    def _parse_monitoring_line(
        cls,
        line: str,
        result: dict[str, MonitoredInterface],
    ) -> None:
        """Parse an interface monitoring line into the result dict."""
        if match := cls._MONITORING_IFACE.match(line):
            interface = match.group("interface")
            entry = MonitoredInterface(
                weight=int(match.group("weight")),
                status=match.group("status"),
            )
            rg = match.group("rg")
            if rg is not None:
                entry["redundancy_group"] = int(rg)
            result[interface] = entry
