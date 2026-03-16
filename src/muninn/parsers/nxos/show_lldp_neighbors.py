"""Parser for 'show lldp neighbors' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class LldpNeighborEntry(TypedDict):
    """Schema for a single LLDP neighbor entry."""

    hold_time: int
    port_id: str
    capabilities: NotRequired[str]


class ShowLldpNeighborsResult(TypedDict):
    """Schema for 'show lldp neighbors' parsed output."""

    neighbors: dict[str, dict[str, LldpNeighborEntry]]
    total_entries: NotRequired[int]


@register(OS.CISCO_NXOS, "show lldp neighbors")
class ShowLldpNeighborsParser(BaseParser[ShowLldpNeighborsResult]):
    """Parser for 'show lldp neighbors' command on NX-OS."""

    tags: ClassVar[frozenset[str]] = frozenset({"lldp"})

    _LOCAL_INTF = r"(?:Eth|mgmt|Gi|Te|Fo|Po|Lo|Vlan|Tu|Se|nve)\S*"
    _SUMMARY_PATTERN = re.compile(
        rf"^(?P<device_id>.+?)\s+"
        rf"(?P<local_intf>{_LOCAL_INTF})\s+"
        r"(?P<hold_time>\d+)\s+"
        r"(?:(?P<capability>[A-Za-z,]+)\s+)?"
        r"(?P<port_id>\S+)$"
    )
    _WRAPPED_DEVICE_PATTERN = re.compile(r"^(?P<device_id>\S.*\S|\S)$")
    _WRAPPED_CONTINUATION_PATTERN = re.compile(
        rf"^\s+(?P<local_intf>{_LOCAL_INTF})\s+"
        r"(?P<hold_time>\d+)\s+"
        r"(?:(?P<capability>[A-Za-z,]+)\s+)?"
        r"(?P<port_id>\S+)\s*$"
    )
    _TOTAL_PATTERN = re.compile(r"^Total entries displayed:\s*(?P<total>\d+)\s*$", re.I)

    _DETAIL_PORT_ID_PATTERN = re.compile(r"^Port\s+id:\s*(?P<value>.+?)\s*$", re.I)
    _DETAIL_LOCAL_PORT_PATTERN = re.compile(
        r"^Local\s+Port\s+id:\s*(?P<value>.+?)\s*$", re.I
    )
    _DETAIL_SYSTEM_NAME_PATTERN = re.compile(
        r"^System\s+Name:\s*(?P<value>.+?)\s*$", re.I
    )
    _DETAIL_TIME_PATTERN = re.compile(
        r"^Time\s+remaining:\s*(?P<value>\d+)\s+seconds\s*$", re.I
    )
    _DETAIL_ENABLED_CAP_PATTERN = re.compile(
        r"^Enabled\s+Capabilities:\s*(?P<value>.+?)\s*$", re.I
    )
    _DETAIL_CHASSIS_PATTERN = re.compile(r"^Chassis\s+id:\s*(?P<value>.+?)\s*$", re.I)

    _INTERFACE_PATTERN = re.compile(
        r"^(?:Gi(?:g(?:abit)?)?|Fa(?:s(?:t)?)?|Eth(?:ernet)?|Te(?:n)?|Fo(?:r(?:ty)?)?|"
        r"Hu(?:n(?:dred)?)?|mgmt|Lo|Vlan|Po|Tu|Se|nve)(?:Ethernet)?\d",
        re.IGNORECASE,
    )

    @classmethod
    def _normalize_port_id(cls, port_id: str) -> str:
        if cls._INTERFACE_PATTERN.match(port_id):
            lowered = port_id.lower()
            if lowered.startswith("ethernet"):
                port_id = "Eth" + port_id[8:]
            return canonical_interface_name(port_id, os=OS.CISCO_NXOS)
        return port_id

    @classmethod
    def _normalize_capabilities(cls, cap_str: str | None) -> str | None:
        if not cap_str:
            return None
        cap = cap_str.strip()
        if not cap or cap.lower() == "not advertised":
            return None
        if "," in cap:
            return "".join(part.strip() for part in cap.split(",") if part.strip())
        return cap

    @classmethod
    def _is_skippable_line(cls, line: str) -> bool:
        stripped = line.strip()
        if not stripped:
            return True
        if stripped.startswith("Capability codes:"):
            return True
        if stripped.startswith("Device ID"):
            return True
        if stripped.startswith("("):
            return True
        return "# show lldp neighbor" in stripped.lower()

    @classmethod
    def _add_neighbor(
        cls,
        neighbors: dict[str, dict[str, LldpNeighborEntry]],
        local_intf: str,
        device_id: str,
        entry: LldpNeighborEntry,
    ) -> None:
        if local_intf not in neighbors:
            neighbors[local_intf] = {}
        neighbors[local_intf][device_id] = entry

    @classmethod
    def _build_entry(
        cls,
        hold_time: int,
        port_id: str,
        capabilities: str | None,
    ) -> LldpNeighborEntry:
        entry: LldpNeighborEntry = {
            "hold_time": hold_time,
            "port_id": cls._normalize_port_id(port_id),
        }
        capability = cls._normalize_capabilities(capabilities)
        if capability:
            entry["capabilities"] = capability
        return entry

    @classmethod
    def _parse_summary_line(
        cls,
        stripped: str,
        neighbors: dict[str, dict[str, LldpNeighborEntry]],
    ) -> bool:
        match = cls._SUMMARY_PATTERN.match(stripped)
        if not match:
            return False

        local_intf = canonical_interface_name(
            match.group("local_intf"), os=OS.CISCO_NXOS
        )
        device_id = match.group("device_id").strip()
        entry = cls._build_entry(
            hold_time=int(match.group("hold_time")),
            port_id=match.group("port_id"),
            capabilities=match.group("capability"),
        )
        cls._add_neighbor(neighbors, local_intf, device_id, entry)
        return True

    @classmethod
    def _parse_wrapped_continuation_line(
        cls,
        line: str,
        pending_device_id: str | None,
        neighbors: dict[str, dict[str, LldpNeighborEntry]],
    ) -> bool:
        if not pending_device_id:
            return False

        match = cls._WRAPPED_CONTINUATION_PATTERN.match(line)
        if not match:
            return False

        local_intf = canonical_interface_name(
            match.group("local_intf"), os=OS.CISCO_NXOS
        )
        entry = cls._build_entry(
            hold_time=int(match.group("hold_time")),
            port_id=match.group("port_id"),
            capabilities=match.group("capability"),
        )
        cls._add_neighbor(neighbors, local_intf, pending_device_id, entry)
        return True

    @classmethod
    def _new_detail_state(cls) -> dict[str, str | int | None]:
        return {
            "chassis_id": None,
            "system_name": None,
            "local_port": None,
            "port_id": None,
            "hold_time": None,
            "capabilities": None,
        }

    @classmethod
    def _flush_detail_entry(
        cls,
        detail_state: dict[str, str | int | None],
        neighbors: dict[str, dict[str, LldpNeighborEntry]],
    ) -> None:
        local_port = detail_state["local_port"]
        port_id = detail_state["port_id"]
        hold_time = detail_state["hold_time"]
        if (
            isinstance(local_port, str)
            and isinstance(port_id, str)
            and isinstance(hold_time, int)
        ):
            device_id = detail_state["system_name"] or detail_state["chassis_id"]
            if isinstance(device_id, str) and device_id.lower() != "not advertised":
                local_intf = canonical_interface_name(local_port, os=OS.CISCO_NXOS)
                entry = cls._build_entry(
                    hold_time=hold_time,
                    port_id=port_id,
                    capabilities=(
                        detail_state["capabilities"]
                        if isinstance(detail_state["capabilities"], str)
                        else None
                    ),
                )
                cls._add_neighbor(neighbors, local_intf, device_id, entry)

        detail_state["chassis_id"] = None
        detail_state["system_name"] = None
        detail_state["local_port"] = None
        detail_state["port_id"] = None
        detail_state["hold_time"] = None
        detail_state["capabilities"] = None

    @classmethod
    def _consume_detail_line(
        cls,
        stripped: str,
        detail_state: dict[str, str | int | None],
        neighbors: dict[str, dict[str, LldpNeighborEntry]],
    ) -> bool:
        chassis_match = cls._DETAIL_CHASSIS_PATTERN.match(stripped)
        if chassis_match:
            cls._flush_detail_entry(detail_state, neighbors)
            detail_state["chassis_id"] = chassis_match.group("value")
            return True

        local_port_match = cls._DETAIL_LOCAL_PORT_PATTERN.match(stripped)
        if local_port_match:
            detail_state["local_port"] = local_port_match.group("value")
            return True

        port_id_match = cls._DETAIL_PORT_ID_PATTERN.match(stripped)
        if port_id_match:
            detail_state["port_id"] = port_id_match.group("value")
            return True

        system_name_match = cls._DETAIL_SYSTEM_NAME_PATTERN.match(stripped)
        if system_name_match:
            detail_state["system_name"] = system_name_match.group("value")
            return True

        time_match = cls._DETAIL_TIME_PATTERN.match(stripped)
        if time_match:
            detail_state["hold_time"] = int(time_match.group("value"))
            return True

        enabled_cap_match = cls._DETAIL_ENABLED_CAP_PATTERN.match(stripped)
        if enabled_cap_match:
            detail_state["capabilities"] = enabled_cap_match.group("value")
            return True

        return False

    @classmethod
    def _process_line(
        cls,
        line: str,
        stripped: str,
        pending_device_id: str | None,
        detail_state: dict[str, str | int | None],
        neighbors: dict[str, dict[str, LldpNeighborEntry]],
    ) -> tuple[int | None, str | None]:
        """Process a single line of output.

        Returns a tuple of (total_entries_if_found, updated_pending_device_id).
        total_entries_if_found is an int when the total line is matched, else None.
        """
        total_match = cls._TOTAL_PATTERN.match(stripped)
        if total_match:
            cls._flush_detail_entry(detail_state, neighbors)
            return int(total_match.group("total")), None

        if cls._parse_wrapped_continuation_line(line, pending_device_id, neighbors):
            return None, None

        if cls._parse_summary_line(stripped, neighbors):
            return None, None

        if cls._consume_detail_line(stripped, detail_state, neighbors):
            return None, pending_device_id

        device_only_match = cls._WRAPPED_DEVICE_PATTERN.match(stripped)
        if device_only_match and stripped.lower() != "show lldp neighbors detail":
            return None, device_only_match.group("device_id")

        return None, pending_device_id

    @classmethod
    def parse(cls, output: str) -> ShowLldpNeighborsResult:
        """Parse 'show lldp neighbors' output on NX-OS."""
        neighbors: dict[str, dict[str, LldpNeighborEntry]] = {}
        total_entries: int | None = None
        pending_device_id: str | None = None
        detail_state = cls._new_detail_state()

        for line in output.splitlines():
            if cls._is_skippable_line(line):
                continue

            stripped = line.strip()
            found_total, pending_device_id = cls._process_line(
                line, stripped, pending_device_id, detail_state, neighbors
            )
            if found_total is not None:
                total_entries = found_total

        cls._flush_detail_entry(detail_state, neighbors)

        if not neighbors:
            msg = "No LLDP neighbors found in output"
            raise ValueError(msg)

        result: ShowLldpNeighborsResult = {"neighbors": neighbors}
        if total_entries is not None:
            result["total_entries"] = total_entries
        return result
