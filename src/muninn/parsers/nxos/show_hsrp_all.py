"""Parser for 'show hsrp all' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class PreemptionDelay(TypedDict):
    """Schema for HSRP preemption delay values."""

    reload: NotRequired[int]
    minimum: NotRequired[int]
    sync: NotRequired[int]


class StandbyRouter(TypedDict):
    """Schema for HSRP standby router info."""

    address: str
    priority: NotRequired[int]


class ActiveRouter(TypedDict):
    """Schema for HSRP active router info."""

    address: str
    priority: NotRequired[int]


class HsrpGroupEntry(TypedDict):
    """Schema for a single HSRP group entry."""

    interface: str
    group: int
    version: int
    address_family: str
    local_state: str
    priority: int
    configured_priority: int
    preempt: bool
    forwarding_threshold_lower: int
    forwarding_threshold_upper: int
    preemption_delay: NotRequired[PreemptionDelay]
    hellotime: int
    holdtime: int
    virtual_ip: str
    secondary_virtual_ips: NotRequired[list[str]]
    active_router: ActiveRouter
    standby_router: StandbyRouter
    authentication_type: NotRequired[str]
    authentication_value: NotRequired[str]
    virtual_mac_address: str
    state_changes: int
    last_state_change: str
    ip_redundancy_name: str


class ShowHsrpAllResult(TypedDict):
    """Schema for 'show hsrp all' parsed output."""

    groups: dict[str, HsrpGroupEntry]


@register(OS.CISCO_NXOS, "show hsrp all")
class ShowHsrpAllParser(BaseParser[ShowHsrpAllResult]):
    """Parser for 'show hsrp all' command on NX-OS.

    Parses operational HSRP state including group priorities, virtual IPs,
    active/standby routers, authentication, and timers.
    """

    tags: ClassVar[frozenset[str]] = frozenset({"fhrp"})

    # Vlan100 - Group 100 (HSRP-V2) (IPv4)
    _HEADER_PATTERN = re.compile(
        r"^(?P<interface>\S+)\s+-\s+Group\s+(?P<group>\d+)\s+"
        r"\(HSRP-V(?P<version>\d+)\)\s+\((?P<af>\S+)\)"
    )

    # Local state is Active, priority 250 (Cfged 250), may preempt
    _STATE_PATTERN = re.compile(
        r"Local state is (?P<state>.+?),\s+priority\s+(?P<priority>\d+)\s+"
        r"\(Cfged\s+(?P<cfged_priority>\d+)\)"
        r"(?P<preempt>,\s+may preempt)?"
    )

    # Forwarding threshold(for vPC), lower: 1 upper: 250
    _THRESHOLD_PATTERN = re.compile(
        r"Forwarding threshold\(for vPC\),\s+lower:\s+(?P<lower>\d+)\s+"
        r"upper:\s+(?P<upper>\d+)"
    )

    # Preemption Delay (Seconds) Reload:120 Minimum:60 Sync:60
    _PREEMPTION_DELAY_PATTERN = re.compile(
        r"Preemption Delay \(Seconds\)\s+(?P<delays>.+)"
    )
    _DELAY_VALUE_PATTERN = re.compile(r"(?P<key>Reload|Minimum|Sync):(?P<value>\d+)")

    # Hellotime 3 sec, holdtime 10 sec
    _TIMER_PATTERN = re.compile(
        r"Hellotime\s+(?P<hello>\d+)\s+sec,\s+holdtime\s+(?P<hold>\d+)\s+sec"
    )

    # Virtual IP address is 192.168.100.1 (Cfged)
    _VIP_PATTERN = re.compile(r"Virtual IP address is (?P<vip>\S+)")

    # Secondary Virtual IP address is 192.168.100.193
    _SECONDARY_VIP_INLINE_PATTERN = re.compile(
        r"Secondary Virtual IP address is (?P<vip>\S+)"
    )

    # Active router is local
    # Active router is 172.17.1.2, priority 150 expires in 0.661000 sec(s)
    _ACTIVE_ROUTER_PATTERN = re.compile(
        r"Active router is (?P<address>\S+?)\s*"
        r"(?:,\s*priority\s+(?P<priority>\d+)\s+expires in .+)?$"
    )

    # Standby router is 192.168.100.69 , priority 200 expires in 10.174000 sec(s)
    # Standby router is local
    _STANDBY_ROUTER_PATTERN = re.compile(
        r"Standby router is (?P<address>\S+?)\s*"
        r"(?:,\s*priority\s+(?P<priority>\d+)\s+expires in .+)?$"
    )

    # Authentication MD5, key-string "dr-hsrp"
    # Authentication MD5, key-chain HSRP-AUTH
    # Authentication text "cisco"
    _AUTH_PATTERN = re.compile(
        r"Authentication\s+(?P<type>\S+?)(?:,\s+(?P<method>key-string|key-chain)\s+"
        r'(?:"(?P<quoted_value>[^"]+)"|(?P<plain_value>\S+))|\s+"(?P<text_value>[^"]+)")'
    )

    # Virtual mac address is 0000.0c9f.f384 (Default MAC)
    _VMAC_PATTERN = re.compile(r"Virtual mac address is (?P<vmac>\S+)")

    # 2 state changes, last state change 1y27w
    _STATE_CHANGES_PATTERN = re.compile(
        r"(?P<changes>\d+) state changes?, last state change (?P<last>.+)"
    )

    # IP redundancy name is hsrp-Vlan100-100 (default)
    _REDUNDANCY_NAME_PATTERN = re.compile(r"IP redundancy name is (?P<name>\S+)")

    # Secondary VIP listed under "Secondary VIP(s):" section
    _SECONDARY_VIP_LIST_PATTERN = re.compile(
        r"^\s+(?P<vip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*$"
    )

    @classmethod
    def _new_entry(cls, match: re.Match[str]) -> HsrpGroupEntry:
        """Create a new HSRP group entry from a header match."""
        return HsrpGroupEntry(
            interface=match.group("interface"),
            group=int(match.group("group")),
            version=int(match.group("version")),
            address_family=match.group("af"),
            local_state="",
            priority=0,
            configured_priority=0,
            preempt=False,
            forwarding_threshold_lower=0,
            forwarding_threshold_upper=0,
            hellotime=0,
            holdtime=0,
            virtual_ip="",
            active_router=ActiveRouter(address=""),
            standby_router=StandbyRouter(address=""),
            virtual_mac_address="",
            state_changes=0,
            last_state_change="",
            ip_redundancy_name="",
        )

    @classmethod
    def _parse_router(cls, match: re.Match[str]) -> ActiveRouter | StandbyRouter:
        """Parse an active or standby router match into a typed dict."""
        result: ActiveRouter = {"address": match.group("address")}
        if match.group("priority"):
            result["priority"] = int(match.group("priority"))
        return result

    @classmethod
    def _parse_preemption_delay(cls, delays_str: str) -> PreemptionDelay:
        """Parse preemption delay key-value pairs."""
        delay_values: PreemptionDelay = {}
        for dv_match in cls._DELAY_VALUE_PATTERN.finditer(delays_str):
            key = dv_match.group("key").lower()
            value = int(dv_match.group("value"))
            if key == "reload":
                delay_values["reload"] = value
            elif key == "minimum":
                delay_values["minimum"] = value
            elif key == "sync":
                delay_values["sync"] = value
        return delay_values

    @classmethod
    def _parse_authentication(cls, match: re.Match[str]) -> tuple[str, str]:
        """Parse authentication type and value from a match.

        Returns:
            Tuple of (auth_type, auth_value).
        """
        auth_type = match.group("type")
        if auth_type.lower() == "text":
            return "text", match.group("text_value")
        method = match.group("method")
        value = match.group("quoted_value") or match.group("plain_value")
        return f"{auth_type}, {method}", value

    @classmethod
    def _add_secondary_vip(cls, entry: HsrpGroupEntry, vip: str) -> None:
        """Add a secondary VIP to the entry, avoiding duplicates."""
        if "secondary_virtual_ips" not in entry:
            entry["secondary_virtual_ips"] = []
        if vip not in entry["secondary_virtual_ips"]:
            entry["secondary_virtual_ips"].append(vip)

    @classmethod
    def _parse_line(cls, stripped: str, entry: HsrpGroupEntry) -> bool:
        """Parse a single line and update the entry. Returns True if matched."""
        state_match = cls._STATE_PATTERN.search(stripped)
        if state_match:
            entry["local_state"] = state_match.group("state")
            entry["priority"] = int(state_match.group("priority"))
            entry["configured_priority"] = int(state_match.group("cfged_priority"))
            entry["preempt"] = state_match.group("preempt") is not None
            return True

        threshold_match = cls._THRESHOLD_PATTERN.search(stripped)
        if threshold_match:
            entry["forwarding_threshold_lower"] = int(threshold_match.group("lower"))
            entry["forwarding_threshold_upper"] = int(threshold_match.group("upper"))
            return True

        preempt_match = cls._PREEMPTION_DELAY_PATTERN.search(stripped)
        if preempt_match:
            delay_values = cls._parse_preemption_delay(preempt_match.group("delays"))
            if delay_values:
                entry["preemption_delay"] = delay_values
            return True

        timer_match = cls._TIMER_PATTERN.search(stripped)
        if timer_match:
            entry["hellotime"] = int(timer_match.group("hello"))
            entry["holdtime"] = int(timer_match.group("hold"))
            return True

        return False

    @classmethod
    def _parse_vip_and_router_line(cls, stripped: str, entry: HsrpGroupEntry) -> bool:
        """Parse VIP and router lines. Returns True if matched."""
        sec_vip_match = cls._SECONDARY_VIP_INLINE_PATTERN.search(stripped)
        if sec_vip_match:
            cls._add_secondary_vip(entry, sec_vip_match.group("vip"))
            return True

        if "Secondary" not in stripped:
            vip_match = cls._VIP_PATTERN.search(stripped)
            if vip_match:
                entry["virtual_ip"] = vip_match.group("vip")
                return True

        if stripped.startswith("Active router"):
            active_match = cls._ACTIVE_ROUTER_PATTERN.search(stripped)
            if active_match:
                entry["active_router"] = cls._parse_router(active_match)
                return True

        if stripped.startswith("Standby router"):
            standby_match = cls._STANDBY_ROUTER_PATTERN.search(stripped)
            if standby_match:
                entry["standby_router"] = cls._parse_router(standby_match)
                return True

        return False

    @classmethod
    def _parse_metadata_line(cls, stripped: str, entry: HsrpGroupEntry) -> bool:
        """Parse auth, MAC, state changes, and redundancy name.

        Returns True if matched.
        """
        auth_match = cls._AUTH_PATTERN.search(stripped)
        if auth_match:
            auth_type, auth_value = cls._parse_authentication(auth_match)
            entry["authentication_type"] = auth_type
            entry["authentication_value"] = auth_value
            return True

        vmac_match = cls._VMAC_PATTERN.search(stripped)
        if vmac_match:
            entry["virtual_mac_address"] = vmac_match.group("vmac")
            return True

        sc_match = cls._STATE_CHANGES_PATTERN.search(stripped)
        if sc_match:
            entry["state_changes"] = int(sc_match.group("changes"))
            entry["last_state_change"] = sc_match.group("last")
            return True

        rn_match = cls._REDUNDANCY_NAME_PATTERN.search(stripped)
        if rn_match:
            entry["ip_redundancy_name"] = rn_match.group("name")
            return True

        return False

    @classmethod
    def _parse_entry_line(
        cls,
        stripped: str,
        entry: HsrpGroupEntry,
    ) -> None:
        """Dispatch a stripped line to the appropriate sub-parser."""
        if cls._parse_line(stripped, entry):
            return
        if cls._parse_vip_and_router_line(stripped, entry):
            return
        cls._parse_metadata_line(stripped, entry)

    @classmethod
    def parse(cls, output: str) -> ShowHsrpAllResult:
        """Parse 'show hsrp all' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed HSRP groups keyed by 'Interface/Group'.

        Raises:
            ValueError: If no HSRP groups found in output.
        """
        groups: dict[str, HsrpGroupEntry] = {}
        current_entry: HsrpGroupEntry | None = None
        in_secondary_vip_section = False

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                in_secondary_vip_section = False
                continue

            header_match = cls._HEADER_PATTERN.match(stripped)
            if header_match:
                in_secondary_vip_section = False
                current_entry = cls._new_entry(header_match)
                intf = header_match.group("interface")
                grp = header_match.group("group")
                groups[f"{intf}/{grp}"] = current_entry
                continue

            if current_entry is None:
                continue

            if in_secondary_vip_section:
                vip_match = cls._SECONDARY_VIP_LIST_PATTERN.match(line)
                if vip_match:
                    cls._add_secondary_vip(current_entry, vip_match.group("vip"))
                    continue
                in_secondary_vip_section = False

            if stripped.startswith("Secondary VIP(s):"):
                in_secondary_vip_section = True
                continue

            cls._parse_entry_line(stripped, current_entry)

        if not groups:
            msg = "No HSRP groups found in output"
            raise ValueError(msg)

        return ShowHsrpAllResult(groups=groups)
