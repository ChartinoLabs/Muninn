"""Parser for 'show high-availability all' command on Palo Alto PAN-OS."""

import re
from collections.abc import Callable, Mapping
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class HAElectionOptions(TypedDict):
    """Election option fields for an HA peer."""

    priority: int
    preemptive: bool
    promotion_hold_interval_ms: NotRequired[int]
    hello_interval_ms: NotRequired[int]
    heartbeat_interval_ms: NotRequired[int]
    max_flaps: NotRequired[int]
    preemption_hold_interval: NotRequired[str]
    monitor_fail_hold_up_interval_ms: NotRequired[int]
    addon_master_hold_up_interval_ms: NotRequired[int]


class HAControlLink(TypedDict):
    """HA1 control link information."""

    ip_address: NotRequired[str]
    mac_address: NotRequired[str]
    interface: NotRequired[str]
    link_state: NotRequired[str]
    key_imported: NotRequired[bool]
    connection: NotRequired[str]


class HADataLink(TypedDict):
    """HA2 data link information."""

    ip_address: NotRequired[str]
    mac_address: NotRequired[str]
    interface: NotRequired[str]
    link_state: NotRequired[str]
    connection: NotRequired[str]


class HAVersionInfo(TypedDict):
    """Software and content version information."""

    build_release: NotRequired[str]
    url_database: NotRequired[str]
    application_content: NotRequired[str]
    anti_virus: NotRequired[str]
    threat_content: NotRequired[str]
    vpn_client_software: NotRequired[str]
    global_protect_client_software: NotRequired[str]


class HAVersionCompatibility(TypedDict):
    """Version compatibility status between local and peer."""

    software_version: NotRequired[str]
    application_content: NotRequired[str]
    anti_virus: NotRequired[str]
    threat_content: NotRequired[str]
    vpn_client_software: NotRequired[str]
    global_protect_client_software: NotRequired[str]


class HA1JointConfig(TypedDict):
    """HA1 control links joint configuration shared by local and peer."""

    link_monitor_interval_ms: NotRequired[int]
    encryption_enabled: NotRequired[bool]


class HALocalInfo(TypedDict):
    """Local HA peer information.

    All fields are ``NotRequired`` because each is populated only when its
    corresponding line appears in the device output; the parser does not
    synthesize defaults for missing lines.
    """

    version: NotRequired[int]
    mode: NotRequired[str]
    state: NotRequired[str]
    state_duration: NotRequired[str]
    model: NotRequired[str]
    mgmt_ipv4: NotRequired[str]
    ha1_control_link: NotRequired[HAControlLink]
    ha2_data_link: NotRequired[HADataLink]
    election_options: NotRequired[HAElectionOptions]
    passive_link_state: NotRequired[str]
    monitor_fail_hold_down_interval: NotRequired[str]
    version_info: NotRequired[HAVersionInfo]
    state_sync: NotRequired[str]
    state_sync_type: NotRequired[str]
    ha1_joint_config: NotRequired[HA1JointConfig]
    version_compatibility: NotRequired[HAVersionCompatibility]


class HAPeerInfo(TypedDict):
    """Peer HA information.

    All fields are ``NotRequired`` because each is populated only when its
    corresponding line appears in the device output; the parser does not
    synthesize defaults for missing lines.
    """

    connection_status: NotRequired[str]
    version: NotRequired[int]
    mode: NotRequired[str]
    state: NotRequired[str]
    state_duration: NotRequired[str]
    model: NotRequired[str]
    mgmt_ipv4: NotRequired[str]
    ha1_control_link: NotRequired[HAControlLink]
    ha2_data_link: NotRequired[HADataLink]
    election_options: NotRequired[HAElectionOptions]
    version_info: NotRequired[HAVersionInfo]


class HALinkMonitoring(TypedDict):
    """Link monitoring configuration."""

    enabled: NotRequired[bool]
    failure_condition: NotRequired[str]
    interfaces: NotRequired[dict[str, str]]


class HAPathMonitoring(TypedDict):
    """Path monitoring configuration."""

    enabled: NotRequired[bool]
    failure_condition: NotRequired[str]


class HAConfigSync(TypedDict):
    """Configuration synchronization status."""

    enabled: NotRequired[bool]
    running_config: NotRequired[str]


class ShowHighAvailabilityAllResult(TypedDict):
    """Schema for 'show high-availability all' parsed output."""

    group_id: int
    mode: str
    local: HALocalInfo
    peer: HAPeerInfo
    link_monitoring: NotRequired[HALinkMonitoring]
    path_monitoring: NotRequired[HAPathMonitoring]
    config_sync: NotRequired[HAConfigSync]


# --- Regex patterns ---

_GROUP_LINE = re.compile(r"^Group\s+(\d+):")
_MODE_LINE = re.compile(r"^\s+Mode:\s+(.+)$")
_STATE_LINE = re.compile(r"^\s+State:\s+(\S+)(?:\s+\(last\s+(.+?)\))?$")
_VERSION_NUM = re.compile(r"^\s+Version:\s+(\d+)$")
_CONNECTION_STATUS = re.compile(r"^\s+Connection status:\s+(\S+)$")
_MODEL = re.compile(r"^\s+Model:\s+(.+)$")
_MGMT_IPV4 = re.compile(r"^\s+Management IPv4 Address:\s+(\S+)")
_IP_ADDR = re.compile(r"^\s+IP Address:\s+(\S+)")
_MAC_ADDR = re.compile(r"^\s+MAC Address:\s+(\S+)")
_INTERFACE_RE = re.compile(r"^\s+Interface:\s+(\S+)")
_LINK_STATE = re.compile(r"^\s+Link State:\s+(.+)$")
_PRIORITY = re.compile(r"^\s+Priority:\s+(\d+)$")
_PREEMPTIVE = re.compile(r"^\s+Preemptive:\s+(\S+)$")
_MS_VALUE = re.compile(r"(\d+)\s+ms$")
_PASSIVE_LINK = re.compile(r"^\s+Passive Link State:\s+(\S+)$")
_MONITOR_FAIL_DOWN = re.compile(
    r"^\s+Monitor Fail Hold Down Interval:\s+(.+)$",
)
_MAX_FLAPS = re.compile(r"^\s+Max # of Flaps:\s+(\d+)$")
_PREEMPTION_HOLD = re.compile(r"^\s+Preemption Hold Interval:\s+(.+)$")
_ENABLED_RE = re.compile(r"^\s+Enabled:\s+(\S+)$")
_FAILURE_CONDITION = re.compile(r"^\s+Failure condition:\s+(\S+)$")
_INTERFACE_STATUS = re.compile(r"^\s+Interface\s+(\S+):\s+(\S+)$")
_STATE_SYNC = re.compile(
    r"^\s+State Synchronization:\s+(\S+)(?:;\s+type:\s+(\S+))?$",
)
_BUILD_RELEASE = re.compile(r"^\s+Build Release:\s+(.+)$")
_URL_DB = re.compile(r"^\s+URL Database:\s+(.+)$")
_APP_CONTENT = re.compile(r"^\s+Application Content:\s+(.+)$")
_ANTI_VIRUS = re.compile(r"^\s+Anti-Virus:\s+(.+)$")
_THREAT_CONTENT = re.compile(r"^\s+Threat Content:\s+(.+)$")
_VPN_CLIENT = re.compile(r"^\s+VPN Client Software:\s+(.+)$")
_GP_CLIENT = re.compile(r"^\s+Global Protect Client Software:\s+(.+)$")
_RUNNING_CONFIG = re.compile(r"^\s+Running Configuration:\s+(.+)$")
_PROMO_HOLD = re.compile(r"^\s+Promotion Hold Interval:\s+(.+)$")
_HELLO_INTERVAL = re.compile(r"^\s+Hello Message Interval:\s+(.+)$")
_HEARTBEAT_INTERVAL = re.compile(r"^\s+Heartbeat Ping Interval:\s+(.+)$")
_MON_FAIL_UP = re.compile(r"^\s+Monitor Fail Hold Up Interval:\s+(.+)$")
_ADDON_HOLD = re.compile(r"^\s+Addon Master Hold Up Interval:\s+(.+)$")
_LINK_MONITOR_INTERVAL = re.compile(r"^\s+Link Monitor Interval:\s+(.+)$")
_ENCRYPTION_ENABLED = re.compile(r"^\s+Encryption Enabled:\s+(\S+)$")
_KEY_IMPORTED = re.compile(r"^\s+Key Imported\s*:\s*(\S+)$")
_CONNECTION_FREEFORM = re.compile(r"^\s+Connection\s+(.+)$")

# Version compatibility lines: "<Field> Compatibility: <Match|Mismatch>"
_COMPAT_LINE = re.compile(r"^\s+(.+?)\s+Compatibility:\s+(\S+)$")
# Version compatibility line for the Software Version row (no "Compatibility:")
_SOFTWARE_VERSION_LINE = re.compile(r"^\s+Software Version:\s+(\S+)$")

# Map between version compatibility human label and TypedDict key.
_COMPAT_LABEL_TO_KEY: dict[str, str] = {
    "Application Content": "application_content",
    "Anti-Virus": "anti_virus",
    "Threat Content": "threat_content",
    "VPN Client Software": "vpn_client_software",
    "Global Protect Client Software": "global_protect_client_software",
}

# Section tracking constants
_SECTION_NONE = "none"
_SECTION_LOCAL = "local"
_SECTION_PEER = "peer"
_SECTION_LINK_MON = "link_mon"
_SECTION_PATH_MON = "path_mon"
_SECTION_CONFIG_SYNC = "config_sync"

# Sub-section tracking constants
_SUB_NONE = "none"
_SUB_DEVICE = "device"
_SUB_HA1 = "ha1"
_SUB_HA2 = "ha2"
_SUB_ELECTION = "election"
_SUB_AP_MODE = "ap_mode"
_SUB_VERSION = "version"
_SUB_COMPAT = "compat"
_SUB_GROUP_LINK = "group_link"
_SUB_HA1_JOINT = "ha1_joint"

# Major section header -> section constant
_SECTION_HEADERS: dict[str, str] = {
    "Local Information:": _SECTION_LOCAL,
    "Peer Information:": _SECTION_PEER,
    "Link Monitoring Information:": _SECTION_LINK_MON,
    "Path Monitoring Information:": _SECTION_PATH_MON,
    "Configuration Synchronization:": _SECTION_CONFIG_SYNC,
}

# Sub-section header -> sub-section constant (exact match)
_SUB_HEADERS_EXACT: dict[str, str] = {
    "Device Information:": _SUB_DEVICE,
    "Election Option Information:": _SUB_ELECTION,
    "Active-Passive Mode:": _SUB_AP_MODE,
    "Version Information:": _SUB_VERSION,
    "Version Compatibility:": _SUB_COMPAT,
    "Group Link:": _SUB_GROUP_LINK,
}

# Sub-section header -> sub-section constant (prefix match)
_SUB_HEADERS_PREFIX: dict[str, str] = {
    "HA1 Control Links Joint Configuration": _SUB_HA1_JOINT,
    "HA1 Control Link": _SUB_HA1,
    "HA2 Data Link": _SUB_HA2,
}

# --- Election option patterns that extract ms values ---
_ELECTION_MS_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_PROMO_HOLD, "promotion_hold_interval_ms"),
    (_HELLO_INTERVAL, "hello_interval_ms"),
    (_HEARTBEAT_INTERVAL, "heartbeat_interval_ms"),
    (_MON_FAIL_UP, "monitor_fail_hold_up_interval_ms"),
    (_ADDON_HOLD, "addon_master_hold_up_interval_ms"),
)

# --- Version info patterns (pattern, key, skip_not_installed) ---
_VERSION_PATTERNS: tuple[tuple[re.Pattern[str], str, bool], ...] = (
    (_BUILD_RELEASE, "build_release", False),
    (_URL_DB, "url_database", False),
    (_APP_CONTENT, "application_content", False),
    (_ANTI_VIRUS, "anti_virus", False),
    (_THREAT_CONTENT, "threat_content", False),
    (_VPN_CLIENT, "vpn_client_software", True),
    (_GP_CLIENT, "global_protect_client_software", True),
)


def _parse_ms(value: str) -> int | None:
    """Extract integer milliseconds from a string like '3000 ms'."""
    m = _MS_VALUE.search(value)
    return int(m.group(1)) if m else None


def _parse_yes_no(value: str) -> bool:
    """Convert 'yes'/'no' string to boolean."""
    return value.lower() == "yes"


def _parse_link_info(line: str, target: dict[str, object]) -> None:
    """Parse HA link fields (IP, MAC, interface, link state, key/conn)."""
    for pattern, key in (
        (_IP_ADDR, "ip_address"),
        (_MAC_ADDR, "mac_address"),
        (_INTERFACE_RE, "interface"),
        (_LINK_STATE, "link_state"),
    ):
        m = pattern.match(line)
        if m:
            target[key] = m.group(1).strip()
            return
    m = _KEY_IMPORTED.match(line)
    if m:
        target["key_imported"] = _parse_yes_no(m.group(1))
        return
    # "Connection up; Primary HA1 link" — appears on peer HA1 control link.
    # Don't consume "Connection status:" lines (those are peer-base fields).
    if "status:" not in line:
        m = _CONNECTION_FREEFORM.match(line)
        if m:
            target["connection"] = m.group(1).strip()


def _parse_ha1_joint_config(
    line: str,
    target: dict[str, object],
) -> None:
    """Parse HA1 Control Links Joint Configuration fields."""
    m = _LINK_MONITOR_INTERVAL.match(line)
    if m:
        ms = _parse_ms(m.group(1).strip())
        if ms is not None:
            target["link_monitor_interval_ms"] = ms
        return
    m = _ENCRYPTION_ENABLED.match(line)
    if m:
        target["encryption_enabled"] = _parse_yes_no(m.group(1))


def _parse_compat_block(line: str, target: dict[str, str]) -> None:
    """Parse Version Compatibility fields (Software Version + per-component)."""
    m = _SOFTWARE_VERSION_LINE.match(line)
    if m:
        target["software_version"] = m.group(1).strip()
        return
    m = _COMPAT_LINE.match(line)
    if m:
        label = m.group(1).strip()
        key = _COMPAT_LABEL_TO_KEY.get(label)
        if key is not None:
            target[key] = m.group(2).strip()


def _parse_device_info(line: str, target: dict[str, object]) -> None:
    """Parse device information fields (model, management IP)."""
    for pattern, key in ((_MODEL, "model"), (_MGMT_IPV4, "mgmt_ipv4")):
        m = pattern.match(line)
        if m:
            target[key] = m.group(1).strip()
            return


def _parse_election_info(line: str, target: dict[str, object]) -> None:
    """Parse election option fields."""
    m = _PRIORITY.match(line)
    if m:
        target["priority"] = int(m.group(1))
        return
    m = _PREEMPTIVE.match(line)
    if m:
        target["preemptive"] = _parse_yes_no(m.group(1))
        return
    m = _MAX_FLAPS.match(line)
    if m:
        target["max_flaps"] = int(m.group(1))
        return
    m = _PREEMPTION_HOLD.match(line)
    if m:
        target["preemption_hold_interval"] = m.group(1).strip()
        return
    _parse_election_ms_fields(line, target)


def _parse_election_ms_fields(
    line: str,
    target: dict[str, object],
) -> None:
    """Parse election option fields that have millisecond values."""
    for pattern, key in _ELECTION_MS_PATTERNS:
        m = pattern.match(line)
        if m:
            ms = _parse_ms(m.group(1))
            if ms is not None:
                target[key] = ms
            return


def _parse_version_block(line: str, target: dict[str, str]) -> None:
    """Parse version information fields."""
    for pattern, key, skip_not_installed in _VERSION_PATTERNS:
        m = pattern.match(line)
        if m:
            val = m.group(1).strip()
            if skip_not_installed and val.lower() == "not installed":
                return
            target[key] = val
            return


def _parse_peer_or_local_base(
    line: str,
    target: dict[str, object],
) -> bool:
    """Parse common base fields for local/peer (version, mode, state).

    Returns True if the line was consumed.
    """
    m = _VERSION_NUM.match(line)
    if m:
        target["version"] = int(m.group(1))
        return True
    m = _MODE_LINE.match(line)
    if m:
        target["mode"] = m.group(1).strip()
        return True
    m = _STATE_LINE.match(line)
    if m:
        target["state"] = m.group(1)
        if m.group(2):
            target["state_duration"] = m.group(2)
        return True
    return False


def _detect_section(stripped: str) -> str | None:
    """Detect a major section header, returning the section constant or None."""
    return _SECTION_HEADERS.get(stripped)


def _detect_sub_section(stripped: str) -> str | None:
    """Detect a sub-section header, returning the sub-section constant or None."""
    result = _SUB_HEADERS_EXACT.get(stripped)
    if result is not None:
        return result
    for prefix, sub in _SUB_HEADERS_PREFIX.items():
        if stripped.startswith(prefix):
            return sub
    return None


class _ParseState:
    """Mutable state container for the HA parser."""

    __slots__ = (
        "result",
        "local",
        "peer",
        "link_mon",
        "path_mon",
        "config_sync",
        "local_ha1",
        "local_ha2",
        "local_election",
        "local_version",
        "local_compat",
        "local_ha1_joint",
        "peer_ha1",
        "peer_ha2",
        "peer_election",
        "peer_version",
        "link_interfaces",
        "section",
        "sub_section",
    )

    def __init__(self) -> None:
        self.result: dict[str, object] = {}
        self.local: dict[str, object] = {}
        self.peer: dict[str, object] = {}
        self.link_mon: dict[str, object] = {}
        self.path_mon: dict[str, object] = {}
        self.config_sync: dict[str, object] = {}
        self.local_ha1: dict[str, object] = {}
        self.local_ha2: dict[str, object] = {}
        self.local_election: dict[str, object] = {}
        self.local_version: dict[str, str] = {}
        self.local_compat: dict[str, str] = {}
        self.local_ha1_joint: dict[str, object] = {}
        self.peer_ha1: dict[str, object] = {}
        self.peer_ha2: dict[str, object] = {}
        self.peer_election: dict[str, object] = {}
        self.peer_version: dict[str, str] = {}
        self.link_interfaces: dict[str, str] = {}
        self.section: str = _SECTION_NONE
        self.sub_section: str = _SUB_NONE

    def assemble(self) -> dict[str, object]:
        """Assemble final result dict from accumulated state."""
        _attach_if_nonempty(self.local, "ha1_control_link", self.local_ha1)
        _attach_if_nonempty(self.local, "ha2_data_link", self.local_ha2)
        _attach_if_nonempty(self.local, "election_options", self.local_election)
        _attach_if_nonempty(self.local, "version_info", self.local_version)
        _attach_if_nonempty(
            self.local,
            "version_compatibility",
            self.local_compat,
        )
        _attach_if_nonempty(
            self.local,
            "ha1_joint_config",
            self.local_ha1_joint,
        )
        _attach_if_nonempty(self.peer, "ha1_control_link", self.peer_ha1)
        _attach_if_nonempty(self.peer, "ha2_data_link", self.peer_ha2)
        _attach_if_nonempty(self.peer, "election_options", self.peer_election)
        _attach_if_nonempty(self.peer, "version_info", self.peer_version)
        _attach_if_nonempty(self.link_mon, "interfaces", self.link_interfaces)

        self.result["local"] = self.local
        self.result["peer"] = self.peer
        _attach_if_nonempty(self.result, "link_monitoring", self.link_mon)
        _attach_if_nonempty(self.result, "path_monitoring", self.path_mon)
        _attach_if_nonempty(self.result, "config_sync", self.config_sync)

        return self.result


def _attach_if_nonempty(
    parent: dict[str, object],
    key: str,
    child: Mapping[str, object],
) -> None:
    """Attach child dict to parent under key only if child is non-empty."""
    if child:
        parent[key] = child


def _parse_peer_base(line: str, peer: dict[str, object]) -> None:
    """Parse peer base fields including connection status."""
    m = _CONNECTION_STATUS.match(line)
    if m:
        peer["connection_status"] = m.group(1)
        return
    _parse_peer_or_local_base(line, peer)


def _parse_ap_mode(line: str, local: dict[str, object]) -> None:
    """Parse Active-Passive mode fields."""
    m = _PASSIVE_LINK.match(line)
    if m:
        local["passive_link_state"] = m.group(1)
        return
    m = _MONITOR_FAIL_DOWN.match(line)
    if m:
        local["monitor_fail_hold_down_interval"] = m.group(1).strip()


# Handler signature: (line, state) -> None
_LOCAL_SUB_HANDLERS: dict[str, "Callable[[str, _ParseState], None]"] = {
    _SUB_NONE: lambda line, st: _parse_peer_or_local_base(line, st.local),
    _SUB_DEVICE: lambda line, st: _parse_device_info(line, st.local),
    _SUB_HA1_JOINT: lambda line, st: _parse_ha1_joint_config(
        line,
        st.local_ha1_joint,
    ),
    _SUB_HA1: lambda line, st: _parse_link_info(line, st.local_ha1),
    _SUB_HA2: lambda line, st: _parse_link_info(line, st.local_ha2),
    _SUB_ELECTION: lambda line, st: _parse_election_info(
        line,
        st.local_election,
    ),
    _SUB_AP_MODE: lambda line, st: _parse_ap_mode(line, st.local),
    _SUB_VERSION: lambda line, st: _parse_version_block(
        line,
        st.local_version,
    ),
    _SUB_COMPAT: lambda line, st: _parse_compat_block(line, st.local_compat),
}

_PEER_SUB_HANDLERS: dict[str, "Callable[[str, _ParseState], None]"] = {
    _SUB_NONE: lambda line, st: _parse_peer_base(line, st.peer),
    _SUB_DEVICE: lambda line, st: _parse_device_info(line, st.peer),
    _SUB_HA1: lambda line, st: _parse_link_info(line, st.peer_ha1),
    _SUB_HA2: lambda line, st: _parse_link_info(line, st.peer_ha2),
    _SUB_ELECTION: lambda line, st: _parse_election_info(
        line,
        st.peer_election,
    ),
    _SUB_VERSION: lambda line, st: _parse_version_block(
        line,
        st.peer_version,
    ),
}


@register(OS.PALOALTO_PANOS, "show high-availability all")
class ShowHighAvailabilityAllParser(
    BaseParser[ShowHighAvailabilityAllResult],
):
    """Parser for 'show high-availability all' on Palo Alto PAN-OS.

    Parses HA group information including local and peer state, link
    monitoring, path monitoring, and configuration synchronization.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.REDUNDANCY})

    @classmethod
    def parse(cls, output: str) -> ShowHighAvailabilityAllResult:
        """Parse 'show high-availability all' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed HA information.

        Raises:
            ValueError: If required fields cannot be parsed.
        """
        state = _ParseState()

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            cls._process_line(line, stripped, state)

        result = state.assemble()
        cls._validate(result)
        return cast(ShowHighAvailabilityAllResult, result)

    @classmethod
    def _process_line(
        cls,
        line: str,
        stripped: str,
        state: _ParseState,
    ) -> None:
        """Route a single line to the appropriate handler."""
        # Top-level group line
        m = _GROUP_LINE.match(stripped)
        if m:
            state.result["group_id"] = int(m.group(1))
            return

        # Top-level mode before any section
        if state.section == _SECTION_NONE and stripped.startswith("Mode:"):
            state.result["mode"] = stripped.split(":", 1)[1].strip()
            return

        # Section transition
        new_section = _detect_section(stripped)
        if new_section is not None:
            state.section = new_section
            state.sub_section = _SUB_NONE
            return

        # Sub-section transition
        new_sub = _detect_sub_section(stripped)
        if new_sub is not None:
            state.sub_section = new_sub
            return

        # Dispatch to section handler
        cls._dispatch_section(line, state)

    @classmethod
    def _dispatch_section(cls, line: str, state: _ParseState) -> None:
        """Dispatch line parsing based on current section."""
        if state.section == _SECTION_LOCAL:
            cls._parse_local_line(line, state)
        elif state.section == _SECTION_PEER:
            cls._parse_peer_line(line, state)
        elif state.section == _SECTION_LINK_MON:
            cls._parse_link_mon_line(line, state)
        elif state.section == _SECTION_PATH_MON:
            _parse_enabled_or_condition(line, state.path_mon)
        elif state.section == _SECTION_CONFIG_SYNC:
            cls._parse_config_sync_line(line, state.config_sync)

    @classmethod
    def _parse_local_line(cls, line: str, state: _ParseState) -> None:
        """Parse a line within the Local Information section."""
        # State Synchronization can appear after any sub-section block
        m = _STATE_SYNC.match(line)
        if m:
            state.local["state_sync"] = m.group(1)
            if m.group(2):
                state.local["state_sync_type"] = m.group(2)
            return

        handler = _LOCAL_SUB_HANDLERS.get(state.sub_section)
        if handler is not None:
            handler(line, state)

    @classmethod
    def _parse_peer_line(cls, line: str, state: _ParseState) -> None:
        """Parse a line within the Peer Information section."""
        handler = _PEER_SUB_HANDLERS.get(state.sub_section)
        if handler is not None:
            handler(line, state)

    @classmethod
    def _parse_link_mon_line(
        cls,
        line: str,
        state: _ParseState,
    ) -> None:
        """Parse link monitoring section fields."""
        if state.sub_section == _SUB_GROUP_LINK:
            # Check interface status first within group link sub-section
            m = _INTERFACE_STATUS.match(line)
            if m:
                state.link_interfaces[m.group(1)] = m.group(2)
                return
        _parse_enabled_or_condition(line, state.link_mon)

    @staticmethod
    def _parse_config_sync_line(
        line: str,
        config_sync: dict[str, object],
    ) -> None:
        """Parse configuration synchronization section fields."""
        m = _ENABLED_RE.match(line)
        if m:
            config_sync["enabled"] = _parse_yes_no(m.group(1))
            return
        m = _RUNNING_CONFIG.match(line)
        if m:
            config_sync["running_config"] = m.group(1).strip()

    @staticmethod
    def _validate(result: dict[str, object]) -> None:
        """Validate required fields are present."""
        if "group_id" not in result:
            msg = "No HA group ID found in output"
            raise ValueError(msg)
        if "mode" not in result:
            msg = "No HA mode found in output"
            raise ValueError(msg)


def _parse_enabled_or_condition(
    line: str,
    target: dict[str, object],
) -> None:
    """Parse 'Enabled:' or 'Failure condition:' lines."""
    m = _ENABLED_RE.match(line)
    if m:
        target["enabled"] = _parse_yes_no(m.group(1))
        return
    m = _FAILURE_CONDITION.match(line)
    if m:
        target["failure_condition"] = m.group(1)
