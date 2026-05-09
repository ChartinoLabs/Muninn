"""Operating system definitions and lookup."""

from enum import Enum
from typing import ClassVar


class OperatingSystem:
    """Base class for operating system definitions.

    Each OS subclass defines a canonical name, a user-facing display
    name, and a set of aliases that can be used to look up the OS.

    Attributes:
        name: Canonical internal name for this OS (used in slugs and paths).
        display_name: Human-friendly name shown in user-facing surfaces
            such as the docs site catalog and CLI tooling.
        aliases: Tuple of acceptable string identifiers for this OS.
    """

    name: ClassVar[str]
    display_name: ClassVar[str]
    aliases: ClassVar[tuple[str, ...]]


class CiscoNXOS(OperatingSystem):
    """Cisco NX-OS (Nexus switches)."""

    name = "cisco_nxos"
    display_name = "Cisco NX-OS"
    aliases = ("nxos", "cisco_nxos", "nexus", "nx-os", "nx_os")


class CiscoIOSXE(OperatingSystem):
    """Cisco IOS-XE (Catalyst switches, ISR/ASR routers)."""

    name = "cisco_iosxe"
    display_name = "Cisco IOS-XE"
    aliases = ("iosxe", "cisco_iosxe", "ios-xe", "ios_xe", "cisco_ios_xe")


class CiscoIOSXR(OperatingSystem):
    """Cisco IOS-XR (ASR 9000, NCS, XRv)."""

    name = "cisco_iosxr"
    display_name = "Cisco IOS-XR"
    aliases = ("iosxr", "cisco_iosxr", "ios-xr", "ios_xr", "cisco_ios_xr")


class CiscoIOS(OperatingSystem):
    """Cisco IOS Classic (legacy devices)."""

    name = "cisco_ios"
    display_name = "Cisco IOS"
    aliases = ("ios", "cisco_ios")


class AristaEOS(OperatingSystem):
    """Arista EOS (data center and campus switches)."""

    name = "arista_eos"
    display_name = "Arista EOS"
    aliases = ("arista_eos", "eos", "arista")


class JuniperJunos(OperatingSystem):
    """Juniper Junos (MX, QFX, EX, SRX, PTX)."""

    name = "juniper_junos"
    display_name = "Juniper Junos"
    aliases = ("juniper_junos", "junos", "juniper")


class PaloAltoPanOS(OperatingSystem):
    """Palo Alto PAN-OS (next-generation firewalls)."""

    name = "paloalto_panos"
    display_name = "Palo Alto PAN-OS"
    aliases = ("paloalto_panos", "panos", "paloalto", "pan-os", "pan_os")


class NokiaSROS(OperatingSystem):
    """Nokia SR OS (7750 SR, 7210 SAS, 7450 ESS)."""

    name = "nokia_sros"
    display_name = "Nokia SR OS"
    aliases = ("nokia_sros", "sros", "nokia", "sr-os", "sr_os")


class Linux(OperatingSystem):
    """Linux (including SONiC, Cumulus, FRR-based platforms)."""

    name = "linux"
    display_name = "Linux"
    aliases = ("linux",)


class OS(Enum):
    """Enumeration of supported operating systems.

    Each member's value is the corresponding OperatingSystem class.

    Example:
        >>> OS.CISCO_NXOS.value.name
        'cisco_nxos'
        >>> OS.CISCO_NXOS.value.aliases
        ('nxos', 'cisco_nxos', 'nexus', 'nx-os', 'nx_os')
    """

    CISCO_NXOS = CiscoNXOS
    CISCO_IOSXE = CiscoIOSXE
    CISCO_IOSXR = CiscoIOSXR
    CISCO_IOS = CiscoIOS
    ARISTA_EOS = AristaEOS
    JUNIPER_JUNOS = JuniperJunos
    PALOALTO_PANOS = PaloAltoPanOS
    NOKIA_SROS = NokiaSROS
    LINUX = Linux


# Build lookup table: alias -> OS enum member
_alias_lookup: dict[str, OS] = {}
for os_member in OS:
    os_class = os_member.value
    for alias in os_class.aliases:
        _alias_lookup[alias.lower()] = os_member


def resolve_os(os_input: str | OS | type[OperatingSystem]) -> OS:
    """Resolve an OS input to an OS enum member.

    Args:
        os_input: Can be:
            - A string alias (e.g., "nxos", "ios-xe")
            - An OS enum member (e.g., OS.CISCO_NXOS)
            - An OperatingSystem class (e.g., CiscoNXOS)

    Returns:
        The corresponding OS enum member.

    Raises:
        ValueError: If the input cannot be resolved to a known OS.

    Example:
        >>> resolve_os("nxos")
        <OS.CISCO_NXOS: <class 'CiscoNXOS'>>
        >>> resolve_os(OS.CISCO_NXOS)
        <OS.CISCO_NXOS: <class 'CiscoNXOS'>>
        >>> resolve_os(CiscoNXOS)
        <OS.CISCO_NXOS: <class 'CiscoNXOS'>>
    """
    # Already an OS enum member
    if isinstance(os_input, OS):
        return os_input

    # An OperatingSystem class
    if isinstance(os_input, type) and issubclass(os_input, OperatingSystem):
        for os_member in OS:
            if os_member.value is os_input:
                return os_member
        msg = f"OperatingSystem class {os_input.__name__} is not registered in OS enum"
        raise ValueError(msg)

    # A string alias
    if isinstance(os_input, str):
        normalized = os_input.lower().strip()
        if normalized in _alias_lookup:
            return _alias_lookup[normalized]
        msg = f"Unknown OS alias: {os_input!r}"
        raise ValueError(msg)

    msg = f"Cannot resolve OS from type {type(os_input).__name__}"
    raise TypeError(msg)
