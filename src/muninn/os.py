"""Operating system definitions and lookup."""

from enum import Enum
from typing import ClassVar


class OperatingSystem:
    """Base class for operating system definitions.

    Each OS subclass defines a canonical name and a set of aliases
    that can be used to look up the OS.

    Attributes:
        name: Canonical internal name for this OS.
        aliases: Tuple of acceptable string identifiers for this OS.
    """

    name: ClassVar[str]
    aliases: ClassVar[tuple[str, ...]]


class CiscoNXOS(OperatingSystem):
    """Cisco NX-OS (Nexus switches)."""

    name = "cisco_nxos"
    aliases = ("nxos", "cisco_nxos", "nexus", "nx-os", "nx_os")


class CiscoIOSXE(OperatingSystem):
    """Cisco IOS-XE (Catalyst switches, ISR/ASR routers)."""

    name = "cisco_iosxe"
    aliases = ("iosxe", "cisco_iosxe", "ios-xe", "ios_xe", "cisco_ios_xe")


class CiscoIOSXR(OperatingSystem):
    """Cisco IOS-XR (ASR 9000, NCS, XRv)."""

    name = "cisco_iosxr"
    aliases = ("iosxr", "cisco_iosxr", "ios-xr", "ios_xr", "cisco_ios_xr")


class CiscoIOS(OperatingSystem):
    """Cisco IOS Classic (legacy devices)."""

    name = "cisco_ios"
    aliases = ("ios", "cisco_ios")


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
