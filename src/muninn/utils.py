"""Utility functions for parser implementations."""

import re

from netutils.interface import canonical_interface_name as _upstream_canonical

from muninn.os import OS

# NX-OS interface prefixes that netutils incorrectly canonicalizes.
# mgmt0 is native on Nexus and should not become Management0.
_NXOS_PASSTHROUGH_PREFIXES = ("mgmt",)
_IOS_FOUR_HUNDRED_GIGE_PATTERN = re.compile(
    r"^(?P<prefix>Fou)(?P<suffix>\d.*)$",
    re.IGNORECASE,
)


def canonical_interface_name(name: str, *, os: OS | None = None) -> str:
    """Return the canonical form of an interface name.

    Thin shim around ``netutils.interface.canonical_interface_name`` that
    corrects platform-specific quirks.

    Args:
        name: Raw interface name (e.g. ``"Eth1/1"``, ``"mgmt0"``).
        os: Operating system context.  When *OS.CISCO_NXOS*, the NX-OS
            native ``mgmt0`` form is preserved instead of being expanded
            to ``Management0``.

    Returns:
        Canonical interface name string.
    """
    if os is OS.CISCO_NXOS:
        name_lower = name.lower()
        for prefix in _NXOS_PASSTHROUGH_PREFIXES:
            if name_lower.startswith(prefix):
                return name

    if os in {OS.CISCO_IOS, OS.CISCO_IOSXE}:
        match = _IOS_FOUR_HUNDRED_GIGE_PATTERN.match(name)
        if match:
            name = f"FourHundredGigabitEthernet{match.group('suffix')}"

    return _upstream_canonical(name)
