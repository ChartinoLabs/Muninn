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

# IOS-XR abbreviated prefixes that netutils does not expand.
_IOSXR_PREFIX_MAP: dict[str, str] = {
    "mg": "MgmtEth",
    "nu": "Null",
    "tt": "tunnel-te",
}
_IOSXR_PREFIX_PATTERN = re.compile(
    r"^(?P<prefix>" + "|".join(_IOSXR_PREFIX_MAP) + r")(?P<suffix>\d.*)$",
    re.IGNORECASE,
)

# Arista EOS abbreviated prefixes that netutils expands incorrectly.
# netutils maps "Vl" -> "VLAN" but Arista's canonical form is "Vlan".
_ARISTA_EOS_PREFIX_MAP: dict[str, str] = {
    "vl": "Vlan",
}
_ARISTA_EOS_PREFIX_PATTERN = re.compile(
    r"^(?P<prefix>" + "|".join(_ARISTA_EOS_PREFIX_MAP) + r")(?P<suffix>\d.*)$",
    re.IGNORECASE,
)

# Platforms where netutils canonicalization is incorrect — these use their
# own naming conventions (e.g. lo0, eth0, ge-0/0/0) that must not be rewritten.
_NETUTILS_PASSTHROUGH_OSES = frozenset(
    {OS.JUNIPER_JUNOS, OS.NOKIA_SROS, OS.PALOALTO_PANOS, OS.LINUX}
)


def _apply_prefix_map(
    name: str,
    pattern: re.Pattern[str],
    prefix_map: dict[str, str],
) -> str:
    """Rewrite an interface name using a prefix lookup table.

    If *name* matches *pattern*, the captured ``prefix`` group is
    looked up (case-insensitively) in *prefix_map* and the name is
    rebuilt as ``<canonical_prefix><suffix>``.  Otherwise *name* is
    returned unchanged.
    """
    match = pattern.match(name)
    if match:
        canonical = prefix_map[match.group("prefix").lower()]
        return f"{canonical}{match.group('suffix')}"
    return name


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
    if os in _NETUTILS_PASSTHROUGH_OSES:
        return name

    if os is OS.CISCO_NXOS:
        name_lower = name.lower()
        for prefix in _NXOS_PASSTHROUGH_PREFIXES:
            if name_lower.startswith(prefix):
                return name

    if os in {OS.CISCO_IOS, OS.CISCO_IOSXE}:
        match = _IOS_FOUR_HUNDRED_GIGE_PATTERN.match(name)
        if match:
            name = f"FourHundredGigabitEthernet{match.group('suffix')}"

    if os is OS.ARISTA_EOS:
        name = _apply_prefix_map(
            name, _ARISTA_EOS_PREFIX_PATTERN, _ARISTA_EOS_PREFIX_MAP
        )

    if os is OS.CISCO_IOSXR:
        name = _apply_prefix_map(name, _IOSXR_PREFIX_PATTERN, _IOSXR_PREFIX_MAP)

    return _upstream_canonical(name)
