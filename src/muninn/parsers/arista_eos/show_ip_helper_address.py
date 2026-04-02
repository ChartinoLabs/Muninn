"""Parser for 'show ip helper-address' command on Arista EOS."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class HelperAddressEntry(TypedDict):
    """Schema for a single interface's DHCP helper configuration."""

    dhcp_smart_relay: bool
    dhcp_servers: list[str]


class ShowIpHelperAddressResult(TypedDict):
    """Schema for 'show ip helper-address' parsed output on Arista EOS.

    Top-level keys are interface names (e.g., "Vlan1", "Vlan2").
    """

    dhcp_relay: bool
    dhcp_relay_option_82: bool
    dhcpv6_relay_link_layer_option_79: bool
    dhcp_smart_relay: bool
    interfaces: dict[str, HelperAddressEntry]


def _is_enabled(state: str) -> bool:
    """Return True when a state string indicates an active/enabled feature."""
    return state in ("active", "enabled")


@register(OS.ARISTA_EOS, "show ip helper-address")
class ShowIpHelperAddressParser(BaseParser[ShowIpHelperAddressResult]):
    """Parser for 'show ip helper-address' command on Arista EOS.

    Parses DHCP relay configuration and per-interface helper addresses.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.DHCP})

    _DHCP_RELAY_ACTIVE = re.compile(r"^DHCP Relay is (?P<state>active|inactive)$")
    _DHCP_RELAY_OPTION_82 = re.compile(
        r"^DHCP Relay Option 82 is (?P<state>enabled|disabled)$"
    )
    _DHCPV6_RELAY_LL = re.compile(
        r"^DHCPv6 Relay Link-layer Address Option \(79\) is "
        r"(?P<state>enabled|disabled)$"
    )
    _GLOBAL_SMART_RELAY = re.compile(
        r"^DHCP Smart Relay is (?P<state>enabled|disabled)$"
    )
    _INTERFACE = re.compile(r"^Interface:\s+(?P<name>\S+)$")
    _SMART_RELAY = re.compile(r"^DHCP Smart Relay is (?P<state>enabled|disabled)$")
    _DHCP_SERVERS_HEADER = re.compile(r"^DHCP servers:\s+(?P<first>\S+)$")
    _CONTINUATION_SERVER = re.compile(r"^\s+(\S+)$")

    @classmethod
    def _parse_global_header(
        cls, stripped: str, globals_: dict[str, bool | None]
    ) -> bool:
        """Try to match a global-level DHCP setting line.

        Returns True if the line was consumed.
        """
        patterns: list[tuple[str, re.Pattern[str]]] = [
            ("dhcp_relay", cls._DHCP_RELAY_ACTIVE),
            ("dhcp_relay_option_82", cls._DHCP_RELAY_OPTION_82),
            ("dhcpv6_relay_ll", cls._DHCPV6_RELAY_LL),
            ("global_smart_relay", cls._GLOBAL_SMART_RELAY),
        ]
        for key, pattern in patterns:
            if globals_[key] is None:
                match = pattern.match(stripped)
                if match:
                    globals_[key] = _is_enabled(match.group("state"))
                    return True
        return False

    @classmethod
    def _parse_interface_line(
        cls,
        line: str,
        stripped: str,
        interfaces: dict[str, HelperAddressEntry],
        state: dict[str, object],
    ) -> None:
        """Parse a single line inside an interface block.

        Mutates *interfaces* and *state* (current_intf, in_servers) in place.
        """
        current_intf: str = state["current_intf"]  # type: ignore[assignment]

        # New interface boundary
        match = cls._INTERFACE.match(stripped)
        if match:
            state["in_servers"] = False
            new_name = match.group("name")
            state["current_intf"] = new_name
            interfaces[new_name] = HelperAddressEntry(
                dhcp_smart_relay=False, dhcp_servers=[]
            )
            return

        # Interface-level smart relay
        match = cls._SMART_RELAY.match(stripped)
        if match:
            state["in_servers"] = False
            interfaces[current_intf]["dhcp_smart_relay"] = _is_enabled(
                match.group("state")
            )
            return

        # DHCP servers header
        match = cls._DHCP_SERVERS_HEADER.match(stripped)
        if match:
            state["in_servers"] = True
            interfaces[current_intf]["dhcp_servers"].append(match.group("first"))
            return

        # Continuation server lines (indented in original output)
        if state["in_servers"]:
            cont = cls._CONTINUATION_SERVER.match(line)
            if cont:
                interfaces[current_intf]["dhcp_servers"].append(cont.group(1))
                return
            state["in_servers"] = False

    @classmethod
    def parse(cls, output: str) -> ShowIpHelperAddressResult:
        """Parse 'show ip helper-address' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed DHCP relay and helper-address information.

        Raises:
            ValueError: If global DHCP relay status cannot be determined.
        """
        globals_: dict[str, bool | None] = {
            "dhcp_relay": None,
            "dhcp_relay_option_82": None,
            "dhcpv6_relay_ll": None,
            "global_smart_relay": None,
        }
        interfaces: dict[str, HelperAddressEntry] = {}
        state: dict[str, object] = {"current_intf": None, "in_servers": False}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            # Inside an interface block, delegate to interface parser
            if state["current_intf"] is not None:
                cls._parse_interface_line(line, stripped, interfaces, state)
                continue

            # First interface boundary transitions into interface mode
            match = cls._INTERFACE.match(stripped)
            if match:
                name = match.group("name")
                state["current_intf"] = name
                interfaces[name] = HelperAddressEntry(
                    dhcp_smart_relay=False, dhcp_servers=[]
                )
                continue

            cls._parse_global_header(stripped, globals_)

        if globals_["dhcp_relay"] is None:
            msg = "Could not determine DHCP relay status from output"
            raise ValueError(msg)

        return cast(
            ShowIpHelperAddressResult,
            {
                "dhcp_relay": globals_["dhcp_relay"],
                "dhcp_relay_option_82": globals_["dhcp_relay_option_82"] or False,
                "dhcpv6_relay_link_layer_option_79": globals_["dhcpv6_relay_ll"]
                or False,
                "dhcp_smart_relay": globals_["global_smart_relay"] or False,
                "interfaces": interfaces,
            },
        )
