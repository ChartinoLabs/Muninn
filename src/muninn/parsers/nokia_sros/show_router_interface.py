"""Parser for 'show router interface' command on Nokia SR OS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class InterfaceEntry(TypedDict):
    """Schema for a single router interface entry."""

    admin_state: str
    oper_state_v4: str
    oper_state_v6: str
    mode: str
    port_sap_id: str
    ip_addresses: list[str]
    pfx_states: NotRequired[list[str]]


# Top-level result is a dict keyed by interface name
ShowRouterInterfaceResult = dict[str, InterfaceEntry]


@register(OS.NOKIA_SROS, "show router interface")
class ShowRouterInterfaceParser(BaseParser[ShowRouterInterfaceResult]):
    """Parser for 'show router interface' command on Nokia SR OS.

    Parses the interface table output, returning a dict keyed by
    interface name. Each interface has admin/oper states, mode,
    port/SAP ID, and associated IP addresses with prefix states.

    The output format has a header row followed by interface entries.
    Each interface occupies one line for the header columns plus one
    or more continuation lines for IP addresses and prefix states.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INTERFACES,
        }
    )

    # Separator lines (=== or ---)
    _SEPARATOR = re.compile(r"^[=\-]{10,}$")

    # Table title line
    _TABLE_TITLE = re.compile(r"^\s*Interface Table\s+\(Router:", re.I)

    # Column header lines
    _HEADER = re.compile(r"^\s*Interface-Name\s+Adm\s+Opr", re.I)
    _HEADER_CONT = re.compile(r"^\s*IP-Address\s+PfxState", re.I)

    # Footer line showing interface count
    _FOOTER = re.compile(r"^\s*Interfaces\s*:\s*\d+", re.I)

    # Interface row: name, admin_state, oper(v4/v6), mode, port/sap
    _INTERFACE_ROW = re.compile(
        r"^(?P<name>\S+)\s+"
        r"(?P<admin_state>Up|Down)\s+"
        r"(?P<oper_v4>Up|Down)/(?P<oper_v6>Up|Down)\s+"
        r"(?P<mode>\S+)\s+"
        r"(?P<port_sap>\S+)\s*$"
    )

    # IP address continuation line: indented IP address with optional prefix state
    _IP_LINE = re.compile(r"^\s+(?P<ip_address>\S+)\s+(?P<pfx_state>\S+)\s*$")

    @classmethod
    def _is_skip_line(cls, line: str) -> bool:
        """Return True for lines that are not data rows."""
        stripped = line.strip()
        if not stripped:
            return True
        if cls._SEPARATOR.match(stripped):
            return True
        if cls._TABLE_TITLE.match(stripped):
            return True
        if cls._HEADER.match(stripped):
            return True
        if cls._HEADER_CONT.match(stripped):
            return True
        if cls._FOOTER.match(stripped):
            return True
        return False

    @classmethod
    def parse(cls, output: str) -> ShowRouterInterfaceResult:
        """Parse 'show router interface' output on Nokia SR OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by interface name, each value an InterfaceEntry dict.

        Raises:
            ValueError: If no interface entries can be parsed.
        """
        result: dict[str, InterfaceEntry] = {}
        current_name: str | None = None

        for line in output.splitlines():
            if cls._is_skip_line(line):
                continue

            # Try to match an interface header row
            iface_match = cls._INTERFACE_ROW.match(line)
            if iface_match:
                current_name = iface_match.group("name")
                entry: InterfaceEntry = {
                    "admin_state": iface_match.group("admin_state"),
                    "oper_state_v4": iface_match.group("oper_v4"),
                    "oper_state_v6": iface_match.group("oper_v6"),
                    "mode": iface_match.group("mode"),
                    "port_sap_id": iface_match.group("port_sap"),
                    "ip_addresses": [],
                }
                result[current_name] = entry
                continue

            # Try to match an IP address continuation line
            ip_match = cls._IP_LINE.match(line)
            if ip_match and current_name is not None:
                current_entry = result[current_name]
                current_entry["ip_addresses"].append(ip_match.group("ip_address"))
                pfx_state = ip_match.group("pfx_state")
                if "pfx_states" not in current_entry:
                    current_entry["pfx_states"] = []
                current_entry["pfx_states"].append(pfx_state)
                continue

        if not result:
            msg = "No interface entries found in output"
            raise ValueError(msg)

        return cast(ShowRouterInterfaceResult, result)
