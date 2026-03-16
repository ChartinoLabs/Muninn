"""Parser for 'show esmc' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class EsmcAdminConfig(TypedDict):
    """Schema for ESMC administrative configurations."""

    mode: str
    esmc_tx: str
    esmc_rx: str
    ql_rx_configured: NotRequired[str]
    ql_tx_configured: NotRequired[str]


class EsmcOperStatus(TypedDict):
    """Schema for ESMC operational status."""

    port_status: str
    ql_receive: NotRequired[str]
    esmc_information_rate: NotRequired[str]
    esmc_expiry: NotRequired[str]


class EsmcInterfaceEntry(TypedDict):
    """Schema for a single interface ESMC entry."""

    admin: EsmcAdminConfig
    oper: EsmcOperStatus


class ShowEsmcResult(TypedDict):
    """Schema for 'show esmc' parsed output."""

    interfaces: dict[str, EsmcInterfaceEntry]


_INTERFACE_RE = re.compile(r"^Interface\s*:\s*(?P<interface>\S+)", re.IGNORECASE)
_MODE_RE = re.compile(r"^\s*Mode\s*:\s*(?P<value>\S+)", re.IGNORECASE)
_ESMC_TX_RE = re.compile(r"^\s*ESMC\s+TX\s*:\s*(?P<value>\S+)", re.IGNORECASE)
_ESMC_RX_RE = re.compile(r"^\s*ESMC\s+RX\s*:\s*(?P<value>\S+)", re.IGNORECASE)
_QL_RX_RE = re.compile(r"^\s*QL\s+RX\s+configured\s*:\s*(?P<value>\S+)", re.IGNORECASE)
_QL_TX_RE = re.compile(r"^\s*QL\s+TX\s+configured\s*:\s*(?P<value>\S+)", re.IGNORECASE)
_PORT_STATUS_RE = re.compile(r"^\s*Port\s+status\s*:\s*(?P<value>\S+)", re.IGNORECASE)
_QL_RECEIVE_RE = re.compile(r"^\s*QL\s+Receive\s*:\s*(?P<value>\S+)", re.IGNORECASE)
_INFO_RATE_RE = re.compile(
    r"^\s*ESMC\s+Information\s+rate\s*:\s*(?P<value>.+?)\s*$", re.IGNORECASE
)
_EXPIRY_RE = re.compile(r"^\s*ESMC\s+Expiry\s*:\s*(?P<value>.+?)\s*$", re.IGNORECASE)


def _split_interface_sections(output: str) -> list[tuple[str, list[str]]]:
    """Split raw output into per-interface sections.

    Returns:
        List of (raw_interface_name, lines) tuples.
    """
    sections: list[tuple[str, list[str]]] = []
    current_name: str | None = None
    current_lines: list[str] = []

    for line in output.splitlines():
        match = _INTERFACE_RE.match(line.strip())
        if match:
            if current_name is not None:
                sections.append((current_name, current_lines))
            current_name = match.group("interface")
            current_lines = []
            continue
        if current_name is not None:
            current_lines.append(line)

    if current_name is not None:
        sections.append((current_name, current_lines))

    return sections


def _parse_admin_config(lines: list[str]) -> EsmcAdminConfig:
    """Extract administrative configuration fields from section lines."""
    admin: EsmcAdminConfig = {"mode": "", "esmc_tx": "", "esmc_rx": ""}

    for line in lines:
        if match := _MODE_RE.match(line):
            admin["mode"] = match.group("value")
        elif match := _ESMC_TX_RE.match(line):
            admin["esmc_tx"] = match.group("value")
        elif match := _ESMC_RX_RE.match(line):
            admin["esmc_rx"] = match.group("value")
        elif match := _QL_RX_RE.match(line):
            value = match.group("value")
            if value.upper() != "NA":
                admin["ql_rx_configured"] = value
        elif match := _QL_TX_RE.match(line):
            value = match.group("value")
            if value.upper() != "NA":
                admin["ql_tx_configured"] = value

    return admin


def _parse_oper_status(lines: list[str]) -> EsmcOperStatus:
    """Extract operational status fields from section lines."""
    oper: EsmcOperStatus = {"port_status": ""}

    for line in lines:
        if match := _PORT_STATUS_RE.match(line):
            oper["port_status"] = match.group("value")
        elif match := _QL_RECEIVE_RE.match(line):
            oper["ql_receive"] = match.group("value")
        elif match := _INFO_RATE_RE.match(line):
            oper["esmc_information_rate"] = match.group("value")
        elif match := _EXPIRY_RE.match(line):
            oper["esmc_expiry"] = match.group("value")

    return oper


def _parse_interface_section(lines: list[str]) -> EsmcInterfaceEntry:
    """Parse a single interface section into an EsmcInterfaceEntry."""
    return EsmcInterfaceEntry(
        admin=_parse_admin_config(lines),
        oper=_parse_oper_status(lines),
    )


@register(OS.CISCO_IOSXE, "show esmc")
class ShowEsmcParser(BaseParser[ShowEsmcResult]):
    """Parser for 'show esmc' command.

    Parses Ethernet Synchronization Messaging Channel (ESMC) status
    for each interface, including administrative configuration and
    operational status.

    Example output:
        Interface: GigabitEthernet0/0/0
        Administrative configurations:
          Mode: Synchronous
          ESMC TX: Enable
          ESMC RX : Enable
          QL RX configured : NA
          QL TX configured : NA
        Operational status:
          Port status: UP
          QL Receive: QL-SSU-B
          ESMC Information rate : 1 packet/second
          ESMC Expiry: 5 second
    """

    tags: ClassVar[frozenset[str]] = frozenset({"system"})

    @classmethod
    def parse(cls, output: str) -> ShowEsmcResult:
        """Parse 'show esmc' output.

        Args:
            output: Raw CLI output from 'show esmc' command.

        Returns:
            Parsed ESMC data keyed by canonical interface name.

        Raises:
            ValueError: If no interfaces are found in the output.
        """
        sections = _split_interface_sections(output)
        if not sections:
            msg = "No ESMC interface entries found in output"
            raise ValueError(msg)

        interfaces: dict[str, EsmcInterfaceEntry] = {}
        for raw_name, lines in sections:
            interface = canonical_interface_name(raw_name, os=OS.CISCO_IOSXE)
            interfaces[interface] = _parse_interface_section(lines)

        return ShowEsmcResult(interfaces=interfaces)
