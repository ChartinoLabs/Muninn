"""Parser for 'show stackwise-virtual' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class SVLLink(TypedDict):
    """Schema for a single StackWise Virtual Link on a switch."""

    ports: list[str]


class SwitchEntry(TypedDict):
    """Schema for a single switch in the StackWise Virtual configuration."""

    links: dict[str, SVLLink]


class ShowStackwiseVirtualResult(TypedDict):
    """Schema for 'show stackwise-virtual' parsed output."""

    stackwise_virtual: str
    domain_number: int
    switches: NotRequired[dict[str, SwitchEntry]]


# Stackwise Virtual : Enabled
_SVL_STATUS = re.compile(
    r"^Stackwise\s+Virtual\s*:\s*(?P<status>\S+)\s*$",
    re.IGNORECASE,
)

# Domain Number : 10
_DOMAIN_NUMBER = re.compile(
    r"^Domain\s+Number\s*:\s*(?P<domain>\d+)\s*$",
    re.IGNORECASE,
)

# 1       1                       HundredGigE1/0/51
_SWITCH_LINK_ROW = re.compile(r"^(?P<switch>\d+)\s+(?P<link>\d+)\s+(?P<port>\S+)\s*$")

#                                 HundredGigE1/0/52
_CONTINUATION_PORT = re.compile(r"^\s{2,}(?P<port>[A-Z]\S+)\s*$")

#         2                       TenGigabitEthernet1/0/5
_LINK_ONLY_ROW = re.compile(r"^\s+(?P<link>\d+)\s+(?P<port>\S+)\s*$")

_TABLE_HEADER_MARKER = "Stackwise Virtual Link"


def _is_table_skip_line(line: str) -> bool:
    """Return True for blank and separator lines in the table section."""
    return not line or line.startswith("---")


def _ensure_switch(switches: dict[str, SwitchEntry], switch_num: str) -> None:
    """Ensure a switch entry exists in the dict."""
    if switch_num not in switches:
        switches[switch_num] = SwitchEntry(links={})


def _add_port_to_link(
    switches: dict[str, SwitchEntry],
    switch_num: str,
    link_num: str,
    port: str,
) -> None:
    """Add a port to a link, creating the link entry if needed."""
    normalized = canonical_interface_name(port)
    links = switches[switch_num]["links"]
    if link_num not in links:
        links[link_num] = SVLLink(ports=[normalized])
    else:
        links[link_num]["ports"].append(normalized)


def _handle_switch_link_row(
    m: re.Match[str],
    switches: dict[str, SwitchEntry],
) -> tuple[str, str]:
    """Process a full switch+link+port row. Returns (switch, link)."""
    switch_num = m.group("switch")
    link_num = m.group("link")
    _ensure_switch(switches, switch_num)
    _add_port_to_link(switches, switch_num, link_num, m.group("port"))
    return switch_num, link_num


def _parse_table_lines(
    lines: list[str],
    start_idx: int,
) -> dict[str, SwitchEntry]:
    """Parse the switch/link/port table section."""
    switches: dict[str, SwitchEntry] = {}
    current_switch: str | None = None
    current_link: str | None = None

    for idx in range(start_idx, len(lines)):
        stripped = lines[idx].strip()
        if _is_table_skip_line(stripped):
            continue

        if m := _SWITCH_LINK_ROW.match(stripped):
            current_switch, current_link = _handle_switch_link_row(m, switches)
        elif (m := _LINK_ONLY_ROW.match(stripped)) and current_switch is not None:
            current_link = m.group("link")
            _add_port_to_link(switches, current_switch, current_link, m.group("port"))
        elif (
            (m := _CONTINUATION_PORT.match(lines[idx]))
            and current_switch is not None
            and current_link is not None
        ):
            _add_port_to_link(switches, current_switch, current_link, m.group("port"))

    return switches


def _extract_header_fields(
    output: str,
) -> tuple[str | None, int | None, int | None]:
    """Extract status, domain number, and table start index from output."""
    status: str | None = None
    domain: int | None = None
    table_start: int | None = None

    for idx, raw_line in enumerate(output.splitlines()):
        line = raw_line.strip()
        if not line:
            continue

        if m := _SVL_STATUS.match(line):
            status = m.group("status")
        elif m := _DOMAIN_NUMBER.match(line):
            domain = int(m.group("domain"))
        elif _TABLE_HEADER_MARKER in line:
            table_start = idx + 1
            break

    return status, domain, table_start


def _validate_status(status: str | None) -> str:
    """Validate and return the StackWise Virtual status."""
    if status is None:
        msg = "No StackWise Virtual status found in output"
        raise ValueError(msg)
    return status


def _validate_domain(domain: int | None) -> int:
    """Validate and return the domain number."""
    if domain is None:
        msg = "No domain number found in output"
        raise ValueError(msg)
    return domain


@register(OS.CISCO_IOSXE, "show stackwise-virtual")
class ShowStackwiseVirtualParser(BaseParser[ShowStackwiseVirtualResult]):
    """Parser for 'show stackwise-virtual' command.

    Example output::

        Stackwise Virtual Configuration:
        --------------------------------
        Stackwise Virtual : Enabled
        Domain Number : 10

        Switch  Stackwise Virtual Link  Ports
        ------  ----------------------  ------
        1       1                       HundredGigE1/0/51
                                        HundredGigE1/0/52
        2       1                       HundredGigE2/0/51
                                        HundredGigE2/0/52
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowStackwiseVirtualResult:
        """Parse 'show stackwise-virtual' output.

        Args:
            output: Raw CLI output from 'show stackwise-virtual' command.

        Returns:
            Parsed StackWise Virtual configuration data.

        Raises:
            ValueError: If required fields are not found in the output.
        """
        status_raw, domain_raw, table_start = _extract_header_fields(output)
        status = _validate_status(status_raw)
        domain = _validate_domain(domain_raw)

        result = ShowStackwiseVirtualResult(
            stackwise_virtual=status,
            domain_number=domain,
        )

        if table_start is not None:
            switches = _parse_table_lines(output.splitlines(), table_start)
            if switches:
                result["switches"] = switches

        return result
