"""Parser for 'show object-group' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class NetworkEntry(TypedDict):
    """Schema for a single network object-group entry."""

    type: str
    host: NotRequired[str]
    network: NotRequired[str]
    mask: NotRequired[str]
    range_start: NotRequired[str]
    range_end: NotRequired[str]
    any: NotRequired[bool]
    group_object: NotRequired[str]


class ServiceEntry(TypedDict):
    """Schema for a single service object-group entry."""

    type: str
    protocol: NotRequired[str]
    port_match: NotRequired[str]
    port: NotRequired[str]
    port_range_start: NotRequired[str]
    port_range_end: NotRequired[str]
    icmp_type: NotRequired[str]
    group_object: NotRequired[str]


class ObjectGroup(TypedDict):
    """Schema for a single object-group."""

    group_type: str
    description: NotRequired[str]
    entries: list[NetworkEntry | ServiceEntry]


class ShowObjectGroupResult(TypedDict):
    """Schema for 'show object-group' parsed output."""

    object_groups: dict[str, ObjectGroup]


# Header pattern: "<type> object group <name>"
# Types: Network, Service, V6-Network, V6-Service
_HEADER_PATTERN = re.compile(
    r"^(?P<type>(?:V6-)?(?:Network|Service))\s+object\s+group\s+(?P<name>\S+)$"
)

# Description line
_DESCRIPTION_PATTERN = re.compile(r"^\s+Description\s+(?P<desc>.+)$")

# Network entries
_HOST_PATTERN = re.compile(r"^\s+host\s+(?P<host>\S+)$")
_RANGE_PATTERN = re.compile(r"^\s+range\s+(?P<start>\S+)\s+(?P<end>\S+)$")
_ANY_PATTERN = re.compile(r"^\s+any$")
_GROUP_OBJECT_PATTERN = re.compile(r"^\s+group-object\s+(?P<name>\S+)$")

# Network with mask (IPv4: "1.1.1.0 255.255.255.0")
_NETWORK_MASK_PATTERN = re.compile(
    r"^\s+(?P<network>\d+\.\d+\.\d+\.\d+)\s+(?P<mask>\d+\.\d+\.\d+\.\d+)$"
)

# IPv6 prefix (e.g. "2001:db8:111:1::/48")
_IPV6_PREFIX_PATTERN = re.compile(r"^\s+(?P<network>\S+)/(?P<prefix_len>\d+)$")

# ICMP with optional type (e.g. "icmp echo-reply", "icmp")
_ICMP_PATTERN = re.compile(r"^\s+icmp(?:\s+(?P<icmp_type>\S+))?\s*$")

# Service entries: protocol with optional port specification
# Matches: "tcp eq smtp", "udp range 49 50", "tcp-udp range 12200 12700",
#           "tcp", "udp", "ip", "ipinip", "99"
_SERVICE_PROTOCOL_PORT_PATTERN = re.compile(
    r"^\s+(?P<protocol>\S+)"
    r"(?:\s+(?P<match>eq|lt|gt|range)\s+(?P<port1>\S+)(?:\s+(?P<port2>\S+))?)?"
    r"\s*$"
)


def _parse_network_entry(line: str, group_type: str) -> NetworkEntry | None:
    """Parse a network object-group entry line.

    Args:
        line: Raw line from CLI output.
        group_type: The group type (Network, V6-Network).

    Returns:
        Parsed entry, or None if line does not match a network entry.
    """
    m = _ANY_PATTERN.match(line)
    if m:
        return {"type": group_type, "any": True}

    m = _HOST_PATTERN.match(line)
    if m:
        return {"type": group_type, "host": m.group("host")}

    m = _RANGE_PATTERN.match(line)
    if m:
        return {
            "type": group_type,
            "range_start": m.group("start"),
            "range_end": m.group("end"),
        }

    m = _GROUP_OBJECT_PATTERN.match(line)
    if m:
        return {"type": group_type, "group_object": m.group("name")}

    m = _NETWORK_MASK_PATTERN.match(line)
    if m:
        return {
            "type": group_type,
            "network": m.group("network"),
            "mask": m.group("mask"),
        }

    m = _IPV6_PREFIX_PATTERN.match(line)
    if m:
        return {
            "type": group_type,
            "network": m.group("network"),
            "mask": m.group("prefix_len"),
        }

    return None


def _parse_service_entry(line: str, group_type: str) -> ServiceEntry | None:
    """Parse a service object-group entry line.

    Args:
        line: Raw line from CLI output.
        group_type: The group type (Service, V6-Service).

    Returns:
        Parsed entry, or None if line does not match a service entry.
    """
    m = _GROUP_OBJECT_PATTERN.match(line)
    if m:
        return {"type": group_type, "group_object": m.group("name")}

    # Check ICMP first since "icmp <type>" doesn't follow the eq/lt/gt/range pattern
    m = _ICMP_PATTERN.match(line)
    if m:
        icmp_type = m.group("icmp_type")
        if icmp_type:
            return {
                "type": group_type,
                "protocol": "icmp",
                "icmp_type": icmp_type,
            }
        return {"type": group_type, "protocol": "icmp"}

    m = _SERVICE_PROTOCOL_PORT_PATTERN.match(line)
    if not m:
        return None

    protocol = m.group("protocol")
    match_type = m.group("match")
    port1 = m.group("port1")
    port2 = m.group("port2")

    entry: ServiceEntry = {"type": group_type, "protocol": protocol}

    if match_type == "range" and port1 and port2:
        entry["port_match"] = "range"
        entry["port_range_start"] = port1
        entry["port_range_end"] = port2
    elif match_type and port1:
        entry["port_match"] = match_type
        entry["port"] = port1

    return entry


def _parse_entry(line: str, group_type: str) -> NetworkEntry | ServiceEntry | None:
    """Parse an object-group entry line based on group type.

    Args:
        line: Raw line from CLI output.
        group_type: The group type (Network, Service, V6-Network, V6-Service).

    Returns:
        Parsed entry, or None if line does not match.
    """
    if "Network" in group_type:
        return _parse_network_entry(line, group_type)
    return _parse_service_entry(line, group_type)


def _process_header(
    line: str,
    object_groups: dict[str, ObjectGroup],
) -> tuple[str, str] | None:
    """Process a group header line.

    Returns:
        Tuple of (name, type) if the line is a header, or None.
    """
    header_match = _HEADER_PATTERN.match(line)
    if not header_match:
        return None

    name = header_match.group("name")
    group_type = header_match.group("type")
    # Avoid overwriting entries if the group was already created.
    if name not in object_groups:
        object_groups[name] = {"group_type": group_type, "entries": []}
    return name, group_type


def _process_body_line(
    line: str,
    current_name: str,
    current_type: str,
    object_groups: dict[str, ObjectGroup],
) -> None:
    """Process a body line (description or entry) within a group."""
    desc_match = _DESCRIPTION_PATTERN.match(line)
    if desc_match:
        object_groups[current_name]["description"] = desc_match.group("desc").strip()
        return

    entry = _parse_entry(line, current_type)
    if entry:
        object_groups[current_name]["entries"].append(entry)


def _parse_object_groups(output: str) -> dict[str, ObjectGroup]:
    """Parse all object groups from raw output.

    Args:
        output: Raw CLI output from 'show object-group' command.

    Returns:
        Dict of object groups keyed by name.
    """
    object_groups: dict[str, ObjectGroup] = {}
    current_name: str | None = None
    current_type: str | None = None

    for line in output.splitlines():
        if not line.strip():
            continue

        header = _process_header(line, object_groups)
        if header:
            current_name, current_type = header
            continue

        if current_name is not None and current_type is not None:
            _process_body_line(line, current_name, current_type, object_groups)

    return object_groups


@register(OS.CISCO_IOS, "show object-group")
class ShowObjectGroupParser(BaseParser[ShowObjectGroupResult]):
    """Parser for 'show object-group' command.

    Example output::

        Network object group NNNN
        Service object group SSSS
        Service object group TEST-SVC-OGR
         Description ! Test Service Group !
         icmp echo-reply
         tcp eq smtp
         udp eq tacacs
        Network object group TEST_NET_OGR
         Description ###TEST NETWORK OGR###
         any
         host 1.1.1.1
         range 2.2.2.2 3.3.3.3
         group-object NNNN
         1.1.1.0 255.255.255.0
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ACL,
            ParserTag.SECURITY,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowObjectGroupResult:
        """Parse 'show object-group' output.

        Args:
            output: Raw CLI output from 'show object-group' command.

        Returns:
            Parsed data with object groups keyed by name.

        Raises:
            ValueError: If no object groups found in output.
        """
        object_groups = _parse_object_groups(output)

        if not object_groups:
            msg = "No object groups found in output"
            raise ValueError(msg)

        return ShowObjectGroupResult(object_groups=object_groups)
