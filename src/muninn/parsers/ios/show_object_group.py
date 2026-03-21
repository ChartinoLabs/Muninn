"""Parser for 'show object-group' command on IOS."""

import ipaddress
import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class RangeEnd(TypedDict):
    """End of a host range line."""

    end: str


class ObjectGroup(TypedDict, total=False):
    """Schema for a single object-group (network or service)."""

    group_type: str
    description: str
    # --- Network / V6-Network ---
    any: bool
    hosts: dict[str, dict]
    ranges: dict[str, RangeEnd]
    nested_groups: dict[str, dict]
    ipv4_networks: dict[str, dict]
    ipv6_prefixes: dict[str, dict]
    # --- Service / V6-Service ---
    protocols: dict[str, object]


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
_SERVICE_PROTOCOL_PORT_PATTERN = re.compile(
    r"^\s+(?P<protocol>\S+)"
    r"(?:\s+(?P<match>eq|lt|gt|range)\s+(?P<port1>\S+)(?:\s+(?P<port2>\S+))?)?"
    r"\s*$"
)


def _ipv4_line_to_cidr(network: str, mask: str) -> str:
    """Normalize IPv4 network + mask to a CIDR string."""
    net = ipaddress.IPv4Network(f"{network}/{mask}", strict=False)
    return str(net)


def _ipv6_line_to_prefix(network: str, prefix_len: str) -> str:
    """Normalize IPv6 address + prefix length to a CIDR string."""
    net = ipaddress.IPv6Network(f"{network}/{prefix_len}", strict=False)
    return str(net)


def _merge_network_into_group(group: ObjectGroup, line: str) -> None:
    """Parse a network object-group line and merge into *group*."""
    m = _ANY_PATTERN.match(line)
    if m:
        group["any"] = True
        return

    m = _HOST_PATTERN.match(line)
    if m:
        hosts = group.setdefault("hosts", {})
        hosts[m.group("host")] = {}
        return

    m = _RANGE_PATTERN.match(line)
    if m:
        ranges = group.setdefault("ranges", {})
        ranges[m.group("start")] = RangeEnd(end=m.group("end"))
        return

    m = _GROUP_OBJECT_PATTERN.match(line)
    if m:
        nested = group.setdefault("nested_groups", {})
        nested[m.group("name")] = {}
        return

    m = _NETWORK_MASK_PATTERN.match(line)
    if m:
        cidr = _ipv4_line_to_cidr(m.group("network"), m.group("mask"))
        group.setdefault("ipv4_networks", {})[cidr] = {}
        return

    m = _IPV6_PREFIX_PATTERN.match(line)
    if m:
        pfx = _ipv6_line_to_prefix(m.group("network"), m.group("prefix_len"))
        group.setdefault("ipv6_prefixes", {})[pfx] = {}
        return


def _merge_icmp_service_line(group: ObjectGroup, line: str) -> bool:
    """Merge an ``icmp`` line; return True if *line* matched."""
    m = _ICMP_PATTERN.match(line)
    if not m:
        return False
    icmp = group.setdefault("protocols", {}).setdefault("icmp", {})
    if not isinstance(icmp, dict):
        return True
    icmp_typed: dict[str, object] = icmp
    icmp_type = m.group("icmp_type")
    if icmp_type:
        types = icmp_typed.setdefault("types", {})
        if isinstance(types, dict):
            types[str(icmp_type)] = {}
    else:
        icmp_typed["all"] = {}
    return True


def _merge_protocol_port_line(group: ObjectGroup, line: str) -> None:
    """Merge a protocol line with optional eq/lt/gt/range (non-ICMP)."""
    m = _SERVICE_PROTOCOL_PORT_PATTERN.match(line)
    if not m:
        return

    protocol = m.group("protocol")
    match_type = m.group("match")
    port1 = m.group("port1")
    port2 = m.group("port2")

    protos = group.setdefault("protocols", {})
    proto_node = protos.setdefault(protocol, {})
    if not isinstance(proto_node, dict):
        return
    pnode: dict[str, object] = proto_node

    if match_type == "range" and port1 and port2:
        rmap = pnode.setdefault("range", {})
        if not isinstance(rmap, dict):
            return
        rmap[str(port1)] = RangeEnd(end=str(port2))
        return
    if match_type and port1:
        mmap = pnode.setdefault(match_type, {})
        if not isinstance(mmap, dict):
            return
        mmap[str(port1)] = {}
        return

    pnode["all"] = {}


def _merge_service_into_group(group: ObjectGroup, line: str) -> None:
    """Parse a service object-group line and merge into *group*."""
    m = _GROUP_OBJECT_PATTERN.match(line)
    if m:
        group.setdefault("nested_groups", {})[m.group("name")] = {}
        return

    if _merge_icmp_service_line(group, line):
        return

    _merge_protocol_port_line(group, line)


def _parse_object_groups(output: str) -> dict[str, ObjectGroup]:
    """Parse all object groups from raw output."""
    object_groups: dict[str, ObjectGroup] = {}
    current_name: str | None = None
    current_type: str | None = None

    for line in output.splitlines():
        if not line.strip():
            continue

        header_match = _HEADER_PATTERN.match(line)
        if header_match:
            name = header_match.group("name")
            group_type = header_match.group("type")
            if name not in object_groups:
                object_groups[name] = ObjectGroup(group_type=group_type)
            current_name, current_type = name, group_type
            continue

        if current_name is None or current_type is None:
            continue

        desc_match = _DESCRIPTION_PATTERN.match(line)
        if desc_match:
            desc = desc_match.group("desc").strip()
            object_groups[current_name]["description"] = desc
            continue

        if "Network" in current_type:
            _merge_network_into_group(object_groups[current_name], line)
        else:
            _merge_service_into_group(object_groups[current_name], line)

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
