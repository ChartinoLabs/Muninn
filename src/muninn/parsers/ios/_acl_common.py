"""Shared helpers for IOS ACL parser line parsing."""

from typing import Literal

AddressSpec = dict[str, object]
PortSpec = dict[str, object]
AclParsedFields = dict[str, object]

_PORT_OPERATORS = frozenset({"eq", "neq", "lt", "gt", "range"})
_TCP_FLAGS = frozenset(
    {"ack", "established", "fin", "fragments", "psh", "rst", "syn", "urg"}
)
_TCP_FLAG_MODES = frozenset({"match-all", "match-any"})
_ICMP_MESSAGES = frozenset(
    {
        "administratively-prohibited",
        "echo",
        "echo-reply",
        "mask-request",
        "mld-query",
        "packet-too-big",
        "parameter-problem",
        "port-unreachable",
        "redirect",
        "router-advertisement",
        "router-solicitation",
        "time-exceeded",
        "ttl-exceeded",
        "unreachable",
    }
)


def parse_standard_ace_body(body: str) -> AclParsedFields:
    """Parse the non-sequence portion of a standard ACL ACE."""
    tokens = body.split()
    parsed: AclParsedFields = {}

    source, index = _parse_address(tokens, 0, ip_version=4)
    parsed["source"] = source

    _parse_trailing_modifiers(parsed, tokens[index:], protocol=None)
    return parsed


def parse_extended_ace_body(body: str, *, ip_version: Literal[4, 6]) -> AclParsedFields:
    """Parse the non-sequence portion of an extended ACL ACE."""
    tokens = body.split()
    if not tokens:
        return {}

    parsed, index, protocol = _parse_protocol_or_service(tokens)

    source, index = _parse_address(tokens, index, ip_version=ip_version)
    parsed["source"] = source

    source_port, index = _parse_port_spec(tokens, index)
    if source_port is not None:
        parsed["source_port"] = source_port

    destination, index = _parse_address(tokens, index, ip_version=ip_version)
    parsed["destination"] = destination

    destination_port, index = _parse_port_spec(tokens, index)
    if destination_port is not None:
        parsed["destination_port"] = destination_port

    _parse_trailing_modifiers(parsed, tokens[index:], protocol=protocol)
    return parsed


def _parse_protocol_or_service(
    tokens: list[str],
) -> tuple[AclParsedFields, int, str | None]:
    """Parse the protocol position, including service object-groups."""
    if len(tokens) >= 2 and tokens[0] == "object-group":
        return {"service_object_group": tokens[1]}, 2, None
    return {"protocol": tokens[0]}, 1, tokens[0]


def _parse_address(
    tokens: list[str], index: int, *, ip_version: Literal[4, 6]
) -> tuple[AddressSpec, int]:
    """Parse an ACL address specification."""
    if index >= len(tokens):
        return {"kind": "unknown"}, index

    token = tokens[index]
    if token == "any":
        return {"kind": "any"}, index + 1

    if token == "host" and index + 1 < len(tokens):
        return {"kind": "host", "value": tokens[index + 1]}, index + 2

    if token == "object-group" and index + 1 < len(tokens):
        return {"kind": "object-group", "name": tokens[index + 1]}, index + 2

    if ip_version == 4:
        current = token.rstrip(",")
        if index + 1 < len(tokens) and _looks_like_ipv4(tokens[index + 1]):
            return {
                "kind": "network",
                "value": current,
                "wildcard": tokens[index + 1],
            }, index + 2
        if (
            index + 3 < len(tokens)
            and tokens[index + 1] == "wildcard"
            and tokens[index + 2] == "bits"
        ):
            return {
                "kind": "network",
                "value": current,
                "wildcard": tokens[index + 3],
            }, index + 4

    kind = "prefix" if "/" in token else "address"
    return {"kind": kind, "value": token}, index + 1


def _parse_port_spec(tokens: list[str], index: int) -> tuple[PortSpec | None, int]:
    """Parse a TCP/UDP port clause if present."""
    if index >= len(tokens):
        return None, index

    operator = tokens[index]
    if operator not in _PORT_OPERATORS:
        return None, index

    if operator == "range" and index + 2 < len(tokens):
        return {
            "operator": operator,
            "ports": [tokens[index + 1], tokens[index + 2]],
        }, index + 3

    if index + 1 < len(tokens):
        return {"operator": operator, "ports": [tokens[index + 1]]}, index + 2

    return {"operator": operator, "ports": []}, index + 1


def _parse_trailing_modifiers(
    parsed: AclParsedFields, tokens: list[str], *, protocol: str | None
) -> None:
    """Parse trailing ACL modifiers such as log, dscp, and ICMP type."""
    extras: list[str] = []
    index = 0

    while index < len(tokens):
        modifier_index = _consume_simple_flag(parsed, tokens, index)
        if modifier_index is not None:
            index = modifier_index
            continue

        modifier_index = _consume_value_modifier(parsed, tokens, index)
        if modifier_index is not None:
            index = modifier_index
            continue

        modifier_index = _consume_time_range(parsed, tokens, index)
        if modifier_index is not None:
            index = modifier_index
            continue

        modifier_index = _consume_protocol_modifier(parsed, tokens, index, protocol)
        if modifier_index is not None:
            index = modifier_index
            continue

        extras.append(tokens[index])
        index += 1

    if extras:
        parsed["extra"] = extras


def _consume_simple_flag(
    parsed: AclParsedFields, tokens: list[str], index: int
) -> int | None:
    """Consume simple boolean trailing modifiers."""
    token = tokens[index]
    if token == "log":
        parsed["log"] = True
        return index + 1
    if token == "log-input":
        parsed["log_input"] = True
        return index + 1
    if token == "fragments":
        parsed["fragments"] = True
        return index + 1
    return None


def _consume_value_modifier(
    parsed: AclParsedFields, tokens: list[str], index: int
) -> int | None:
    """Consume key/value modifiers like dscp, precedence, tos, and ttl."""
    token = tokens[index]
    if token in {"dscp", "precedence", "tos"} and index + 1 < len(tokens):
        parsed[token] = tokens[index + 1]
        return index + 2

    if token == "ttl" and index + 1 < len(tokens):
        ttl_spec: dict[str, object] = {}
        if index + 2 < len(tokens) and tokens[index + 1] in _PORT_OPERATORS:
            ttl_spec["operator"] = tokens[index + 1]
            ttl_spec["value"] = int(tokens[index + 2])
            parsed["ttl"] = ttl_spec
            return index + 3

        ttl_spec["value"] = int(tokens[index + 1])
        parsed["ttl"] = ttl_spec
        return index + 2

    return None


def _consume_time_range(
    parsed: AclParsedFields, tokens: list[str], index: int
) -> int | None:
    """Consume a time-range modifier and optional status."""
    if tokens[index] != "time-range" or index + 1 >= len(tokens):
        return None

    time_range: dict[str, object] = {"name": tokens[index + 1]}
    next_index = index + 2
    if next_index < len(tokens) and tokens[next_index].startswith("("):
        status, next_index = _consume_parenthesized_status(tokens, next_index)
        time_range["status"] = status

    parsed["time_range"] = time_range
    return next_index


def _consume_protocol_modifier(
    parsed: AclParsedFields,
    tokens: list[str],
    index: int,
    protocol: str | None,
) -> int | None:
    """Consume protocol-specific trailing modifiers."""
    token = tokens[index]
    tcp_flags, next_index = _consume_tcp_flag_group(tokens, index, protocol)
    if tcp_flags is not None:
        parsed["tcp_flags"] = tcp_flags
        return next_index

    if protocol == "tcp" and token in _TCP_FLAGS:
        parsed[token.replace("-", "_")] = True
        return index + 1

    if protocol == "icmp" and token in _ICMP_MESSAGES and "icmp_message" not in parsed:
        parsed["icmp_message"] = token
        return index + 1

    return None


def _consume_parenthesized_status(tokens: list[str], index: int) -> tuple[str, int]:
    """Consume one or more tokens that form a parenthesized status string."""
    token = tokens[index]
    if token.endswith(")"):
        return token.strip("()"), index + 1

    parts = [token.lstrip("(")]
    next_index = index + 1
    while next_index < len(tokens):
        part = tokens[next_index]
        parts.append(part.rstrip(")"))
        next_index += 1
        if part.endswith(")"):
            break
    return " ".join(parts), next_index


def _consume_tcp_flag_group(
    tokens: list[str], index: int, protocol: str | None
) -> tuple[dict[str, object] | None, int]:
    """Consume a TCP flag group such as 'match-all +syn -ack'."""
    if protocol != "tcp":
        return None, index

    mode: str | None = None
    next_index = index
    if tokens[next_index] in _TCP_FLAG_MODES:
        mode = tokens[next_index]
        next_index += 1

    flags: dict[str, str] = {}
    while next_index < len(tokens):
        parsed_flag = _parse_signed_tcp_flag(tokens[next_index])
        if parsed_flag is None:
            break
        flag_name, flag_value = parsed_flag
        flags[flag_name] = flag_value
        next_index += 1

    if not flags:
        return None, index

    tcp_flags: dict[str, object] = {"flags": flags}
    if mode is not None:
        tcp_flags["mode"] = mode
    return tcp_flags, next_index


def _parse_signed_tcp_flag(token: str) -> tuple[str, str] | None:
    """Parse a signed TCP flag token like '+syn' or '-ack'."""
    operator = "include"
    flag = token
    if token.startswith("+"):
        flag = token[1:]
    elif token.startswith("-"):
        operator = "exclude"
        flag = token[1:]

    if flag not in _TCP_FLAGS:
        return None

    return flag, operator


def _looks_like_ipv4(token: str) -> bool:
    """Return whether a token looks like an IPv4 address or wildcard."""
    parts = token.split(".")
    return len(parts) == 4 and all(part.isdigit() for part in parts)
