"""Parser for 'show macdb summary' command on IOS-XE."""

import re
from dataclasses import dataclass, field
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ClientCounter(TypedDict):
    """Counter pair for a MACDB client operation (count and failures)."""

    count: int
    failures: int


class TableCounters(TypedDict):
    """Counters describing one MACDB table (software or hardware)."""

    interfaces: int
    mac_addresses: int
    forwarding_entities: int
    active_count: int


class PlatformCounters(TypedDict):
    """Platform-level MAC counters."""

    mac_reserve_count: int
    mac_reserve_fail: int
    mac_active_count: int
    mac_smf_count: int


class ClientForwarding(TypedDict):
    """Forwarding-entity counters for one registered MACDB client."""

    forwarding_entities: int
    active_count: int


class RegisteredClient(TypedDict):
    """Per-client MACDB summary block (e.g. VRRS)."""

    id: int
    software: ClientForwarding
    hardware: ClientForwarding


class ShowMacdbSummaryResult(TypedDict):
    """Schema for 'show macdb summary' parsed output."""

    clients: dict[str, ClientCounter]
    software: TableCounters
    hardware: TableCounters
    platform: PlatformCounters
    registered_clients_count: int
    registered_clients: NotRequired[dict[str, RegisteredClient]]


# Lines like:
#   "    Client registrations         :      1   Failures :      0"
_CLIENT_RE = re.compile(
    r"^Client\s+(?P<op>registrations|reservations|activations|deactivations|releases)"
    r"\s*:\s*(?P<count>\d+)\s+Failures\s*:\s*(?P<failures>\d+)\s*$",
    re.I,
)

# Lines like: "    Software interfaces          :      0"
_TABLE_RE = re.compile(
    r"^(?P<scope>Software|Hardware)\s+"
    r"(?P<field>interfaces|MAC addresses|forwarding entities|active count)"
    r"\s*:\s*(?P<value>\d+)\s*$",
    re.I,
)

# Lines like: "    Platform MAC reserve count   :      0"
_PLATFORM_RE = re.compile(
    r"^Platform\s+MAC\s+"
    r"(?P<field>reserve count|reserve fail|active count|smf count)"
    r"\s*:\s*(?P<value>\d+)\s*$",
    re.I,
)

# "    Number of registered clients :      1"
_REGISTERED_RE = re.compile(
    r"^Number\s+of\s+registered\s+clients\s*:\s*(?P<value>\d+)\s*$",
    re.I,
)

# "  VRRS                        ID :      1"
_CLIENT_HEADER_RE = re.compile(
    r"^(?P<name>\S+(?:\s+\S+)*?)\s+ID\s*:\s*(?P<id>\d+)\s*$",
    re.I,
)

# Within a registered client block: "    Software forwarding entities :      0"
_CLIENT_TABLE_RE = re.compile(
    r"^(?P<scope>Software|Hardware)\s+"
    r"(?P<field>forwarding entities|active count)"
    r"\s*:\s*(?P<value>\d+)\s*$",
    re.I,
)

_TABLE_FIELD_MAP = {
    "interfaces": "interfaces",
    "mac addresses": "mac_addresses",
    "forwarding entities": "forwarding_entities",
    "active count": "active_count",
}

_PLATFORM_FIELD_MAP = {
    "reserve count": "mac_reserve_count",
    "reserve fail": "mac_reserve_fail",
    "active count": "mac_active_count",
    "smf count": "mac_smf_count",
}


def _empty_table() -> dict[str, int]:
    return {
        "interfaces": 0,
        "mac_addresses": 0,
        "forwarding_entities": 0,
        "active_count": 0,
    }


def _empty_platform() -> dict[str, int]:
    return {
        "mac_reserve_count": 0,
        "mac_reserve_fail": 0,
        "mac_active_count": 0,
        "mac_smf_count": 0,
    }


def _empty_client_forwarding() -> dict[str, int]:
    return {"forwarding_entities": 0, "active_count": 0}


@dataclass
class _ParseState:
    """Mutable parse state accumulated while walking ``show macdb summary``."""

    clients: dict[str, ClientCounter] = field(default_factory=dict)
    software: dict[str, int] = field(default_factory=_empty_table)
    hardware: dict[str, int] = field(default_factory=_empty_table)
    platform: dict[str, int] = field(default_factory=_empty_platform)
    registered_count: int | None = None
    registered_clients: dict[str, dict[str, object]] = field(default_factory=dict)
    current_client: dict[str, dict[str, int]] | None = None


@register(OS.CISCO_IOSXE, "show macdb summary")
class ShowMacdbSummaryParser(BaseParser[ShowMacdbSummaryResult]):
    """Parser for 'show macdb summary' command on IOS-XE.

    Parses MACDB summary statistics including client operation counters,
    software/hardware/platform MAC table counts, and any per-client
    (e.g. VRRS) forwarding-entity sections that follow.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.MAC, ParserTag.SWITCHING}
    )

    @classmethod
    def _try_client_counter(cls, line: str, clients: dict[str, ClientCounter]) -> bool:
        m = _CLIENT_RE.match(line)
        if not m:
            return False
        op = m.group("op").lower()
        clients[op] = {
            "count": int(m.group("count")),
            "failures": int(m.group("failures")),
        }
        return True

    @classmethod
    def _try_table_counter(
        cls,
        line: str,
        software: dict[str, int],
        hardware: dict[str, int],
    ) -> bool:
        m = _TABLE_RE.match(line)
        if not m:
            return False
        scope = m.group("scope").lower()
        field = _TABLE_FIELD_MAP[m.group("field").lower()]
        value = int(m.group("value"))
        target = software if scope == "software" else hardware
        target[field] = value
        return True

    @classmethod
    def _try_platform_counter(cls, line: str, platform: dict[str, int]) -> bool:
        m = _PLATFORM_RE.match(line)
        if not m:
            return False
        field = _PLATFORM_FIELD_MAP[m.group("field").lower()]
        platform[field] = int(m.group("value"))
        return True

    @classmethod
    def _try_client_table(
        cls,
        line: str,
        current: dict[str, dict[str, int]] | None,
    ) -> bool:
        if current is None:
            return False
        m = _CLIENT_TABLE_RE.match(line)
        if not m:
            return False
        scope = m.group("scope").lower()
        field = _TABLE_FIELD_MAP[m.group("field").lower()]
        current[scope][field] = int(m.group("value"))
        return True

    @classmethod
    def _try_client_header(
        cls,
        line: str,
        registered_clients: dict[str, dict[str, object]],
    ) -> dict[str, dict[str, int]] | None:
        """Match a per-client header (e.g. ``VRRS ID : 1``) and register it.

        Returns the new ``current_client`` reference if matched, else ``None``.
        """
        hdr = _CLIENT_HEADER_RE.match(line)
        if not hdr:
            return None
        name = hdr.group("name").strip()
        sw = _empty_client_forwarding()
        hw = _empty_client_forwarding()
        current_client = {"software": sw, "hardware": hw}
        registered_clients[name] = {
            "id": int(hdr.group("id")),
            "software": sw,
            "hardware": hw,
        }
        return current_client

    @classmethod
    def _process_global_line(
        cls,
        line: str,
        clients: dict[str, ClientCounter],
        software: dict[str, int],
        hardware: dict[str, int],
        platform: dict[str, int],
    ) -> bool:
        """Try to match a line against any of the top-level counter blocks."""
        if line.lower() == "macdb summary statistics":
            return True
        if cls._try_client_counter(line, clients):
            return True
        if cls._try_table_counter(line, software, hardware):
            return True
        return cls._try_platform_counter(line, platform)

    @classmethod
    def _consume_line(cls, line: str, state: _ParseState) -> bool:
        """Process one non-blank input line, mutating ``state`` in place."""
        # Once we are inside a per-client section, ``Software``/``Hardware``
        # lines belong to that client, not the global software/hardware tables.
        # Match the client header and client table first so they take priority
        # over the global ``_TABLE_RE`` which would otherwise consume them.
        if state.current_client is not None:
            new_client = cls._try_client_header(line, state.registered_clients)
            if new_client is not None:
                state.current_client = new_client
                return True
            if cls._try_client_table(line, state.current_client):
                return True

        if cls._process_global_line(
            line, state.clients, state.software, state.hardware, state.platform
        ):
            return True

        m = _REGISTERED_RE.match(line)
        if m:
            state.registered_count = int(m.group("value"))
            return True

        if state.registered_count is None:
            return False
        new_client = cls._try_client_header(line, state.registered_clients)
        if new_client is not None:
            state.current_client = new_client
            return True
        return False

    @classmethod
    def parse(cls, output: str) -> ShowMacdbSummaryResult:
        r"""Parse 'show macdb summary' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed MACDB summary including counters and any per-client
            sections (e.g. VRRS) reported after the registered-clients line.

        Raises:
            ValueError: If no recognizable MACDB summary content was found.
        """
        state = _ParseState()
        any_match = False
        for raw in output.splitlines():
            line = raw.strip()
            if not line:
                continue
            if cls._consume_line(line, state):
                any_match = True

        if not any_match or state.registered_count is None:
            msg = "No MACDB summary content found"
            raise ValueError(msg)

        result: dict[str, object] = {
            "clients": state.clients,
            "software": cast(TableCounters, state.software),
            "hardware": cast(TableCounters, state.hardware),
            "platform": cast(PlatformCounters, state.platform),
            "registered_clients_count": state.registered_count,
        }
        if state.registered_clients:
            result["registered_clients"] = cast(
                dict[str, RegisteredClient], state.registered_clients
            )
        return cast(ShowMacdbSummaryResult, result)
