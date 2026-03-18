"""Parser for 'show graceful-reload' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ClientEntry(TypedDict):
    """Schema for a single graceful reload client."""

    id: str
    status: str


class ShowGracefulReloadResult(TypedDict):
    """Schema for 'show graceful-reload' parsed output."""

    infra_status: str
    minimum_uptime_seconds: int
    clients: NotRequired[dict[str, ClientEntry]]


_INFRA_STATUS_PATTERN = re.compile(
    r"^Graceful\s+Reload\s+Infra\s+Status:\s+(?P<value>.+)$", re.IGNORECASE
)

_UPTIME_PATTERN = re.compile(
    r"^Minimum\s+required\s+system\s+uptime\s+before\s+fast\s+reload\s+"
    r"can\s+be\s+supported\s+is\s+(?P<seconds>\d+)\s+seconds$",
    re.IGNORECASE,
)

_CLIENT_PATTERN = re.compile(
    r"^Client\s+(?P<name>\S+)\s*:\s*\((?P<id>0x[0-9a-fA-F]+)\)\s*Status:\s*(?P<status>.+)$"
)


def _normalize_client_name(name: str) -> str:
    """Normalize a client name to a lowercase key with hyphens replaced by underscores.

    Converts names like 'IS-IS' to 'is_is' and 'OSPFV3' to 'ospfv3'.
    """
    return name.lower().replace("-", "_")


@register(OS.CISCO_IOSXE, "show graceful-reload")
class ShowGracefulReloadParser(BaseParser[ShowGracefulReloadResult]):
    """Parser for 'show graceful-reload' command.

    Example output:
        Graceful Reload Infra Status: Started in stacking mode, not running
        Minimum required system uptime before fast reload can be supported is 5 seconds
        Client OSPFV3                          : (0x10203004) Status: GR stack none: Up
        Client OSPF                            : (0x10203003) Status: GR stack none: Up
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowGracefulReloadResult:
        """Parse 'show graceful-reload' output.

        Args:
            output: Raw CLI output from 'show graceful-reload' command.

        Returns:
            Parsed graceful reload status data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        infra_status: str | None = None
        minimum_uptime: int | None = None
        clients: dict[str, ClientEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = _INFRA_STATUS_PATTERN.match(line)
            if match:
                infra_status = match.group("value").strip()
                continue

            match = _UPTIME_PATTERN.match(line)
            if match:
                minimum_uptime = int(match.group("seconds"))
                continue

            match = _CLIENT_PATTERN.match(line)
            if match:
                name = _normalize_client_name(match.group("name"))
                clients[name] = ClientEntry(
                    id=match.group("id"),
                    status=match.group("status").strip(),
                )
                continue

        if infra_status is None:
            msg = "No graceful reload infra status found in output"
            raise ValueError(msg)

        if minimum_uptime is None:
            msg = "No minimum uptime value found in output"
            raise ValueError(msg)

        result: dict[str, object] = {
            "infra_status": infra_status,
            "minimum_uptime_seconds": minimum_uptime,
        }

        if clients:
            result["clients"] = clients

        return ShowGracefulReloadResult(**result)  # type: ignore[typeddict-item]
