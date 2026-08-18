"""Parser for 'show ip sla responder' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowIpSlaResponderResult(TypedDict):
    """Schema for 'show ip sla responder' parsed output."""

    general_responder_enabled: bool
    general_responder_control_port: NotRequired[int]
    general_responder_control_v2_port: NotRequired[int]
    permanent_port_responder_enabled: bool


@register(OS.CISCO_IOSXE, "show ip sla responder")
class ShowIpSlaResponderParser(BaseParser[ShowIpSlaResponderResult]):
    """Parser for 'show ip sla responder' command on IOS-XE.

    Parses the IP SLA responder global status output. The command reports
    two responder modes:

    * General IP SLA Responder, with its control port and (optionally)
      Control V2 port numbers.
    * Permanent Port IP SLA Responder.

    Each mode reports an enabled/disabled status.

    Example output::

        General IP SLA Responder on Control port 1967
                General IP SLA Responder on Control V2 port 1167
        General IP SLA Responder is: Disabled

                Permanent Port IP SLA Responder
        Permanent Port IP SLA Responder is: Disabled
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.CONNECTIVITY})

    _CONTROL_V2_PORT_RE = re.compile(
        r"General IP SLA Responder on Control V2 port (?P<port>\d+)"
    )
    _CONTROL_PORT_RE = re.compile(
        r"General IP SLA Responder on Control port (?P<port>\d+)"
    )
    _GENERAL_STATUS_RE = re.compile(r"General IP SLA Responder is:\s+(?P<status>\S+)")
    _PERMANENT_STATUS_RE = re.compile(
        r"Permanent Port IP SLA Responder is:\s+(?P<status>\S+)"
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpSlaResponderResult:
        """Parse 'show ip sla responder' output.

        Args:
            output: Raw CLI output from 'show ip sla responder'.

        Returns:
            Parsed responder configuration and status.

        Raises:
            ValueError: If required responder status lines cannot be found.
        """
        result: dict = {}

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            # Check Control V2 first since it is a more specific match.
            match = cls._CONTROL_V2_PORT_RE.search(line)
            if match:
                result["general_responder_control_v2_port"] = int(match.group("port"))
                continue

            match = cls._CONTROL_PORT_RE.search(line)
            if match:
                result["general_responder_control_port"] = int(match.group("port"))
                continue

            match = cls._GENERAL_STATUS_RE.search(line)
            if match:
                result["general_responder_enabled"] = (
                    match.group("status").lower() == "enabled"
                )
                continue

            match = cls._PERMANENT_STATUS_RE.search(line)
            if match:
                result["permanent_port_responder_enabled"] = (
                    match.group("status").lower() == "enabled"
                )
                continue

        for required in (
            "general_responder_enabled",
            "permanent_port_responder_enabled",
        ):
            if required not in result:
                msg = f"Missing required field: {required}"
                raise ValueError(msg)

        return cast(ShowIpSlaResponderResult, result)
