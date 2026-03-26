"""Parser for 'show cdp' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowCdpResult(TypedDict):
    """Schema for 'show cdp' parsed output.

    Represents global CDP configuration settings on the device.
    """

    cdp_enabled: bool
    send_interval: int
    holdtime: int
    cdp_version: NotRequired[int]
    device_id_type: NotRequired[str]


# Global CDP information:
#         Sending CDP packets every 60 seconds
_SEND_INTERVAL_PATTERN = re.compile(
    r"^\s*Sending\s+CDP\s+packets\s+every\s+(?P<interval>\d+)\s+seconds?$",
    re.IGNORECASE,
)

#         Sending a holdtime value of 180 seconds
_HOLDTIME_PATTERN = re.compile(
    r"^\s*Sending\s+a\s+holdtime\s+value\s+of\s+(?P<holdtime>\d+)\s+seconds?$",
    re.IGNORECASE,
)

#         Sending CDPv2 advertisements is  enabled
_CDP_VERSION_PATTERN = re.compile(
    r"^\s*Sending\s+CDPv(?P<version>\d+)\s+advertisements\s+is\s+"
    r"(?P<enabled>enabled|disabled)$",
    re.IGNORECASE,
)

#         Device ID type: 1
_DEVICE_ID_TYPE_PATTERN = re.compile(
    r"^\s*Device\s+ID\s+type:\s*(?P<device_id_type>.+)$",
    re.IGNORECASE,
)

# CDP is not enabled
_CDP_NOT_ENABLED_PATTERN = re.compile(
    r"^\s*CDP\s+is\s+not\s+enabled$",
    re.IGNORECASE,
)


class _CdpFields:
    """Accumulates parsed CDP fields from individual lines."""

    def __init__(self) -> None:
        self.send_interval: int | None = None
        self.holdtime: int | None = None
        self.cdp_version: int | None = None
        self.cdp_enabled: bool | None = None
        self.device_id_type: str | None = None


def _parse_line(line: str, fields: _CdpFields) -> None:
    """Parse a single line and update fields in place."""
    if _CDP_NOT_ENABLED_PATTERN.match(line):
        fields.cdp_enabled = False
        return

    match = _SEND_INTERVAL_PATTERN.match(line)
    if match:
        fields.send_interval = int(match.group("interval"))
        fields.cdp_enabled = True
        return

    match = _HOLDTIME_PATTERN.match(line)
    if match:
        fields.holdtime = int(match.group("holdtime"))
        return

    match = _CDP_VERSION_PATTERN.match(line)
    if match:
        if match.group("enabled").lower() == "enabled":
            fields.cdp_version = int(match.group("version"))
        return

    match = _DEVICE_ID_TYPE_PATTERN.match(line)
    if match:
        fields.device_id_type = match.group("device_id_type").strip()


def _build_enabled_result(
    send_interval: int | None, holdtime: int | None
) -> ShowCdpResult:
    """Build result for an enabled CDP configuration."""
    return ShowCdpResult(
        cdp_enabled=True,
        send_interval=send_interval if send_interval is not None else 0,
        holdtime=holdtime if holdtime is not None else 0,
    )


def _build_result(fields: _CdpFields) -> ShowCdpResult:
    """Build the result dict from accumulated fields.

    Raises:
        ValueError: If required fields are missing.
    """
    has_no_info = fields.cdp_enabled is None or (
        fields.cdp_enabled and fields.send_interval is None
    )
    if has_no_info:
        msg = "No CDP global information found in output"
        raise ValueError(msg)

    if fields.cdp_enabled and fields.holdtime is None:
        msg = "No holdtime value found in output"
        raise ValueError(msg)

    if not fields.cdp_enabled:
        return ShowCdpResult(cdp_enabled=False, send_interval=0, holdtime=0)

    # send_interval and holdtime are guaranteed non-None by guards above
    result = _build_enabled_result(fields.send_interval, fields.holdtime)
    if fields.cdp_version is not None:
        result["cdp_version"] = fields.cdp_version
    if fields.device_id_type is not None:
        result["device_id_type"] = fields.device_id_type

    return result


@register(OS.CISCO_IOSXE, "show cdp")
class ShowCdpParser(BaseParser[ShowCdpResult]):
    """Parser for 'show cdp' command.

    Parses global CDP configuration settings from the device.

    Example output:
        Global CDP information:
                Sending CDP packets every 60 seconds
                Sending a holdtime value of 180 seconds
                Sending CDPv2 advertisements is  enabled
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.CDP})

    @classmethod
    def parse(cls, output: str) -> ShowCdpResult:
        """Parse 'show cdp' output.

        Args:
            output: Raw CLI output from 'show cdp' command.

        Returns:
            Parsed CDP global configuration data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        fields = _CdpFields()

        for line in output.splitlines():
            if line.strip():
                _parse_line(line, fields)

        return _build_result(fields)
