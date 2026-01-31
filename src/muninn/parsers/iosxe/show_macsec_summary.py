"""Parser for 'show macsec summary' command on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from netutils.interface import canonical_interface_name

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class MacsecSummaryInterface(TypedDict):
    """Schema for MACsec summary interface counters."""

    transmit_sc: int
    receive_sc: int


class MacsecCapableInterface(TypedDict):
    """Schema for MACsec-capable interface details."""

    extension: str
    installed_rx_sc: NotRequired[int]


class MacsecEnabledInterface(TypedDict):
    """Schema for MACsec-enabled interface details."""

    receive_sc: int
    vlan: int


class ShowMacsecSummaryResult(TypedDict):
    """Schema for 'show macsec summary' parsed output."""

    has_secure_channels: bool
    summary_interfaces: dict[str, MacsecSummaryInterface]
    macsec_capable: dict[str, MacsecCapableInterface]
    macsec_enabled: dict[str, MacsecEnabledInterface]


@register(OS.CISCO_IOSXE, "show macsec summary")
class ShowMacsecSummaryParser(BaseParser[ShowMacsecSummaryResult]):
    """Parser for 'show macsec summary' command."""

    _NO_CHANNELS_PATTERN = re.compile(r"^%?No\s+Secure\s+Channels$", re.I)
    _SUMMARY_HEADER = re.compile(r"^Interface\s+Transmit\s+SC\s+Receive\s+SC$", re.I)
    _CAPABLE_HEADER = re.compile(r"^MACsec\s+Capable\s+Interface", re.I)
    _ENABLED_HEADER = re.compile(r"^MACsec\s+Enabled\s+Interface", re.I)
    _SEPARATOR = re.compile(r"^[-=]+$")

    @staticmethod
    def _normalize_interface(interface: str) -> str:
        return canonical_interface_name(interface)

    @classmethod
    def _parse_summary_parts(
        cls, parts: list[str], result: ShowMacsecSummaryResult
    ) -> bool:
        if len(parts) < 3:
            return False
        interface = cls._normalize_interface(parts[0].strip())
        result["summary_interfaces"][interface] = {
            "transmit_sc": int(parts[1].strip()),
            "receive_sc": int(parts[2].strip()),
        }
        return True

    @classmethod
    def _parse_capable_parts(
        cls, parts: list[str], result: ShowMacsecSummaryResult
    ) -> bool:
        if len(parts) < 2:
            return False
        interface = cls._normalize_interface(parts[0].strip())
        entry: dict[str, object] = {"extension": parts[1].strip()}
        if len(parts) >= 3 and parts[2].strip():
            entry["installed_rx_sc"] = int(parts[2].strip())
        result["macsec_capable"][interface] = entry
        return True

    @classmethod
    def _parse_enabled_parts(
        cls, parts: list[str], result: ShowMacsecSummaryResult
    ) -> bool:
        if len(parts) >= 4 and parts[1].strip() == ":":
            parts = [parts[0], parts[2], parts[3]]
        if len(parts) < 3:
            return False
        interface = cls._normalize_interface(parts[0].strip().rstrip(":"))
        result["macsec_enabled"][interface] = {
            "receive_sc": int(parts[1].strip()),
            "vlan": int(parts[2].strip()),
        }
        return True

    @classmethod
    def parse(cls, output: str) -> ShowMacsecSummaryResult:
        """Parse 'show macsec summary' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed MACsec summary.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        result: ShowMacsecSummaryResult = {
            "has_secure_channels": True,
            "summary_interfaces": {},
            "macsec_capable": {},
            "macsec_enabled": {},
        }
        mode: str | None = None
        handlers = {
            "summary": cls._parse_summary_parts,
            "capable": cls._parse_capable_parts,
            "enabled": cls._parse_enabled_parts,
        }

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if cls._NO_CHANNELS_PATTERN.match(line):
                result["has_secure_channels"] = False
                return result

            if cls._SUMMARY_HEADER.match(line):
                mode = "summary"
                continue

            if cls._CAPABLE_HEADER.match(line):
                mode = "capable"
                continue

            if cls._ENABLED_HEADER.match(line):
                mode = "enabled"
                continue

            if cls._SEPARATOR.match(line):
                continue

            parts = re.split(r"\s{2,}", line)
            if mode in handlers and handlers[mode](parts, result):
                continue

        if (
            result["summary_interfaces"]
            or result["macsec_capable"]
            or result["macsec_enabled"]
        ):
            return result

        msg = "No MACsec summary data found"
        raise ValueError(msg)
