"""Parser for 'show install inactive' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class SdrInfo(TypedDict):
    """Schema for a single SDR's inactive install information."""

    inactive_packages: list[str]


class ShowInstallInactiveResult(TypedDict):
    """Schema for 'show install inactive' parsed output on IOS-XR.

    Top-level keys:
        sdrs: Dict keyed by SDR name (e.g. "Owner") mapping to
            SDR details including the list of inactive packages.
    """

    sdrs: dict[str, SdrInfo]


@register(OS.CISCO_IOSXR, "show install inactive")
class ShowInstallInactiveParser(BaseParser[ShowInstallInactiveResult]):
    """Parser for 'show install inactive' command on Cisco IOS-XR.

    Parses the inactive installed packages per SDR (Secure Domain Router),
    listing packages available for activation or removal.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    _SDRS_HEADER = re.compile(r"^\s+SDRs:\s*$")
    _INACTIVE_PACKAGES_HEADER = re.compile(r"^\s+Inactive Packages:\s*$")
    _PACKAGE = re.compile(r"^\s+(?P<package>\S+)\s*$")
    _SDR_NAME = re.compile(r"^\s+(?P<sdr_name>\S+)\s*$")

    @classmethod
    def parse(cls, output: str) -> ShowInstallInactiveResult:
        """Parse 'show install inactive' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed install information with SDRs and their inactive
            packages.

        Raises:
            ValueError: If no SDR information can be parsed.
        """
        sdrs: dict[str, SdrInfo] = {}
        current_sdr: str | None = None
        in_sdrs = False
        in_packages = False

        for line in output.splitlines():
            if not line.strip():
                continue

            if cls._SDRS_HEADER.match(line):
                in_sdrs = True
                in_packages = False
                continue

            if cls._INACTIVE_PACKAGES_HEADER.match(line):
                in_sdrs = False
                in_packages = True
                continue

            if in_sdrs:
                current_sdr = cls._handle_sdr_line(line, sdrs, current_sdr)
                continue

            if in_packages and current_sdr is not None:
                in_packages = cls._handle_package_line(line, sdrs, current_sdr)

        if not sdrs:
            msg = "No SDR information found in output"
            raise ValueError(msg)

        return ShowInstallInactiveResult(sdrs=sdrs)

    @classmethod
    def _handle_sdr_line(
        cls, line: str, sdrs: dict[str, SdrInfo], current_sdr: str | None
    ) -> str | None:
        """Handle a line in the SDRs section, returning updated current_sdr."""
        if match := cls._SDR_NAME.match(line):
            sdr_name = match.group("sdr_name")
            sdrs[sdr_name] = SdrInfo(inactive_packages=[])
            return sdr_name
        return current_sdr

    @classmethod
    def _handle_package_line(
        cls, line: str, sdrs: dict[str, SdrInfo], current_sdr: str
    ) -> bool:
        """Handle a line in the packages section."""
        if match := cls._PACKAGE.match(line):
            sdrs[current_sdr]["inactive_packages"].append(match.group("package"))
            return True
        return False
