"""Parser for 'show install inactive' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class SdrInfo(TypedDict):
    """Schema for a single SDR's inactive install information."""

    inactive_packages: list[str]


class ShowInstallInactiveResult(TypedDict):
    """Schema for 'show install inactive' parsed output on IOS-XR.

    IOS-XR prints one of two layouts, and the result carries the keys of
    the layout it was given:

    Top-level keys:
        sdrs: Classic layout. Dict keyed by SDR name (e.g. "Owner")
            mapping to SDR details including the list of inactive packages.
        package_count: IOS-XR 7.x layout. The count from the
            "N inactive package(s) found:" header.
        inactive_packages: IOS-XR 7.x layout. The inactive packages, in
            the order the device lists them.
    """

    sdrs: NotRequired[dict[str, SdrInfo]]
    package_count: NotRequired[int]
    inactive_packages: NotRequired[list[str]]


@register(OS.CISCO_IOSXR, "show install inactive")
class ShowInstallInactiveParser(BaseParser[ShowInstallInactiveResult]):
    """Parser for 'show install inactive' command on Cisco IOS-XR.

    Parses the inactive installed packages, listing packages available for
    activation or removal. The classic layout groups them per SDR (Secure
    Domain Router); the IOS-XR 7.x layout is a flat, counted list.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    _SDRS_HEADER = re.compile(r"^\s+SDRs:\s*$")
    _INACTIVE_PACKAGES_HEADER = re.compile(r"^\s+Inactive Packages:\s*$")
    _PACKAGE = re.compile(r"^\s+(?P<package>\S+)\s*$")
    _SDR_NAME = re.compile(r"^\s+(?P<sdr_name>\S+)\s*$")
    # IOS-XR 7.x: "14 inactive package(s) found:" followed by indented packages.
    _FLAT_HEADER = re.compile(r"^(?P<count>\d+) inactive package\(s\) found:\s*$")

    @classmethod
    def parse(cls, output: str) -> ShowInstallInactiveResult:
        """Parse 'show install inactive' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed install information with SDRs and their inactive
            packages.

        Raises:
            ValueError: If neither layout can be parsed.
        """
        flat = cls._parse_flat(output)
        if flat is not None:
            return flat

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
    def _parse_flat(cls, output: str) -> ShowInstallInactiveResult | None:
        """Parse the IOS-XR 7.x layout, or return None if it is not that layout."""
        lines = iter(output.splitlines())
        for line in lines:
            if header := cls._FLAT_HEADER.match(line.strip()):
                break
        else:
            return None

        packages = [
            match.group("package")
            for line in lines
            if (match := cls._PACKAGE.match(line))
        ]
        return {
            "package_count": int(header.group("count")),
            "inactive_packages": packages,
        }

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
