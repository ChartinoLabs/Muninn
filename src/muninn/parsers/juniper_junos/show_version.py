"""Parser for 'show version' command on Juniper Junos."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class SoftwarePackage(TypedDict):
    """Schema for a software package entry."""

    name: str
    version: str


class ShowVersionResult(TypedDict):
    """Schema for 'show version' parsed output.

    Captures hostname, model, Junos version, and installed software packages
    from Juniper Junos devices (MX, EX, QFX, SRX, etc.).
    """

    hostname: str
    model: str
    junos_version: NotRequired[str]
    software_packages: list[SoftwarePackage]


@register(OS.JUNIPER_JUNOS, "show version")
class ShowVersionParser(BaseParser[ShowVersionResult]):
    """Parser for 'show version' command on Juniper Junos.

    Parses system version, model, hostname, and installed software packages.
    Supports output from single-chassis and multi-node (cluster) devices.
    When multiple FPCs or nodes are present, only the first node is parsed.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INVENTORY,
            ParserTag.SYSTEM,
        }
    )

    # Header line pattern for FPC/node sections (e.g., "fpc0:", "node0:")
    _NODE_HEADER = re.compile(r"^(?:fpc|node)\d+:\s*$")

    # Separator line of dashes
    _SEPARATOR = re.compile(r"^-{5,}\s*$")

    # Hostname, Model, Junos version
    _HOSTNAME = re.compile(r"^\s*Hostname:\s+(?P<hostname>\S+)\s*$")
    _MODEL = re.compile(r"^\s*Model:\s+(?P<model>\S+)\s*$")
    _JUNOS_VERSION = re.compile(r"^\s*Junos:\s+(?P<version>\S+)\s*$")

    # Software package line: "JUNOS Base OS boot [18.2R2-S1]" or
    # non-JUNOS packages like "labpkg [7.0]", "CHEF client bundle [...]"
    _PACKAGE = re.compile(
        r"^\s*(?P<name>.+?)\s+\[(?P<version>[^\]]+)\]\s*$",
    )

    # Junos prompt lines like "{master:0}" or "{primary:node0}"
    _PROMPT = re.compile(r"^\{.+\}\s*$")

    @classmethod
    def _is_skippable(cls, stripped: str) -> bool:
        """Return True if the line should be skipped entirely."""
        if not stripped:
            return True
        if cls._SEPARATOR.match(stripped):
            return True
        return bool(cls._PROMPT.match(stripped))

    @classmethod
    def _parse_line(cls, line: str, result: dict[str, object]) -> None:
        """Parse a single content line, updating result in place."""
        if "hostname" not in result:
            if match := cls._HOSTNAME.match(line):
                result["hostname"] = match.group("hostname")
                return

        if "model" not in result:
            if match := cls._MODEL.match(line):
                result["model"] = match.group("model")
                return

        if "junos_version" not in result:
            if match := cls._JUNOS_VERSION.match(line):
                result["junos_version"] = match.group("version")
                return

        if match := cls._PACKAGE.match(line):
            packages: list[SoftwarePackage] = result.setdefault(  # type: ignore[assignment]
                "software_packages", []
            )
            packages.append(
                SoftwarePackage(
                    name=match.group("name"),
                    version=match.group("version"),
                )
            )

    @classmethod
    def _extract_first_node_lines(cls, output: str) -> list[str]:
        """Extract lines belonging to the first FPC/node section only.

        For multi-node output (e.g., SRX clusters or EX virtual chassis),
        only the first section is returned to avoid duplicate data.
        """
        lines: list[str] = []
        first_node_parsed = False

        for line in output.splitlines():
            stripped = line.strip()

            if cls._NODE_HEADER.match(stripped):
                if first_node_parsed:
                    break
                first_node_parsed = True
                continue

            lines.append(line)

        return lines

    @classmethod
    def parse(cls, output: str) -> ShowVersionResult:
        """Parse 'show version' output on Juniper Junos.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed version information.

        Raises:
            ValueError: If required fields cannot be parsed.
        """
        result: dict[str, object] = {}

        for line in cls._extract_first_node_lines(output):
            stripped = line.strip()
            if cls._is_skippable(stripped):
                continue
            cls._parse_line(line, result)

        # Validate required fields
        missing = [f for f in ("hostname", "model") if f not in result]
        if missing:
            msg = f"Missing required fields: {', '.join(missing)}"
            raise ValueError(msg)

        # Ensure software_packages is always present
        result.setdefault("software_packages", [])

        return cast(ShowVersionResult, result)
