"""Parser for 'show version' command on Cisco FTD."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowVersionResult(TypedDict):
    """Schema for 'show version' parsed output on Cisco FTD."""

    hostname: str
    model: str
    version: str
    build: str
    uuid: str
    lsp_version: str
    vdb_version: str


@register(OS.CISCO_FTD, "show version")
class ShowVersionParser(BaseParser[ShowVersionResult]):
    """Parser for 'show version' command on Cisco FTD.

    Parses device identity, software version, and signature database
    versions from the FTD version summary output.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INVENTORY})

    _HOSTNAME = re.compile(r"^-+\[\s*(?P<hostname>\S+)\s*\]-+$")
    _MODEL_VERSION = re.compile(
        r"^Model\s*:\s*(?P<model>.+?)\s+Version\s+(?P<version>\S+)\s+"
        r"\(Build\s+(?P<build>\d+)\)",
    )
    _UUID = re.compile(r"^UUID\s*:\s*(?P<uuid>\S+)")
    _LSP_VERSION = re.compile(r"^LSP version\s*:\s*(?P<lsp_version>\S+)")
    _VDB_VERSION = re.compile(r"^VDB version\s*:\s*(?P<vdb_version>\S+)")

    @classmethod
    def parse(cls, output: str) -> ShowVersionResult:
        """Parse 'show version' output on Cisco FTD.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed version information.

        Raises:
            ValueError: If required fields cannot be parsed.
        """
        result: dict[str, str] = {}

        for line in output.splitlines():
            line = line.strip()

            if match := cls._HOSTNAME.match(line):
                result["hostname"] = match.group("hostname")
            elif match := cls._MODEL_VERSION.match(line):
                result["model"] = match.group("model").strip()
                result["version"] = match.group("version")
                result["build"] = match.group("build")
            elif match := cls._UUID.match(line):
                result["uuid"] = match.group("uuid")
            elif match := cls._LSP_VERSION.match(line):
                result["lsp_version"] = match.group("lsp_version")
            elif match := cls._VDB_VERSION.match(line):
                result["vdb_version"] = match.group("vdb_version")

        required = [
            "hostname",
            "model",
            "version",
            "build",
            "uuid",
            "lsp_version",
            "vdb_version",
        ]
        missing = [f for f in required if f not in result]
        if missing:
            msg = f"Missing required fields: {', '.join(missing)}"
            raise ValueError(msg)

        return ShowVersionResult(
            hostname=result["hostname"],
            model=result["model"],
            version=result["version"],
            build=result["build"],
            uuid=result["uuid"],
            lsp_version=result["lsp_version"],
            vdb_version=result["vdb_version"],
        )
