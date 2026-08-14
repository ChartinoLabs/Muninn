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

    # Ordered list of patterns to try against each line.
    # Each entry maps a compiled regex to field names that need .strip().
    _PATTERNS: ClassVar[list[tuple[re.Pattern[str], tuple[str, ...]]]] = []

    _REQUIRED_FIELDS: ClassVar[list[str]] = [
        "hostname",
        "model",
        "version",
        "build",
        "uuid",
        "lsp_version",
        "vdb_version",
    ]

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Populate _PATTERNS after class attributes are bound."""
        super().__init_subclass__(**kwargs)

    @classmethod
    def _init_patterns(cls) -> list[tuple[re.Pattern[str], tuple[str, ...]]]:
        """Build pattern list on first use (lazy class-level init)."""
        return [
            (cls._HOSTNAME, ("hostname",)),
            (cls._MODEL_VERSION, ("model", "version", "build")),
            (cls._UUID, ("uuid",)),
            (cls._LSP_VERSION, ("lsp_version",)),
            (cls._VDB_VERSION, ("vdb_version",)),
        ]

    @classmethod
    def _extract_fields(cls, output: str) -> dict[str, str]:
        """Extract all fields from raw CLI output using pattern matching."""
        patterns = cls._init_patterns()
        result: dict[str, str] = {}

        for line in output.splitlines():
            cls._match_line(line.strip(), patterns, result)

        return result

    @classmethod
    def _match_line(
        cls,
        line: str,
        patterns: list[tuple[re.Pattern[str], tuple[str, ...]]],
        result: dict[str, str],
    ) -> None:
        """Try each pattern against a single line, storing matches."""
        for pattern, fields in patterns:
            match = pattern.match(line)
            if match:
                for field in fields:
                    result[field] = match.group(field).strip()
                return

    @classmethod
    def _validate(cls, result: dict[str, str]) -> None:
        """Raise ValueError if any required fields are missing."""
        missing = [f for f in cls._REQUIRED_FIELDS if f not in result]
        if missing:
            msg = f"Missing required fields: {', '.join(missing)}"
            raise ValueError(msg)

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
        result = cls._extract_fields(output)
        cls._validate(result)

        return ShowVersionResult(
            hostname=result["hostname"],
            model=result["model"],
            version=result["version"],
            build=result["build"],
            uuid=result["uuid"],
            lsp_version=result["lsp_version"],
            vdb_version=result["vdb_version"],
        )
