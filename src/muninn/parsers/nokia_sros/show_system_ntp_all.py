"""Parser for 'show system ntp all' command on Nokia SR OS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class NtpAssociationEntry(TypedDict):
    """Schema for a single NTP association entry."""

    state: str
    reference_id: str
    stratum: NotRequired[int]
    type: str
    poll: int
    reach: str
    offset_ms: float
    router: str


class NtpStatusSection(TypedDict):
    """Schema for the NTP status section."""

    configured: bool
    stratum: int
    admin_status: str
    oper_status: str
    server_enabled: bool
    server_authenticate: bool
    clock_source: str
    auth_check: bool
    current_datetime: str


class ShowSystemNtpAllResult(TypedDict):
    """Schema for 'show system ntp all' parsed output."""

    status: NtpStatusSection
    associations: dict[str, NtpAssociationEntry]


@register(OS.NOKIA_SROS, "show system ntp all")
class ShowSystemNtpAllParser(BaseParser[ShowSystemNtpAllResult]):
    """Parser for 'show system ntp all' command on Nokia SR OS.

    Parses the NTP status section and active associations table,
    returning structured status information and a dict of associations
    keyed by remote server address.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    _SEPARATOR = re.compile(r"^[=\-]{10,}$")

    # Status key-value pairs on a line (may have two pairs)
    _STATUS_KV = re.compile(
        r"(?P<key>[A-Za-z &]+?)\s*:\s*"
        r"(?P<value>\S+(?:\s+\S+)*?)(?:\s{2,}|$)"
    )

    # Association data row with all columns
    _ASSOC_ROW = re.compile(
        r"^(?P<state>\S+)\s+"
        r"(?P<ref_id>\S+)\s+"
        r"(?P<stratum>\d+|-)\s+"
        r"(?P<type>\S+)\s+"
        r"(?P<auth>\S+)\s+"
        r"(?P<poll>\d+)\s+"
        r"(?P<reach>\S+)\s+"
        r"(?P<offset>-?\d+\.\d+)\s*$"
    )

    # Continuation line with router and remote address
    _ASSOC_CONT = re.compile(r"^\s+(?P<router>\S+)\s+(?P<remote>\S+)\s*$")

    # Header lines in associations table
    _ASSOC_HEADER = re.compile(r"^\s*State\s+Reference ID", re.I)
    _ASSOC_HEADER_CONT = re.compile(r"^\s*Router\s+Remote", re.I)

    # Section title lines
    _SECTION_TITLE = re.compile(
        r"^\s*NTP\s+(Status|Active Associations|Clients)\s*$", re.I
    )

    _YES_NO_MAP: ClassVar[dict[str, bool]] = {"yes": True, "no": False}

    _STATUS_KEY_MAP: ClassVar[dict[str, str]] = {
        "configured": "configured",
        "stratum": "stratum",
        "admin status": "admin_status",
        "oper status": "oper_status",
        "server enabled": "server_enabled",
        "server authenticate": "server_authenticate",
        "clock source": "clock_source",
        "auth check": "auth_check",
        "current date & time": "current_datetime",
    }

    @classmethod
    def _parse_status_value(cls, key: str, raw: str) -> bool | int | str:
        """Convert a raw status value to the appropriate Python type."""
        lower = raw.lower()
        if key in {"configured", "server_enabled", "server_authenticate", "auth_check"}:
            return cls._YES_NO_MAP.get(lower, raw)
        if key == "stratum":
            return int(raw)
        return raw

    @classmethod
    def _parse_status_section(cls, lines: list[str]) -> NtpStatusSection:
        """Extract NTP status key-value pairs from the status section lines."""
        raw_pairs: dict[str, str] = {}
        for line in lines:
            for match in cls._STATUS_KV.finditer(line):
                raw_key = match.group("key").strip().lower()
                raw_val = match.group("value").strip()
                mapped = cls._STATUS_KEY_MAP.get(raw_key)
                if mapped:
                    raw_pairs[mapped] = raw_val

        result: dict[str, bool | int | str] = {}
        for mapped_key, raw_val in raw_pairs.items():
            result[mapped_key] = cls._parse_status_value(mapped_key, raw_val)

        return cast(NtpStatusSection, result)

    @classmethod
    def _parse_associations_section(
        cls, lines: list[str]
    ) -> dict[str, NtpAssociationEntry]:
        """Parse the NTP active associations table."""
        associations: dict[str, NtpAssociationEntry] = {}
        pending_entry: NtpAssociationEntry | None = None

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if cls._SEPARATOR.match(stripped):
                continue
            if cls._ASSOC_HEADER.match(stripped):
                continue
            if cls._ASSOC_HEADER_CONT.match(stripped):
                continue

            row_match = cls._ASSOC_ROW.match(stripped)
            if row_match:
                entry: NtpAssociationEntry = {
                    "state": row_match.group("state"),
                    "reference_id": row_match.group("ref_id"),
                    "type": row_match.group("type"),
                    "poll": int(row_match.group("poll")),
                    "reach": row_match.group("reach"),
                    "offset_ms": float(row_match.group("offset")),
                    "router": "",
                }
                stratum_raw = row_match.group("stratum")
                if stratum_raw != "-":
                    entry["stratum"] = int(stratum_raw)
                pending_entry = entry
                continue

            cont_match = cls._ASSOC_CONT.match(line)
            if cont_match and pending_entry is not None:
                remote = cont_match.group("remote")
                pending_entry["router"] = cont_match.group("router")
                associations[remote] = pending_entry
                pending_entry = None
                continue

        return associations

    @classmethod
    def parse(cls, output: str) -> ShowSystemNtpAllResult:
        """Parse 'show system ntp all' output on Nokia SR OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict with 'status' and 'associations' sections.

        Raises:
            ValueError: If no NTP status information can be parsed.
        """
        all_lines = output.splitlines()

        # Identify section boundaries by separator blocks
        status_lines: list[str] = []
        assoc_lines: list[str] = []
        current_section: str | None = None

        for line in all_lines:
            stripped = line.strip()
            if cls._SECTION_TITLE.match(stripped):
                title_lower = stripped.lower()
                if "status" in title_lower:
                    current_section = "status"
                elif "active associations" in title_lower:
                    current_section = "associations"
                elif "clients" in title_lower:
                    current_section = "clients"
                continue

            if current_section == "status":
                status_lines.append(line)
            elif current_section == "associations":
                assoc_lines.append(line)

        status = cls._parse_status_section(status_lines)
        if not status:
            msg = "No NTP status information found in output"
            raise ValueError(msg)

        associations = cls._parse_associations_section(assoc_lines)

        return ShowSystemNtpAllResult(
            status=status,
            associations=associations,
        )
