"""Parser for 'show ip ospf database' command on Arista EOS."""

import re
from dataclasses import dataclass, field
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class LSAEntry(TypedDict):
    """Schema for a single LSA entry."""

    advertising_router: str
    age: str
    sequence: str
    checksum: str
    link_count: NotRequired[int]
    tag: NotRequired[int]


class ShowIpOspfDatabaseResult(TypedDict):
    """Schema for 'show ip ospf database' parsed output on Arista EOS.

    Structure: top-level metadata plus areas dict keyed by area ID,
    then by LSA type, then by link-state ID, then by advertising router.
    Type-5 external LSAs are stored under a separate top-level key
    since they are not associated with an area.
    """

    router_id: str
    process_id: int
    areas: dict[str, dict[str, dict[str, dict[str, LSAEntry]]]]
    external_lsas: NotRequired[dict[str, dict[str, LSAEntry]]]


# LSA type labels as they appear in EOS output, mapped to normalized keys.
_LSA_TYPE_MAP: dict[str, str] = {
    "Router Link States": "router",
    "Net Link States": "network",
    "Summary Net Link States": "summary",
    "Summary ASB Link States": "asbr_summary",
    "Type-5 AS External Link States": "external",
    "Type-7 AS External Link States": "nssa_external",
}


@dataclass
class _ParseState:
    """Mutable state accumulated while walking OSPF database output."""

    router_id: str | None = None
    process_id: int | None = None
    areas: dict[str, dict[str, dict[str, dict[str, LSAEntry]]]] = field(
        default_factory=dict
    )
    external_lsas: dict[str, dict[str, LSAEntry]] = field(default_factory=dict)
    current_area: str | None = None
    current_lsa_type_key: str | None = None
    is_external: bool = False


@register(OS.ARISTA_EOS, "show ip ospf database")
class ShowIpOspfDatabaseParser(BaseParser[ShowIpOspfDatabaseResult]):
    """Parser for 'show ip ospf database' command on Arista EOS.

    Parses OSPF LSDB summary into a nested dict structure keyed by
    area, LSA type, link-state ID, and advertising router.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.OSPF, ParserTag.ROUTING}
    )

    _HEADER = re.compile(
        r"OSPF Router with ID\((?P<router_id>\S+)\)"
        r"\s+\(Process ID (?P<process_id>\d+)\)"
    )
    _AREA_LSA_TYPE = re.compile(
        r"^\s*(?P<lsa_type>Router Link States"
        r"|Net Link States"
        r"|Summary Net Link States"
        r"|Summary ASB Link States"
        r"|Type-7 AS External Link States)"
        r"\s+\(Area (?P<area>\S+)\)"
    )
    _EXTERNAL_LSA_TYPE = re.compile(
        r"^\s*(?P<lsa_type>Type-5 AS External Link States)\s*$"
    )
    _LSA_ENTRY = re.compile(
        r"^(?P<link_id>\d+\.\d+\.\d+\.\d+)\s+"
        r"(?P<adv_router>\d+\.\d+\.\d+\.\d+)\s+"
        r"(?P<age>\S+)\s+"
        r"(?P<seq>0x\S+)\s+"
        r"(?P<checksum>0x\S+)"
        r"(?:\s+(?P<extra>\S+))?\s*$"
    )

    @classmethod
    def _build_lsa_entry(
        cls,
        match: re.Match[str],
        lsa_type_key: str,
    ) -> LSAEntry:
        """Build an LSAEntry dict from a regex match."""
        entry = LSAEntry(
            advertising_router=match.group("adv_router"),
            age=match.group("age"),
            sequence=match.group("seq"),
            checksum=match.group("checksum"),
        )
        extra = match.group("extra")
        if lsa_type_key == "router" and extra is not None:
            entry["link_count"] = int(extra)
        elif lsa_type_key == "external" and extra is not None:
            entry["tag"] = int(extra)
        return entry

    @classmethod
    def _handle_section_header(cls, line: str, state: _ParseState) -> bool:
        """Detect and apply LSA section headers. Return True if matched."""
        area_match = cls._AREA_LSA_TYPE.search(line)
        if area_match:
            lsa_label = area_match.group("lsa_type")
            state.current_area = area_match.group("area")
            state.current_lsa_type_key = _LSA_TYPE_MAP[lsa_label]
            state.is_external = False
            state.areas.setdefault(state.current_area, {})
            state.areas[state.current_area].setdefault(state.current_lsa_type_key, {})
            return True

        ext_match = cls._EXTERNAL_LSA_TYPE.search(line)
        if ext_match:
            lsa_label = ext_match.group("lsa_type")
            state.current_lsa_type_key = _LSA_TYPE_MAP[lsa_label]
            state.is_external = True
            state.current_area = None
            return True

        return False

    @classmethod
    def _store_lsa_entry(
        cls,
        entry: LSAEntry,
        link_id: str,
        state: _ParseState,
    ) -> None:
        """Insert a parsed LSA entry into the appropriate collection."""
        adv_router = entry["advertising_router"]
        if state.is_external:
            state.external_lsas.setdefault(link_id, {})
            state.external_lsas[link_id][adv_router] = entry
        elif state.current_area is not None and state.current_lsa_type_key is not None:
            lsa_bucket = state.areas[state.current_area][state.current_lsa_type_key]
            lsa_bucket.setdefault(link_id, {})
            lsa_bucket[link_id][adv_router] = entry

    @classmethod
    def _process_line(cls, line: str, state: _ParseState) -> None:
        """Process a single non-header line, updating state in place."""
        stripped = line.strip()
        if not stripped or stripped.startswith("Link ID"):
            return

        if cls._handle_section_header(line, state):
            return

        if state.current_lsa_type_key is None:
            return

        entry_match = cls._LSA_ENTRY.match(stripped)
        if entry_match:
            entry = cls._build_lsa_entry(entry_match, state.current_lsa_type_key)
            cls._store_lsa_entry(entry, entry_match.group("link_id"), state)

    @classmethod
    def _build_result(cls, state: _ParseState) -> ShowIpOspfDatabaseResult:
        """Validate state and build the final result dict."""
        if state.router_id is None or state.process_id is None:
            msg = "OSPF header not found in output"
            raise ValueError(msg)

        result = ShowIpOspfDatabaseResult(
            router_id=state.router_id,
            process_id=state.process_id,
            areas=state.areas,
        )
        if state.external_lsas:
            result["external_lsas"] = state.external_lsas
        return result

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfDatabaseResult:
        """Parse 'show ip ospf database' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed OSPF database information.

        Raises:
            ValueError: If the OSPF header cannot be found.
        """
        state = _ParseState()

        for line in output.splitlines():
            if state.router_id is None:
                header_match = cls._HEADER.search(line)
                if header_match:
                    state.router_id = header_match.group("router_id")
                    state.process_id = int(header_match.group("process_id"))
                continue

            cls._process_line(line, state)

        return cls._build_result(state)
