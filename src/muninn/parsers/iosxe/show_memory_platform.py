"""Parser for 'show memory platform' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class MemoryKbBlock(TypedDict):
    """Schema for the 'Memory (kB)' sub-block."""

    physical: NotRequired[int]
    total: NotRequired[int]
    used: NotRequired[int]
    free: NotRequired[int]
    active: NotRequired[int]
    inactive: NotRequired[int]
    inact_dirty: NotRequired[int]
    inact_clean: NotRequired[int]
    dirty: NotRequired[int]
    anonpages: NotRequired[int]
    bounce: NotRequired[int]
    cached: NotRequired[int]
    commit_limit: NotRequired[int]
    committed_as: NotRequired[int]
    high_total: NotRequired[int]
    high_free: NotRequired[int]
    low_total: NotRequired[int]
    low_free: NotRequired[int]
    mapped: NotRequired[int]
    nfs_unstable: NotRequired[int]
    page_tables: NotRequired[int]
    slab: NotRequired[int]
    writeback: NotRequired[int]
    hugepages_total: NotRequired[int]
    hugepages_free: NotRequired[int]
    hugepages_rsvd: NotRequired[int]
    hugepage_size: NotRequired[int]


class SwapKbBlock(TypedDict):
    """Schema for the 'Swap (kB)' sub-block."""

    total: NotRequired[int]
    used: NotRequired[int]
    free: NotRequired[int]
    cached: NotRequired[int]


class LoadAverageBlock(TypedDict):
    """Schema for the 'Load Average' sub-block."""

    one_min: NotRequired[float]
    five_min: NotRequired[float]
    fifteen_min: NotRequired[float]


class ShowMemoryPlatformResult(TypedDict):
    """Schema for 'show memory platform' parsed output."""

    virtual_memory_bytes: int
    pages_resident: int
    major_page_faults: int
    minor_page_faults: int
    architecture: NotRequired[str]
    memory_kb: NotRequired[MemoryKbBlock]
    swap_kb: NotRequired[SwapKbBlock]
    buffers_kb: NotRequired[int]
    load_average: NotRequired[LoadAverageBlock]


# Section header lines
_MEMORY_HEADER_RE = re.compile(r"^Memory\s*\(kB\)\s*$")
_SWAP_HEADER_RE = re.compile(r"^Swap\s*\(kB\)\s*$")
_LOAD_AVG_HEADER_RE = re.compile(r"^Load Average\s*$")

# Top-level scalar lines (no parent section)
_VIRTUAL_MEMORY_RE = re.compile(r"^Virtual memory\s*:\s*(?P<value>\d+)\s*$")
_PAGES_RESIDENT_RE = re.compile(r"^Pages resident\s*:\s*(?P<value>\d+)\s*$")
_MAJOR_FAULTS_RE = re.compile(r"^Major page faults\s*:\s*(?P<value>\d+)\s*$")
_MINOR_FAULTS_RE = re.compile(r"^Minor page faults\s*:\s*(?P<value>\d+)\s*$")
_ARCHITECTURE_RE = re.compile(r"^Architecture\s*:\s*(?P<value>\S+)\s*$")
_BUFFERS_RE = re.compile(r"^Buffers\s*\(kB\)\s*:\s*(?P<value>\d+)\s*$")

# Generic "label : value" line used inside Memory/Swap blocks.
_INT_FIELD_RE = re.compile(
    r"^(?P<label>[A-Za-z][A-Za-z0-9 \-]*?)\s*:\s*(?P<value>\d+)\s*$"
)

# Float "label : value" line used inside Load Average block, e.g. "1-Min : 1.52".
_FLOAT_FIELD_RE = re.compile(
    r"^(?P<label>[A-Za-z0-9][A-Za-z0-9 \-]*?)\s*:\s*(?P<value>\d+\.\d+)\s*$"
)


# Label -> schema-key maps. Anything not in the map is ignored (forward-compat).
_MEMORY_LABEL_MAP: dict[str, str] = {
    "Physical": "physical",
    "Total": "total",
    "Used": "used",
    "Free": "free",
    "Active": "active",
    "Inactive": "inactive",
    "Inact-dirty": "inact_dirty",
    "Inact-clean": "inact_clean",
    "Dirty": "dirty",
    "AnonPages": "anonpages",
    "Bounce": "bounce",
    "Cached": "cached",
    "Commit Limit": "commit_limit",
    "Committed As": "committed_as",
    "High Total": "high_total",
    "High Free": "high_free",
    "Low Total": "low_total",
    "Low Free": "low_free",
    "Mapped": "mapped",
    "NFS Unstable": "nfs_unstable",
    "Page Tables": "page_tables",
    "Slab": "slab",
    "Writeback": "writeback",
    "HugePages Total": "hugepages_total",
    "HugePages Free": "hugepages_free",
    "HugePages Rsvd": "hugepages_rsvd",
    "HugePage Size": "hugepage_size",
}

_SWAP_LABEL_MAP: dict[str, str] = {
    "Total": "total",
    "Used": "used",
    "Free": "free",
    "Cached": "cached",
}

_LOAD_LABEL_MAP: dict[str, str] = {
    "1-Min": "one_min",
    "5-Min": "five_min",
    "15-Min": "fifteen_min",
}


# Mapping of (regex, schema-key, converter) used by the top-level scalar matcher.
_TOP_LEVEL_SCALARS: tuple[tuple[re.Pattern[str], str, type], ...] = (
    (_VIRTUAL_MEMORY_RE, "virtual_memory_bytes", int),
    (_PAGES_RESIDENT_RE, "pages_resident", int),
    (_MAJOR_FAULTS_RE, "major_page_faults", int),
    (_MINOR_FAULTS_RE, "minor_page_faults", int),
    (_ARCHITECTURE_RE, "architecture", str),
    (_BUFFERS_RE, "buffers_kb", int),
)


def _try_top_level_scalar(line: str, result: dict[str, object]) -> bool:
    """Match a top-level scalar line and update result. Returns True if matched."""
    for pattern, key, converter in _TOP_LEVEL_SCALARS:
        match = pattern.match(line)
        if match:
            result[key] = converter(match.group("value"))
            return True
    return False


# Mapping of section-header regexes to their internal section identifier.
_SECTION_HEADERS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_MEMORY_HEADER_RE, "memory"),
    (_SWAP_HEADER_RE, "swap"),
    (_LOAD_AVG_HEADER_RE, "load"),
)


def _try_section_header(line: str) -> str | None:
    """Return the section identifier if line is a section header, else None."""
    for pattern, name in _SECTION_HEADERS:
        if pattern.match(line):
            return name
    return None


def _dispatch_section_line(
    line: str,
    current_section: str | None,
    memory_block: dict[str, int],
    swap_block: dict[str, int],
    load_block: dict[str, float],
) -> None:
    """Dispatch a non-header, non-top-level line to the active sub-block."""
    if current_section == "memory":
        _try_int_block_field(line, memory_block, _MEMORY_LABEL_MAP)
    elif current_section == "swap":
        _try_int_block_field(line, swap_block, _SWAP_LABEL_MAP)
    elif current_section == "load":
        _try_float_block_field(line, load_block, _LOAD_LABEL_MAP)


def _validate_required(result: dict[str, object]) -> None:
    """Raise ValueError if any required top-level scalar field is missing."""
    for required in (
        "virtual_memory_bytes",
        "pages_resident",
        "major_page_faults",
        "minor_page_faults",
    ):
        if required not in result:
            msg = f"Missing required field: {required}"
            raise ValueError(msg)


def _try_int_block_field(
    line: str, block: dict[str, int], label_map: dict[str, str]
) -> bool:
    """Insert an int field into a sub-block. Returns True if matched."""
    match = _INT_FIELD_RE.match(line)
    if not match:
        return False
    label = match.group("label").strip()
    key = label_map.get(label)
    if key is None:
        return False
    block[key] = int(match.group("value"))
    return True


def _try_float_block_field(
    line: str, block: dict[str, float], label_map: dict[str, str]
) -> bool:
    """Insert a float field into a sub-block. Returns True if matched."""
    match = _FLOAT_FIELD_RE.match(line)
    if not match:
        return False
    label = match.group("label").strip()
    key = label_map.get(label)
    if key is None:
        return False
    block[key] = float(match.group("value"))
    return True


@register(OS.CISCO_IOSXE, "show memory platform")
class ShowMemoryPlatformParser(BaseParser[ShowMemoryPlatformResult]):
    r"""Parser for 'show memory platform' on IOS-XE.

    Example output::

        Virtual memory   : 24663146496
          Pages resident   : 934874
          Major page faults: 11383
          Minor page faults: 112726047

          Architecture     : x86_64
          Memory (kB)
            Physical       : 15985428
            Total          : 15985428
            ...

          Swap (kB)
            Total          : 0
            ...

          Buffers (kB)     : 988732

          Load Average
            1-Min          : 1.52
            5-Min          : 1.37
            15-Min         : 1.36
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.PLATFORM, ParserTag.SYSTEM}
    )

    @classmethod
    def parse(cls, output: str) -> ShowMemoryPlatformResult:
        """Parse 'show memory platform' output."""
        result: dict[str, object] = {}
        memory_block: dict[str, int] = {}
        swap_block: dict[str, int] = {}
        load_block: dict[str, float] = {}
        current_section: str | None = None

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            section = _try_section_header(line)
            if section is not None:
                current_section = section
                continue

            # Top-level scalar fields can appear before / between sub-blocks
            # and end the current sub-block when they do.
            if _try_top_level_scalar(line, result):
                current_section = None
                continue

            _dispatch_section_line(
                line, current_section, memory_block, swap_block, load_block
            )

        if memory_block:
            result["memory_kb"] = memory_block
        if swap_block:
            result["swap_kb"] = swap_block
        if load_block:
            result["load_average"] = load_block

        _validate_required(result)
        return cast(ShowMemoryPlatformResult, result)
