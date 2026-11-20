"""Parser for QFP active datapath utilization summary on IOS-XE.

Command: ``show platform hardware qfp active datapath utilization summary``.
"""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class IntervalEntry(TypedDict):
    """QFP datapath utilization measurements over a single time interval."""

    input_pps: NotRequired[int]
    input_bps: NotRequired[int]
    output_pps: NotRequired[int]
    output_bps: NotRequired[int]
    processing_load_pct: NotRequired[int]
    crypto_load_pct: NotRequired[int]
    rx_load_pct: NotRequired[int]
    tx_load_pct: NotRequired[int]
    idle_pct: NotRequired[int]


class CppEntry(TypedDict):
    """Single Cisco Packet Processor (CPP) datapath utilization block."""

    intervals: dict[str, IntervalEntry]


class ShowPlatformHardwareQfpActiveDatapathUtilizationSummaryResult(TypedDict):
    """Parsed QFP active datapath utilization summary output."""

    cpps: dict[str, CppEntry]


# Header line example:
#   "CPP 0:                     5 secs        1 min        5 min       60 min"
_CPP_HEADER_RE = re.compile(r"^CPP\s+(?P<cpp_id>\d+):\s+(?P<intervals>.+)$")

# Interval column header tokens like "5 secs", "1 min", "5 min", "60 min".
_INTERVAL_TOKEN_RE = re.compile(
    r"(?P<value>\d+)\s+(?P<unit>secs?|mins?|hrs?|hours?)",
)

# Data line with an optional label, an optional Total/Load/Idle sublabel,
# a unit in parentheses, and four integer values.
#
# Examples::
#   "Input:     Total (pps)           47           60           41           30"
#   "                 (bps)        38384        39128        28712        22840"
#   "Processing: Load (pct)            0            0            0            0"
#   "    Crypto: Load (pct)            0            0            0            0"
#   "        RX: Load (pct)            0            0            0            0"
#   "            Idle (pct)           98           98           98           98"
_METRIC_RE = re.compile(
    r"^\s*"
    r"(?:(?P<label>[A-Za-z][A-Za-z/ ]*?):\s+)?"
    r"(?:(?P<sublabel>Total|Load|Idle)\s+)?"
    r"\((?P<unit>pps|bps|pct)\)\s+"
    r"(?P<v1>\d+)\s+(?P<v2>\d+)\s+(?P<v3>\d+)\s+(?P<v4>\d+)\s*$",
)


def _normalize_interval(value: str, unit: str) -> str:
    """Convert column header tokens like ``5 secs`` into stable keys.

    Returns keys like ``5_secs``, ``1_min``, ``5_min``, ``60_min``.
    """
    unit_norm = unit.lower()
    if unit_norm.startswith("sec"):
        return f"{value}_secs"
    if unit_norm.startswith("min"):
        return f"{value}_min"
    if unit_norm.startswith("hr") or unit_norm.startswith("hour"):
        return f"{value}_hr"
    return f"{value}_{unit_norm}"


# Mapping of (section_lower, unit) -> schema field key. Sections seen in the
# sample: Input, Output, Processing, Crypto, RX, TX.
_FIELD_MAP: dict[tuple[str, str], str] = {
    ("input", "pps"): "input_pps",
    ("input", "bps"): "input_bps",
    ("output", "pps"): "output_pps",
    ("output", "bps"): "output_bps",
    ("processing", "pct"): "processing_load_pct",
    ("crypto", "pct"): "crypto_load_pct",
    ("rx", "pct"): "rx_load_pct",
    ("tx", "pct"): "tx_load_pct",
}


def _derive_field(
    section: str,
    sublabel: str | None,
    unit: str,
) -> str | None:
    """Map (section, sublabel, unit) to a schema key, or None to skip the line."""
    # An "Idle" sublabel indented under TX is the global idle counter.
    if sublabel and sublabel.lower() == "idle" and unit == "pct":
        return "idle_pct"
    return _FIELD_MAP.get((section.lower(), unit))


@register(
    OS.CISCO_IOSXE,
    "show platform hardware qfp active datapath utilization summary",
)
class ShowPlatformHardwareQfpActiveDatapathUtilizationSummaryParser(
    BaseParser[ShowPlatformHardwareQfpActiveDatapathUtilizationSummaryResult],
):
    """Parser for QFP active datapath utilization summary on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.PLATFORM, ParserTag.SYSTEM},
    )

    @classmethod
    def parse(
        cls,
        output: str,
    ) -> ShowPlatformHardwareQfpActiveDatapathUtilizationSummaryResult:
        """Parse QFP datapath utilization summary output.

        Args:
            output: Raw CLI output of the command.

        Returns:
            Parsed utilization data keyed by CPP id.

        Raises:
            ValueError: If no ``CPP <n>:`` header is found in the output.
        """
        cpps: dict[str, CppEntry] = {}
        current_cpp_id: str | None = None
        current_interval_keys: list[str] = []
        current_section: str | None = None

        for raw_line in output.splitlines():
            if not raw_line.strip():
                continue

            new_cpp_id, new_interval_keys = cls._try_header(raw_line)
            if new_cpp_id is not None:
                current_cpp_id = new_cpp_id
                current_interval_keys = new_interval_keys
                cpps[current_cpp_id] = {
                    "intervals": {key: {} for key in current_interval_keys},
                }
                current_section = None
                continue

            if current_cpp_id is None:
                continue

            current_section = cls._update_section(raw_line, current_section)
            cls._apply_metric_line(
                raw_line,
                cpps[current_cpp_id]["intervals"],
                current_interval_keys,
                current_section,
            )

        if not cpps:
            msg = "No 'CPP <n>:' header found in output"
            raise ValueError(msg)

        return cast(
            ShowPlatformHardwareQfpActiveDatapathUtilizationSummaryResult,
            {"cpps": cpps},
        )

    @staticmethod
    def _try_header(line: str) -> tuple[str | None, list[str]]:
        """Return (cpp_id, interval_keys) if `line` is a CPP header, else (None, [])."""
        match = _CPP_HEADER_RE.match(line)
        if not match:
            return None, []
        interval_keys = [
            _normalize_interval(m.group("value"), m.group("unit"))
            for m in _INTERVAL_TOKEN_RE.finditer(match.group("intervals"))
        ]
        return match.group("cpp_id"), interval_keys

    @staticmethod
    def _update_section(line: str, current_section: str | None) -> str | None:
        """Carry forward the most recent section label seen on data lines.

        The CLI uses ``Label:`` prefixes (Input, Output, Processing, Crypto, RX,
        TX) to denote sections. The bare ``Crypto/IO`` banner has no metric
        line and is not treated as a section change.
        """
        if line.strip() == "Crypto/IO":
            return current_section
        match = _METRIC_RE.match(line)
        if match and match.group("label"):
            return match.group("label").strip()
        return current_section

    @staticmethod
    def _apply_metric_line(
        line: str,
        intervals: dict[str, IntervalEntry],
        interval_keys: list[str],
        current_section: str | None,
    ) -> None:
        """If ``line`` is a metric line, write its 4 values into interval dicts."""
        match = _METRIC_RE.match(line)
        if not match:
            return
        unit = match.group("unit")
        sublabel = match.group("sublabel")
        # Section: explicit label on this line, else the carried section.
        label = match.group("label")
        section = label.strip() if label else current_section
        if section is None:
            return
        field = _derive_field(section, sublabel, unit)
        if field is None:
            return
        values = (
            int(match.group("v1")),
            int(match.group("v2")),
            int(match.group("v3")),
            int(match.group("v4")),
        )
        for key, value in zip(interval_keys, values, strict=False):
            interval_entry = cast(dict[str, int], intervals[key])
            interval_entry[field] = value
