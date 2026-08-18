"""Parser for 'show controllers ethernet-controller' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class ControllerEthernetCounterEntry(TypedDict):
    """Numeric counter under a label key."""

    value: str


class ControllerEthernetStatistics(TypedDict):
    """Per-column counters keyed by CLI label.

    Labels are unique keys; if the device repeats a label in the same column,
    later keys are suffixed `` (2)``, `` (3)``, ...
    """

    transmit: dict[str, ControllerEthernetCounterEntry]
    receive: dict[str, ControllerEthernetCounterEntry]


class ControllerEthernetInterfaceEntry(TypedDict):
    """Per-interface entry from 'show controllers ethernet-controller'."""

    statistics: ControllerEthernetStatistics
    last_update: NotRequired[str]


# Top-level schema is a mapping of canonical interface name to entry.
ShowControllersEthernetControllerResult = dict[str, ControllerEthernetInterfaceEntry]


# Header line identifying each interface block:
#   Transmit                  GigabitEthernet1/0/1          Receive
_IF_RE = re.compile(r"^Transmit\s+(?P<interface>\S+)\s+Receive\s*$", re.IGNORECASE)

# Footer line for each interface block:
#   LAST UPDATE 5392 msecs AGO
_LAST_RE = re.compile(r"^LAST UPDATE\s+(?P<value>.+)$", re.IGNORECASE)

# Two-column counter row: "<num> <label>  <num> <label>". Labels may contain
# single spaces (e.g. "Total bytes", "65 to 127 byte frames"). The two
# columns are separated by two or more spaces.
_STAT_ROW_FULL_RE = re.compile(
    r"^\s*(?P<tx_value>\d+)\s+(?P<tx_label>.+?)"
    r"\s{2,}(?P<rx_value>\d+)\s+(?P<rx_label>.+)$"
)

# Transmit-only continuation row (e.g. per-collision-count counters).
_STAT_ROW_TX_ONLY_RE = re.compile(r"^\s*(?P<tx_value>\d+)\s+(?P<tx_label>.+)$")


def _unique_label_key(d: dict[str, ControllerEthernetCounterEntry], label: str) -> str:
    """Return a key not already present in ``d`` (suffix duplicate labels)."""
    if label not in d:
        return label
    n = 2
    while f"{label} ({n})" in d:
        n += 1
    return f"{label} ({n})"


def _new_block() -> ControllerEthernetInterfaceEntry:
    """Return a fresh per-interface entry with empty statistics."""
    return ControllerEthernetInterfaceEntry(
        statistics=ControllerEthernetStatistics(transmit={}, receive={}),
    )


def _handle_full_row(
    match: re.Match[str], entry: ControllerEthernetInterfaceEntry
) -> None:
    """Apply a two-column counter row to ``entry``."""
    tx_label = match.group("tx_label").strip()
    rx_label = match.group("rx_label").strip()
    transmit = entry["statistics"]["transmit"]
    receive = entry["statistics"]["receive"]
    tx_key = _unique_label_key(transmit, tx_label)
    rx_key = _unique_label_key(receive, rx_label)
    transmit[tx_key] = ControllerEthernetCounterEntry(value=match.group("tx_value"))
    receive[rx_key] = ControllerEthernetCounterEntry(value=match.group("rx_value"))


def _handle_tx_only_row(
    match: re.Match[str], entry: ControllerEthernetInterfaceEntry
) -> None:
    """Apply a transmit-only continuation row to ``entry``."""
    tx_label = match.group("tx_label").strip()
    transmit = entry["statistics"]["transmit"]
    tx_key = _unique_label_key(transmit, tx_label)
    transmit[tx_key] = ControllerEthernetCounterEntry(value=match.group("tx_value"))


@register(OS.CISCO_IOSXE, "show controllers ethernet-controller")
class ShowControllersEthernetControllerParser(
    BaseParser[ShowControllersEthernetControllerResult]
):
    """Parser for 'show controllers ethernet-controller' on IOS-XE.

    The command emits one block per physical Ethernet interface. Each block
    starts with a header line identifying the interface (e.g.
    ``Transmit  GigabitEthernet1/0/1  Receive``) and ends with an optional
    ``LAST UPDATE`` footer.

    The parsed output is keyed by canonical interface name. Each entry
    contains a ``statistics`` sub-dict with ``transmit`` and ``receive``
    columns, where counter labels (as printed by the device) are dict keys
    and values are stringified integers.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    @classmethod
    def parse(cls, output: str) -> ShowControllersEthernetControllerResult:
        """Parse 'show controllers ethernet-controller' output."""
        result: dict[str, ControllerEthernetInterfaceEntry] = {}
        current_key: str | None = None

        for raw_line in output.splitlines():
            line = raw_line.rstrip()
            if not line.strip():
                continue

            if_match = _IF_RE.match(line.strip())
            if if_match:
                interface = canonical_interface_name(
                    if_match.group("interface"), os=OS.CISCO_IOSXE
                )
                result[interface] = _new_block()
                current_key = interface
                continue

            if current_key is None:
                # Skip any preamble before the first interface header.
                continue

            entry = result[current_key]

            last_match = _LAST_RE.match(line.strip())
            if last_match:
                entry["last_update"] = last_match.group("value").strip()
                continue

            full_match = _STAT_ROW_FULL_RE.match(line)
            if full_match:
                _handle_full_row(full_match, entry)
                continue

            tx_only_match = _STAT_ROW_TX_ONLY_RE.match(line)
            if tx_only_match:
                _handle_tx_only_row(tx_only_match, entry)
                continue

        if not result:
            msg = (
                "No interface blocks found in 'show controllers "
                "ethernet-controller' output"
            )
            raise ValueError(msg)

        return cast(ShowControllersEthernetControllerResult, result)
