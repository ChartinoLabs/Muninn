"""Parser for 'show ip ospf events' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag

_HEADER_RE = re.compile(
    r"OSPF Router with ID \((" + IPV4_ADDRESS + r")\)"
    r" \(Process ID (\d+)\)"
)

_EVENT_RE = re.compile(
    r"(\S+\s+\d+\s+\d+:\d+:\d+\.\d+):\s+"
    r"(Rcv|Generate)\s+"
    r"(Changed|Unchanged)\s+"
    r"Type-(\d+)\s+LSA,\s+"
    r"LSID\s+(" + IPV4_ADDRESS + r"),"
)

_ADV_RTR_RE = re.compile(r"Adv-Rtr\s+(" + IPV4_ADDRESS + r"),")

_SEQ_RE = re.compile(r"Seq#\s+([0-9A-Fa-f]+),")

_AGE_RE = re.compile(r"Age\s+(\d+),")

_AREA_RE = re.compile(r"Area\s+(\S+)")


class EventEntry(TypedDict):
    """Schema for a single OSPF event."""

    timestamp: str
    action: str
    status: str
    lsa_type: int
    lsid: str
    adv_router: NotRequired[str]
    sequence: str
    age: int
    area: str


class ShowIpOspfEventsResult(TypedDict):
    """Schema for 'show ip ospf events' parsed output."""

    router_id: str
    process_id: int
    events: dict[str, EventEntry]


@register(OS.CISCO_IOSXE, "show ip ospf events")
class ShowIpOspfEventsParser(BaseParser["ShowIpOspfEventsResult"]):
    """Parser for 'show ip ospf events' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.OSPF})

    @classmethod
    def parse(cls, output: str) -> "ShowIpOspfEventsResult":
        """Parse show ip ospf events output into structured data."""
        router_id = ""
        process_id = 0
        events: dict[str, EventEntry] = {}

        lines = output.splitlines()
        full_text = output

        for line in lines:
            header_match = _HEADER_RE.search(line)
            if header_match:
                router_id = header_match.group(1)
                process_id = int(header_match.group(2))
                break

        # Events can wrap across lines; split by leading event index.
        event_blocks = re.split(r"(?m)^(\d+)\s+", full_text)

        # event_blocks: ['preamble', '1', 'rest...', '2', 'rest...', ...]
        i = 1
        while i < len(event_blocks) - 1:
            index = event_blocks[i]
            block = event_blocks[i + 1]
            # Collapse any newlines within the block into a single line
            block_single = " ".join(block.split())
            event = cls._parse_event_block(block_single)
            if event is not None:
                events[index] = event
            i += 2

        if not router_id:
            msg = "Missing required field: router_id"
            raise ValueError(msg)

        return cast(
            "ShowIpOspfEventsResult",
            {
                "router_id": router_id,
                "process_id": process_id,
                "events": events,
            },
        )

    @classmethod
    def _parse_event_block(cls, block: str) -> EventEntry | None:
        """Parse a single event block into an EventEntry."""
        event_match = _EVENT_RE.search(block)
        if not event_match:
            return None

        timestamp = event_match.group(1)
        action = event_match.group(2)
        status = event_match.group(3)
        lsa_type = int(event_match.group(4))
        lsid = event_match.group(5)

        seq_match = _SEQ_RE.search(block)
        age_match = _AGE_RE.search(block)
        area_match = _AREA_RE.search(block)

        if not seq_match or not age_match or not area_match:
            return None

        sequence = seq_match.group(1)
        age = int(age_match.group(1))
        area = area_match.group(1)

        entry: dict[str, str | int] = {
            "timestamp": timestamp,
            "action": action,
            "status": status,
            "lsa_type": lsa_type,
            "lsid": lsid,
            "sequence": sequence,
            "age": age,
            "area": area,
        }

        adv_match = _ADV_RTR_RE.search(block)
        if adv_match:
            entry["adv_router"] = adv_match.group(1)

        return cast(EventEntry, entry)
