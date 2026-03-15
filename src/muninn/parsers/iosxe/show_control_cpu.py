"""Parser for 'show control cpu' command on IOS-XE."""

import re
from typing import TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class QueueEntry(TypedDict):
    """Schema for a single CPU control-plane queue."""

    retrieved: int
    dropped: int
    invalid: int
    hol_block: int


class ShowControlCpuResult(TypedDict):
    """Schema for 'show control cpu' parsed output."""

    queues: dict[str, QueueEntry]


# Matches data lines: queue name followed by four integer counters.
# Queue names may contain letters, digits, hyphens, and spaces.
# Example: "Routing Protocol           327         0           0           0"
_QUEUE_LINE = re.compile(
    r"^(?P<name>.+?)\s{2,}"
    r"(?P<retrieved>\d+)\s+"
    r"(?P<dropped>\d+)\s+"
    r"(?P<invalid>\d+)\s+"
    r"(?P<hol_block>\d+)\s*$"
)

# Header and separator lines to skip
_SKIP = re.compile(r"^(?:queue\s|---)")


@register(OS.CISCO_IOSXE, "show control cpu")
class ShowControlCpuParser(BaseParser[ShowControlCpuResult]):
    """Parser for 'show control cpu' command.

    Example output::

        queue                      retrieved   dropped     invalid     hol-block
        -------------------------------------------------------------------------
        Routing Protocol           327         0           0           0
        L2 Protocol                23362       0           0           0
        sw forwarding              433         425         0           0
        broadcast                  0           0           0           0
    """

    @classmethod
    def parse(cls, output: str) -> ShowControlCpuResult:
        """Parse 'show control cpu' output.

        Args:
            output: Raw CLI output from 'show control cpu'.

        Returns:
            Parsed CPU control-plane queue statistics keyed by queue name.

        Raises:
            ValueError: If no queue data is found in the output.
        """
        queues: dict[str, QueueEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or _SKIP.match(stripped):
                continue
            # Skip command echo lines
            if stripped.startswith("show control"):
                continue

            match = _QUEUE_LINE.match(stripped)
            if match:
                name = match.group("name").strip()
                queues[name] = QueueEntry(
                    retrieved=int(match.group("retrieved")),
                    dropped=int(match.group("dropped")),
                    invalid=int(match.group("invalid")),
                    hol_block=int(match.group("hol_block")),
                )

        if not queues:
            msg = "No CPU control-plane queue data found in output"
            raise ValueError(msg)

        return ShowControlCpuResult(queues=queues)
