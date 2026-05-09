"""Parser for 'show krt queue' command on Juniper Junos."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class KrtQueueEntry(TypedDict):
    """Schema for a single KRT queue entry."""

    queued: int


class ShowKrtQueueResult(TypedDict):
    """Schema for 'show krt queue' parsed output.

    Dict keyed by queue name, each containing the queued count.
    """

    queues: dict[str, KrtQueueEntry]


@register(OS.JUNIPER_JUNOS, "show krt queue")
class ShowKrtQueueParser(BaseParser[ShowKrtQueueResult]):
    """Parser for 'show krt queue' command on Juniper Junos.

    Parses Kernel Routing Table (KRT) queue names and their queued counts.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ROUTING})

    _QUEUE_PATTERN = re.compile(r"^\s*(?P<name>.+?):\s+(?P<queued>\d+)\s+queued\s*$")

    @classmethod
    def parse(cls, output: str) -> ShowKrtQueueResult:
        """Parse 'show krt queue' output on Juniper Junos.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed KRT queue information.

        Raises:
            ValueError: If no queue entries are found.
        """
        queues: dict[str, KrtQueueEntry] = {}

        for line in output.splitlines():
            match = cls._QUEUE_PATTERN.match(line)
            if match:
                name = match.group("name")
                queued = int(match.group("queued"))
                queues[name] = KrtQueueEntry(queued=queued)

        if not queues:
            msg = "No KRT queue entries found in output"
            raise ValueError(msg)

        return ShowKrtQueueResult(queues=queues)
