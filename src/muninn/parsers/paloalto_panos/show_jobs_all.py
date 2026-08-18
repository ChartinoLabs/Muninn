"""Parser for 'show jobs all' command on Palo Alto PAN-OS."""

import re
from typing import ClassVar, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowJobsAllEntry(TypedDict):
    """Schema for a single job entry."""

    enqueued: str
    job_type: str
    status: str
    result: str
    completed: NotRequired[str]


ShowJobsAllResult = dict[str, ShowJobsAllEntry]


@register(OS.PALOALTO_PANOS, "show jobs all")
class ShowJobsAllParser(BaseParser[ShowJobsAllResult]):
    """Parser for 'show jobs all' command on Palo Alto PAN-OS.

    Parses the tabular job listing into a dict-of-dicts keyed by job ID.
    Each entry contains the enqueued timestamp, job type, status, result,
    and completed time.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    # Match lines like:
    # 2016/04/28 03:05:24        2341      FqdnRefresh       FIN     OK 03:05:41
    _JOB_LINE = re.compile(
        r"^(?P<enqueued>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})"
        r"\s+(?P<id>\d+)"
        r"\s+(?P<type>\S+)"
        r"\s+(?P<status>\S+)"
        r"\s+(?P<result>\S+)"
        r"(?:\s+(?P<completed>\S+))?"
    )

    @classmethod
    def parse(cls, output: str) -> ShowJobsAllResult:
        """Parse 'show jobs all' output on PAN-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict of job entries keyed by job ID string.

        Raises:
            ValueError: If no job entries are found in the output.
        """
        result: ShowJobsAllResult = {}

        for line in output.splitlines():
            match = cls._JOB_LINE.match(line.strip())
            if not match:
                continue

            job_id = match.group("id")
            entry = ShowJobsAllEntry(
                enqueued=match.group("enqueued"),
                job_type=match.group("type"),
                status=match.group("status"),
                result=match.group("result"),
            )

            completed = match.group("completed")
            if completed:
                entry["completed"] = completed

            result[job_id] = entry

        if not result:
            msg = "No job entries found in output"
            raise ValueError(msg)

        return result
