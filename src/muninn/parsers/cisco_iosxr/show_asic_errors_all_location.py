"""Parser for 'show asic-errors all location' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class AsicInstanceErrors(TypedDict):
    """Error counters for a single ASIC instance."""

    number_of_nodes: int
    sbe_error_count: int
    mbe_error_count: int
    parity_error_count: int
    crc_error_count: int
    generic_error_count: int
    reset_error_count: int


# ASIC name -> instance ID (str) -> error counters
ShowAsicErrorsAllLocationResult = dict[str, dict[str, AsicInstanceErrors]]


@register(
    OS.CISCO_IOSXR,
    r"show asic-errors all location (?P<location>\S+)",
)
class ShowAsicErrorsAllLocationParser(
    BaseParser[ShowAsicErrorsAllLocationResult],
):
    """Parser for 'show asic-errors all location <location>' on Cisco IOS-XR.

    Parses ASIC error summaries grouped by ASIC type and instance number.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.PLATFORM})

    # Header line: "*                  Fia ASIC Error Summary                  *"
    _ASIC_HEADER = re.compile(
        r"^\*\s+(?P<asic>\S+)\s+ASIC Error Summary\s+\*$",
    )

    # Key-value lines within an instance block
    _FIELD_PATTERN = re.compile(
        r"^(?P<key>[A-Za-z_ ]+?)\s+:\s+(?P<value>\d+)\s*$",
    )

    @classmethod
    def parse(cls, output: str) -> ShowAsicErrorsAllLocationResult:
        """Parse 'show asic-errors all location' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Dict keyed by ASIC name, each containing a dict keyed by
            instance ID with error counters.

        Raises:
            ValueError: If no ASIC error summary blocks are found.
        """
        result: ShowAsicErrorsAllLocationResult = {}
        current_asic: str | None = None
        current_instance: dict[str, int] = {}
        current_instance_id: str | None = None

        for line in output.splitlines():
            stripped = line.strip()

            # Detect ASIC header
            header_match = cls._ASIC_HEADER.match(stripped)
            if header_match:
                # Save previous instance if pending
                cls._save_instance(
                    result, current_asic, current_instance_id, current_instance
                )
                current_asic = header_match.group("asic")
                current_instance_id = None
                current_instance = {}
                if current_asic not in result:
                    result[current_asic] = {}
                continue

            if current_asic is None:
                continue

            # Parse key-value field lines
            field_match = cls._FIELD_PATTERN.match(stripped)
            if field_match:
                key = field_match.group("key").strip()
                value = int(field_match.group("value"))
                normalized = key.lower().replace(" ", "_")

                if normalized == "instance":
                    # Save the previous instance before starting a new one
                    cls._save_instance(
                        result,
                        current_asic,
                        current_instance_id,
                        current_instance,
                    )
                    current_instance_id = str(value)
                    current_instance = {}
                else:
                    current_instance[normalized] = value

            # Separator line ends an instance block (but we accumulate until
            # the next Instance line or header, so no action needed here)

        # Save the last pending instance
        cls._save_instance(result, current_asic, current_instance_id, current_instance)

        if not result:
            msg = "No ASIC error summary blocks found in output"
            raise ValueError(msg)

        return result

    @staticmethod
    def _save_instance(
        result: ShowAsicErrorsAllLocationResult,
        asic: str | None,
        instance_id: str | None,
        fields: dict[str, int],
    ) -> None:
        """Store a completed instance block into the result dict."""
        if asic is None or instance_id is None or not fields:
            return
        result[asic][instance_id] = AsicInstanceErrors(
            number_of_nodes=fields.get("number_of_nodes", 0),
            sbe_error_count=fields.get("sbe_error_count", 0),
            mbe_error_count=fields.get("mbe_error_count", 0),
            parity_error_count=fields.get("parity_error_count", 0),
            crc_error_count=fields.get("crc_error_count", 0),
            generic_error_count=fields.get("generic_error_count", 0),
            reset_error_count=fields.get("reset_error_count", 0),
        )
