"""Base parser class for all Muninn parsers."""

from abc import ABC, abstractmethod
from typing import Any, ClassVar


class BaseParser(ABC):
    """Abstract base class for all parsers.

    Subclasses must implement the `parse` classmethod to transform
    raw CLI output into structured data.

    Attributes:
        os: Operating system identifier (e.g., "nxos", "iosxe").
        command: The command this parser handles.
    """

    os: ClassVar[str]
    command: ClassVar[str]

    @classmethod
    @abstractmethod
    def parse(cls, output: str) -> dict[str, Any]:
        """Parse CLI output into structured data.

        Args:
            output: Raw CLI output string.

        Returns:
            Parsed structured data as a dictionary.
        """
        ...
