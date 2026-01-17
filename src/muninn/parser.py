"""Base parser class for all Muninn parsers."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from muninn.os import OS


class BaseParser(ABC):
    """Abstract base class for all parsers.

    Subclasses must implement the `parse` classmethod to transform
    raw CLI output into structured data.

    Attributes:
        os: Operating system this parser is registered for.
        command: The command this parser handles.
    """

    os: ClassVar["OS"]
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
