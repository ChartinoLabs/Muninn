"""Base parser class for all Muninn parsers."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar, Generic, TypeVar

from muninn.tags import ParserTag

if TYPE_CHECKING:
    from muninn.os import OS


T_co = TypeVar("T_co", covariant=True)


class BaseParser(ABC, Generic[T_co]):
    """Abstract base class for all parsers.

    Subclasses must implement the `parse` classmethod to transform
    raw CLI output into structured data.

    Attributes:
        os: Operating system this parser is registered for.
        command: The command this parser handles.
        tags: Descriptive tags for categorizing the parser (e.g., "routing", "ospf").
    """

    os: ClassVar["OS"]
    command: ClassVar[str]
    tags: ClassVar[frozenset[ParserTag]] = frozenset()

    @classmethod
    @abstractmethod
    def parse(cls, output: str) -> T_co:
        """Parse CLI output into structured data.

        Args:
            output: Raw CLI output string.

        Returns:
            Parsed structured data as a dictionary.
        """
        ...
