"""Muninn exceptions."""


class MuninnError(Exception):
    """Base exception for all Muninn errors."""


class ParserNotFoundError(MuninnError):
    """Raised when no parser exists for the given OS/command combination."""

    def __init__(self, os: str, command: str) -> None:
        """Initialize the exception.

        Args:
            os: The operating system identifier.
            command: The command that was attempted.
        """
        self.os = os
        self.command = command
        super().__init__(f"No parser found for os={os!r}, command={command!r}")


class ParseError(MuninnError):
    """Raised when a parser fails to parse the given output."""

    def __init__(self, os: str, command: str, message: str) -> None:
        """Initialize the exception.

        Args:
            os: The operating system identifier.
            command: The command that produced the output.
            message: Description of what went wrong.
        """
        self.os = os
        self.command = command
        super().__init__(f"Failed to parse os={os!r}, command={command!r}: {message}")


class EmptyOutputError(MuninnError):
    """Raised when CLI output is empty or whitespace only."""

    def __init__(self, os: str, command: str) -> None:
        """Initialize the exception.

        Args:
            os: The operating system identifier.
            command: The command that produced the output.
        """
        self.os = os
        self.command = command
        super().__init__(f"Empty output for os={os!r}, command={command!r}")
