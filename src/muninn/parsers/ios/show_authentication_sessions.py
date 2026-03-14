"""Parser for 'show authentication sessions' command on IOS."""

from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.parsers.ios._session_table import parse_session_table
from muninn.registry import register


class AuthSessionEntry(TypedDict):
    """Schema for a single authentication session entry."""

    method: str
    domain: str
    status: str
    session_id: str
    fg: NotRequired[str]


class ShowAuthenticationSessionsResult(TypedDict):
    """Schema for 'show authentication sessions' parsed output."""

    sessions: dict[str, dict[str, AuthSessionEntry]]
    session_count: NotRequired[int]


@register(OS.CISCO_IOS, "show authentication sessions")
class ShowAuthenticationSessionsParser(
    BaseParser[ShowAuthenticationSessionsResult],
):
    """Parser for 'show authentication sessions' on IOS."""

    @classmethod
    def parse(cls, output: str) -> ShowAuthenticationSessionsResult:
        """Parse 'show authentication sessions' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed authentication sessions keyed by interface, then MAC address.

        Raises:
            ValueError: If no sessions found or no header detected.
        """
        parsed = parse_session_table(
            output,
            missing_header_message=(
                "No authentication sessions header line found in output"
            ),
            missing_sessions_message="No authentication sessions found in output",
        )

        sessions: dict[str, dict[str, AuthSessionEntry]] = {}
        for entry in parsed["sessions"]:
            interface = entry["interface"]
            mac_address = entry["mac_address"]

            auth_entry: AuthSessionEntry = {
                "method": entry["method"],
                "domain": entry["domain"],
                "status": entry["status"],
                "session_id": entry["session_id"],
            }
            if "fg" in entry:
                auth_entry["fg"] = entry["fg"]

            if interface not in sessions:
                sessions[interface] = {}
            sessions[interface][mac_address] = auth_entry

        result: ShowAuthenticationSessionsResult = {"sessions": sessions}
        if "session_count" in parsed:
            result["session_count"] = parsed["session_count"]

        return result
