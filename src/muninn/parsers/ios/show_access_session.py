"""Parser for 'show access-session' command on IOS."""

from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.parsers.ios._session_table import parse_session_table
from muninn.registry import register


class AccessSessionEntry(TypedDict):
    """Schema for a single access session entry."""

    interface: str
    mac_address: str
    method: str
    domain: str
    status: str
    flags: NotRequired[str]


class ShowAccessSessionResult(TypedDict):
    """Schema for 'show access-session' parsed output."""

    sessions: dict[str, AccessSessionEntry]


@register(OS.CISCO_IOS, "show access-session")
class ShowAccessSessionParser(BaseParser[ShowAccessSessionResult]):
    """Parser for 'show access-session' command.

    Example output::

        Interface  MAC Address     Method  Domain  Status   Session ID
        Fa3/0/40   (unknown)       mab     UNKNOWN Running  0A5C...01FF
        Fa3/0/13   002a.12cd.3d08  mab     DATA    Auth     0A0A...01FF

    Sessions are keyed by session ID since the same interface can host
    multiple sessions (e.g. DATA and VOICE on the same port).
    """

    @classmethod
    def parse(cls, output: str) -> ShowAccessSessionResult:
        """Parse 'show access-session' output.

        Args:
            output: Raw CLI output from 'show access-session' command.

        Returns:
            Parsed sessions keyed by session ID.

        Raises:
            ValueError: If no sessions found in output.
        """
        parsed = parse_session_table(
            output,
            missing_header_message="No access sessions header line found in output",
            missing_sessions_message="No access sessions found in output",
        )

        sessions: dict[str, AccessSessionEntry] = {}
        for parsed_entry in parsed["sessions"]:
            entry: AccessSessionEntry = {
                "interface": parsed_entry["interface"],
                "mac_address": parsed_entry["mac_address"],
                "method": parsed_entry["method"],
                "domain": parsed_entry["domain"],
                "status": parsed_entry["status"],
            }

            if "fg" in parsed_entry:
                entry["flags"] = parsed_entry["fg"]

            sessions[parsed_entry["session_id"]] = entry

        return ShowAccessSessionResult(sessions=sessions)
