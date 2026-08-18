"""Parser for 'show line console 0' command on IOS."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class TtyTableEntry(TypedDict):
    """Schema for the single Tty summary table row."""

    tty: int
    type: str
    tx_rx: NotRequired[str]
    a: NotRequired[str]
    modem: NotRequired[str]
    roty: NotRequired[str]
    acco: NotRequired[str]
    acci: NotRequired[str]
    uses: int
    noise: int
    overruns: str
    int: NotRequired[str]


class SpecialCharsEntry(TypedDict):
    """Schema for the 'Special Chars' block."""

    escape: NotRequired[str]
    hold: NotRequired[str]
    stop: NotRequired[str]
    start: NotRequired[str]
    disconnect: NotRequired[str]
    activation: NotRequired[str]


class TimeoutsEntry(TypedDict):
    """Schema for the 'Timeouts' block."""

    idle_exec: NotRequired[str]
    idle_session: NotRequired[str]
    modem_answer: NotRequired[str]
    session: NotRequired[str]
    dispatch: NotRequired[str]
    idle_session_disconnect_warning: NotRequired[str]
    login_sequence_user_response: NotRequired[str]
    autoselect_initial_wait: NotRequired[str]


class ShowLineConsole0Result(TypedDict):
    """Schema for 'show line console 0' parsed output."""

    tty_table: NotRequired[TtyTableEntry]
    line: int
    location: NotRequired[str]
    type: NotRequired[str]
    length_lines: NotRequired[int]
    width_columns: NotRequired[int]
    baud_rate_tx: NotRequired[int]
    baud_rate_rx: NotRequired[int]
    parity: NotRequired[str]
    stopbits: NotRequired[str]
    databits: NotRequired[str]
    status: NotRequired[list[str]]
    capabilities: NotRequired[list[str]]
    modem_state: NotRequired[str]
    rj45_console: NotRequired[str]
    usb_console_baud_rate: NotRequired[int]
    special_chars: NotRequired[SpecialCharsEntry]
    timeouts: NotRequired[TimeoutsEntry]
    modem_type: NotRequired[str]
    session_limit: NotRequired[str]
    time_since_activation: NotRequired[str]
    editing_enabled: NotRequired[bool]
    history_enabled: NotRequired[bool]
    history_size: NotRequired[int]
    dns_resolution_enabled: NotRequired[bool]
    full_user_help_enabled: NotRequired[bool]
    allowed_input_transports: NotRequired[list[str]]
    allowed_output_transports: NotRequired[list[str]]
    preferred_transport: NotRequired[str]
    shell_enabled: NotRequired[bool]
    shell_trace: NotRequired[str]
    output_characters_padded: NotRequired[bool]
    special_data_dispatching_characters: NotRequired[bool]


# --- Regex patterns ---

# Tty table header: "Tty Typ     Tx/Rx ..."
_TTY_HEADER_RE = re.compile(r"^\s*Tty\s+Typ\s+Tx/Rx\s+", re.IGNORECASE)

# Tty table row matcher: row begins with a numeric Tty value followed by a
# non-numeric Type token. We split positionally and back-fill columns that
# may be elided (e.g. Tx/Rx blank for CTY lines).
_TTY_ROW_PREFIX_RE = re.compile(r"^\s*(?P<tty>\d+)\s+(?P<rest>\S.*\S)\s*$")

# Tty table columns in left-to-right order
_TTY_COLUMNS = (
    "type",
    "tx_rx",
    "a",
    "modem",
    "roty",
    "acco",
    "acci",
    "uses",
    "noise",
    "overruns",
    "int",
)

# Integer columns in the Tty table (parsed as int when not a placeholder)
_TTY_INT_COLUMNS = frozenset({"uses", "noise"})

# "Line 0, Location: "", Type: """
_LINE_HEADER_RE = re.compile(
    r'^Line\s+(?P<line>\d+),\s+Location:\s+"(?P<location>[^"]*)"'
    r',\s+Type:\s+"(?P<type>[^"]*)"\s*$'
)

# "Length: 24 lines, Width: 80 columns"
_LENGTH_WIDTH_RE = re.compile(
    r"^Length:\s+(?P<length>\d+)\s+lines?,\s+Width:\s+(?P<width>\d+)\s+columns?\s*$"
)

# "Baud rate (TX/RX) is 9600/9600, no parity, 2 stopbits, 8 databits"
_BAUD_RE = re.compile(
    r"^Baud\s+rate\s+\(TX/RX\)\s+is\s+(?P<tx>\d+)/(?P<rx>\d+)"
    r",\s+(?P<parity>[^,]+),\s+(?P<stopbits>\S+)\s+stopbits"
    r",\s+(?P<databits>\S+)\s+databits\s*$"
)

# "Status: Ready" - status may be comma-separated list
_STATUS_RE = re.compile(r"^Status:\s+(?P<status>.+?)\s*$")

# "Capabilities: none" - may be comma-separated list
_CAPABILITIES_RE = re.compile(r"^Capabilities:\s+(?P<caps>.+?)\s*$")

# "Modem state: Ready"
_MODEM_STATE_RE = re.compile(r"^Modem\s+state:\s+(?P<state>.+?)\s*$")

# "RJ45 Console is in use" or "RJ45 Console is not in use"
_RJ45_CONSOLE_RE = re.compile(r"^RJ45\s+Console\s+is\s+(?P<state>.+?)\s*$")

# "USB Console baud rate = 9600"
_USB_CONSOLE_RATE_RE = re.compile(
    r"^USB\s+Console\s+baud\s+rate\s+=\s+(?P<rate>\d+)\s*$"
)

# Special Chars header
_SPECIAL_CHARS_HDR_RE = re.compile(
    r"^Special\s+Chars:\s+Escape\s+Hold\s+Stop\s+Start\s+Disconnect\s+Activation\s*$"
)

# Timeouts header
_TIMEOUTS_HDR_RE = re.compile(
    r"^Timeouts:\s+Idle\s+EXEC\s+Idle\s+Session\s+Modem\s+Answer\s+Session\s+Dispatch\s*$"
)

# Sub-headers within the Timeouts block (indented, no leading "Timeouts:")
_TO_IDLE_SESSION_DISC_HDR_RE = re.compile(
    r"^\s+Idle\s+Session\s+Disconnect\s+Warning\s*$"
)
_TO_LOGIN_SEQUENCE_HDR_RE = re.compile(r"^\s+Login-sequence\s+User\s+Response\s*$")
_TO_AUTOSELECT_HDR_RE = re.compile(r"^\s+Autoselect\s+Initial\s+Wait\s*$")

# "Modem type is unknown."
_MODEM_TYPE_RE = re.compile(r"^Modem\s+type\s+is\s+(?P<type>.+?)\.?\s*$")

# "Session limit is not set." / "Session limit is N."
_SESSION_LIMIT_RE = re.compile(r"^Session\s+limit\s+is\s+(?P<limit>.+?)\.?\s*$")

# "Time since activation: never" / "Time since activation: 00:00:01"
_TIME_SINCE_RE = re.compile(r"^Time\s+since\s+activation:\s+(?P<value>.+?)\s*$")

# "Editing is enabled." / "Editing is disabled."
_EDITING_RE = re.compile(r"^Editing\s+is\s+(?P<state>enabled|disabled)\.?\s*$")

# "History is enabled, history size is 20."
_HISTORY_RE = re.compile(
    r"^History\s+is\s+(?P<state>enabled|disabled),\s+history\s+size\s+is\s+"
    r"(?P<size>\d+)\.?\s*$"
)

# "DNS resolution in show commands is enabled" / "...is disabled"
_DNS_RE = re.compile(
    r"^DNS\s+resolution\s+in\s+show\s+commands\s+is\s+(?P<state>enabled|disabled)\s*$"
)

# "Full user help is disabled" / "...is enabled"
_FULL_USER_HELP_RE = re.compile(
    r"^Full\s+user\s+help\s+is\s+(?P<state>enabled|disabled)\s*$"
)

# "Allowed input transports are none." / "...are telnet ssh."
_INPUT_TRANSPORTS_RE = re.compile(
    r"^Allowed\s+input\s+transports\s+are\s+(?P<transports>.+?)\.?\s*$"
)

# "Allowed output transports are telnet ssh."
_OUTPUT_TRANSPORTS_RE = re.compile(
    r"^Allowed\s+output\s+transports\s+are\s+(?P<transports>.+?)\.?\s*$"
)

# "Preferred transport is telnet."
_PREFERRED_TRANSPORT_RE = re.compile(
    r"^Preferred\s+transport\s+is\s+(?P<transport>.+?)\.?\s*$"
)

# "Shell: enabled" / "Shell: disabled"
_SHELL_RE = re.compile(r"^Shell:\s+(?P<state>enabled|disabled)\s*$")

# "Shell trace: off" / "Shell trace: on"
_SHELL_TRACE_RE = re.compile(r"^Shell\s+trace:\s+(?P<state>.+?)\s*$")

# "No output characters are padded" / "Output characters are padded"
_OUTPUT_PADDED_NO_RE = re.compile(r"^No\s+output\s+characters\s+are\s+padded\s*$")
_OUTPUT_PADDED_YES_RE = re.compile(r"^Output\s+characters\s+are\s+padded\s*$")

# "No special data dispatching characters" / "Special data dispatching characters"
_DISPATCH_CHARS_NO_RE = re.compile(
    r"^No\s+special\s+data\s+dispatching\s+characters\s*$"
)
_DISPATCH_CHARS_YES_RE = re.compile(r"^Special\s+data\s+dispatching\s+characters\s*$")

# Placeholder sentinels that should be omitted from output
_PLACEHOLDERS = frozenset({"-", "", "none"})

# Required fields for validation
_REQUIRED_FIELDS = ("line",)


def _split_list_field(value: str) -> list[str] | None:
    """Split a comma- or whitespace-separated list field into tokens.

    Returns None if the value is a placeholder like 'none' so the caller can
    omit the key entirely rather than emitting an empty list.
    """
    stripped = value.strip().rstrip(".")
    if stripped.lower() == "none":
        return None
    # Prefer comma-split if commas are present; otherwise whitespace
    if "," in stripped:
        tokens = [t.strip() for t in stripped.split(",") if t.strip()]
    else:
        tokens = [t for t in stripped.split() if t]
    return tokens or None


def _omit_placeholder(value: str | None) -> str | None:
    """Return None if value is a placeholder sentinel, else the trimmed value."""
    if value is None:
        return None
    trimmed = value.strip()
    if trimmed in _PLACEHOLDERS:
        return None
    return trimmed


def _parse_tty_row(tty: int, rest: str) -> TtyTableEntry | None:
    """Build a TtyTableEntry from a Tty row.

    The row uses positional, whitespace-aligned columns where any column may
    be blank or a '-' placeholder. We assume the rightmost columns
    (uses, noise, overruns, int) are always present and back-fill optional
    columns from the left when the row is short.

    Args:
        tty: Parsed integer Tty number.
        rest: The remainder of the row after the Tty number.

    Returns:
        A populated TtyTableEntry, or None if the row cannot be interpreted.
    """
    tokens = rest.split()
    # The fixed rightmost columns: uses, noise, overruns, int. Some captures
    # may omit Int (when the row simply has no interface), but the sample
    # output always renders a placeholder. We require at least 4 tokens to
    # match the minimum (type + uses + noise + overruns).
    min_tokens = 4
    if len(tokens) < min_tokens:
        return None

    column_count = len(_TTY_COLUMNS)
    # Pad missing middle columns from the left after `type`, since CTY rows
    # routinely omit Tx/Rx but always render the full right-side columns.
    if len(tokens) < column_count:
        missing = column_count - len(tokens)
        # Insert placeholder dashes after type (index 1) for the missing slots
        tokens = [tokens[0], *(["-"] * missing), *tokens[1:]]
    elif len(tokens) > column_count:
        # Should not happen for the documented sample; trim from the right.
        tokens = tokens[:column_count]

    entry: dict = {"tty": tty}
    for column, token in zip(_TTY_COLUMNS, tokens, strict=True):
        if column in _TTY_INT_COLUMNS:
            entry[column] = int(token)
            continue
        if column == "type":
            entry["type"] = token
            continue
        if column == "overruns":
            # Always recorded as a string (e.g. "0/0")
            entry["overruns"] = token
            continue
        value = _omit_placeholder(token)
        if value is not None:
            entry[column] = value
    return cast(TtyTableEntry, entry)


# Mapping from Special Chars header columns to result keys
_SPECIAL_CHARS_KEYS = ("escape", "hold", "stop", "start", "disconnect", "activation")

# Header column names (verbatim) → output keys for the main Timeouts table.
# Order matters: used to locate column start positions in the header line.
_TIMEOUTS_COLUMN_HEADERS: tuple[tuple[str, str], ...] = (
    ("Idle EXEC", "idle_exec"),
    ("Idle Session", "idle_session"),
    ("Modem Answer", "modem_answer"),
    ("Session", "session"),
    ("Dispatch", "dispatch"),
)


def _parse_special_chars_values(line: str) -> SpecialCharsEntry:
    """Parse the data row beneath the Special Chars header."""
    tokens = line.split()
    entry: dict = {}
    for key, token in zip(_SPECIAL_CHARS_KEYS, tokens, strict=False):
        value = _omit_placeholder(token)
        if value is not None:
            entry[key] = value
    return cast(SpecialCharsEntry, entry)


def _locate_timeouts_columns(header_line: str) -> list[tuple[int, str]]:
    """Return ``(start_col, output_key)`` for each Timeouts column header.

    Search for each known column name sequentially so that the standalone
    ``Session`` column is matched after ``Idle Session``.
    """
    columns: list[tuple[int, str]] = []
    cursor = 0
    for header_text, output_key in _TIMEOUTS_COLUMN_HEADERS:
        idx = header_line.find(header_text, cursor)
        if idx == -1:
            return []
        columns.append((idx, output_key))
        cursor = idx + len(header_text)
    return columns


def _parse_timeouts_main_values(
    line: str, columns: list[tuple[int, str]], timeouts: dict
) -> None:
    """Parse the data row beneath the main Timeouts header.

    IOS aligns Timeouts values within fixed column slots from the header row.
    Blank middle columns must not shift adjacent values, so slice the data
    line by each column's start position rather than whitespace-splitting.
    """
    if not columns:
        return
    for i, (start, key) in enumerate(columns):
        end = columns[i + 1][0] if i + 1 < len(columns) else len(line)
        raw = line[start:end].strip()
        value = _omit_placeholder(raw)
        if value is not None:
            timeouts[key] = value


# Internal state for the block-oriented parts of the parser
class _ParseState:
    """Mutable parse state to track block context across lines."""

    def __init__(self) -> None:
        self.expect_special_chars_values = False
        self.expect_timeouts_main_values = False
        self.timeouts_columns: list[tuple[int, str]] = []
        self.expect_idle_session_disconnect_value = False
        self.expect_login_sequence_value = False
        self.expect_autoselect_value = False


def _try_block_headers(line: str, stripped: str, state: _ParseState) -> bool:
    """Detect block headers (Special Chars / Timeouts and sub-headers)."""
    if _SPECIAL_CHARS_HDR_RE.match(stripped):
        state.expect_special_chars_values = True
        return True
    if _TIMEOUTS_HDR_RE.match(stripped):
        state.expect_timeouts_main_values = True
        state.timeouts_columns = _locate_timeouts_columns(line)
        return True
    return False


def _try_indented_timeout_subheaders(line: str, state: _ParseState) -> bool:
    """Detect indented sub-headers inside the Timeouts block."""
    if _TO_IDLE_SESSION_DISC_HDR_RE.match(line):
        state.expect_idle_session_disconnect_value = True
        return True
    if _TO_LOGIN_SEQUENCE_HDR_RE.match(line):
        state.expect_login_sequence_value = True
        return True
    if _TO_AUTOSELECT_HDR_RE.match(line):
        state.expect_autoselect_value = True
        return True
    return False


def _consume_block_value(
    line: str, stripped: str, state: _ParseState, result: dict, timeouts: dict
) -> bool:
    """Consume the data row immediately following a recognized block header."""
    if state.expect_special_chars_values:
        result["special_chars"] = _parse_special_chars_values(stripped)
        state.expect_special_chars_values = False
        return True
    if state.expect_timeouts_main_values:
        _parse_timeouts_main_values(line, state.timeouts_columns, timeouts)
        state.expect_timeouts_main_values = False
        state.timeouts_columns = []
        return True
    if state.expect_idle_session_disconnect_value:
        value = _omit_placeholder(stripped)
        if value is not None:
            timeouts["idle_session_disconnect_warning"] = value
        state.expect_idle_session_disconnect_value = False
        return True
    if state.expect_login_sequence_value:
        value = _omit_placeholder(stripped)
        if value is not None:
            timeouts["login_sequence_user_response"] = value
        state.expect_login_sequence_value = False
        return True
    if state.expect_autoselect_value:
        value = _omit_placeholder(stripped)
        if value is not None:
            timeouts["autoselect_initial_wait"] = value
        state.expect_autoselect_value = False
        return True
    return False


def _try_line_header(stripped: str, result: dict) -> bool:
    """Try to parse 'Line N, Location: "", Type: ""'."""
    match = _LINE_HEADER_RE.match(stripped)
    if not match:
        return False
    result["line"] = int(match.group("line"))
    location = match.group("location")
    if location:
        result["location"] = location
    type_value = match.group("type")
    if type_value:
        result["type"] = type_value
    return True


def _try_length_width(stripped: str, result: dict) -> bool:
    """Try to parse 'Length: N lines, Width: N columns'."""
    match = _LENGTH_WIDTH_RE.match(stripped)
    if not match:
        return False
    result["length_lines"] = int(match.group("length"))
    result["width_columns"] = int(match.group("width"))
    return True


def _try_baud(stripped: str, result: dict) -> bool:
    """Try to parse the baud rate / parity / stopbits / databits line."""
    match = _BAUD_RE.match(stripped)
    if not match:
        return False
    result["baud_rate_tx"] = int(match.group("tx"))
    result["baud_rate_rx"] = int(match.group("rx"))
    result["parity"] = match.group("parity").strip()
    result["stopbits"] = match.group("stopbits")
    result["databits"] = match.group("databits")
    return True


def _try_status_capabilities(stripped: str, result: dict) -> bool:
    """Try Status: / Capabilities: lines."""
    match = _STATUS_RE.match(stripped)
    if match:
        values = _split_list_field(match.group("status"))
        if values is not None:
            result["status"] = values
        return True
    match = _CAPABILITIES_RE.match(stripped)
    if match:
        values = _split_list_field(match.group("caps"))
        if values is not None:
            result["capabilities"] = values
        return True
    return False


def _try_modem_console(stripped: str, result: dict) -> bool:
    """Try modem state / RJ45 / USB console lines."""
    match = _MODEM_STATE_RE.match(stripped)
    if match:
        result["modem_state"] = match.group("state")
        return True
    match = _RJ45_CONSOLE_RE.match(stripped)
    if match:
        result["rj45_console"] = match.group("state")
        return True
    match = _USB_CONSOLE_RATE_RE.match(stripped)
    if match:
        result["usb_console_baud_rate"] = int(match.group("rate"))
        return True
    return False


def _try_modem_session_time(stripped: str, result: dict) -> bool:
    """Try modem type / session limit / time since activation lines."""
    match = _MODEM_TYPE_RE.match(stripped)
    if match:
        result["modem_type"] = match.group("type")
        return True
    match = _SESSION_LIMIT_RE.match(stripped)
    if match:
        result["session_limit"] = match.group("limit")
        return True
    match = _TIME_SINCE_RE.match(stripped)
    if match:
        result["time_since_activation"] = match.group("value")
        return True
    return False


def _try_toggles(stripped: str, result: dict) -> bool:
    """Try simple enabled/disabled toggle lines."""
    match = _EDITING_RE.match(stripped)
    if match:
        result["editing_enabled"] = match.group("state") == "enabled"
        return True
    match = _HISTORY_RE.match(stripped)
    if match:
        result["history_enabled"] = match.group("state") == "enabled"
        result["history_size"] = int(match.group("size"))
        return True
    match = _DNS_RE.match(stripped)
    if match:
        result["dns_resolution_enabled"] = match.group("state") == "enabled"
        return True
    match = _FULL_USER_HELP_RE.match(stripped)
    if match:
        result["full_user_help_enabled"] = match.group("state") == "enabled"
        return True
    return False


def _try_transports(stripped: str, result: dict) -> bool:
    """Try transport-related lines."""
    match = _INPUT_TRANSPORTS_RE.match(stripped)
    if match:
        values = _split_list_field(match.group("transports"))
        if values is not None:
            result["allowed_input_transports"] = values
        return True
    match = _OUTPUT_TRANSPORTS_RE.match(stripped)
    if match:
        values = _split_list_field(match.group("transports"))
        if values is not None:
            result["allowed_output_transports"] = values
        return True
    match = _PREFERRED_TRANSPORT_RE.match(stripped)
    if match:
        result["preferred_transport"] = match.group("transport")
        return True
    return False


def _try_shell(stripped: str, result: dict) -> bool:
    """Try shell-related lines."""
    match = _SHELL_RE.match(stripped)
    if match:
        result["shell_enabled"] = match.group("state") == "enabled"
        return True
    match = _SHELL_TRACE_RE.match(stripped)
    if match:
        result["shell_trace"] = match.group("state")
        return True
    return False


def _try_padding_dispatch(stripped: str, result: dict) -> bool:
    """Try output-padding / dispatching-character lines."""
    if _OUTPUT_PADDED_NO_RE.match(stripped):
        result["output_characters_padded"] = False
        return True
    if _OUTPUT_PADDED_YES_RE.match(stripped):
        result["output_characters_padded"] = True
        return True
    if _DISPATCH_CHARS_NO_RE.match(stripped):
        result["special_data_dispatching_characters"] = False
        return True
    if _DISPATCH_CHARS_YES_RE.match(stripped):
        result["special_data_dispatching_characters"] = True
        return True
    return False


def _try_tty_table(stripped: str, result: dict, state_in_table: list[bool]) -> bool:
    """Try Tty table header and the single data row that follows."""
    if _TTY_HEADER_RE.match(stripped):
        state_in_table[0] = True
        return True
    if state_in_table[0]:
        match = _TTY_ROW_PREFIX_RE.match(stripped)
        if match:
            entry = _parse_tty_row(int(match.group("tty")), match.group("rest"))
            if entry is not None:
                result["tty_table"] = entry
                state_in_table[0] = False
                return True
        # Any other content ends the table context
        state_in_table[0] = False
    return False


# Dispatch table for simple (stripped, result) handlers
_SIMPLE_HANDLERS = (
    _try_line_header,
    _try_length_width,
    _try_baud,
    _try_status_capabilities,
    _try_modem_console,
    _try_modem_session_time,
    _try_toggles,
    _try_transports,
    _try_shell,
    _try_padding_dispatch,
)


def _state_expects_block_value(state: _ParseState) -> bool:
    """Return True if a block data row is expected next."""
    return (
        state.expect_special_chars_values
        or state.expect_timeouts_main_values
        or state.expect_idle_session_disconnect_value
        or state.expect_login_sequence_value
        or state.expect_autoselect_value
    )


def _parse_line(
    line: str,
    result: dict,
    timeouts: dict,
    state: _ParseState,
    in_tty_table: list[bool],
) -> None:
    """Parse a single line of output, dispatching to specific handlers."""
    stripped = line.strip()
    if not stripped:
        return

    # Sub-headers inside the Timeouts block are indented; check before strip-only
    # logic to capture them, but only when not currently expecting a data row.
    if not _state_expects_block_value(state) and _try_indented_timeout_subheaders(
        line, state
    ):
        return

    if _consume_block_value(line, stripped, state, result, timeouts):
        return

    if _try_block_headers(line, stripped, state):
        return

    if _try_tty_table(stripped, result, in_tty_table):
        return

    for handler in _SIMPLE_HANDLERS:
        if handler(stripped, result):
            return


@register(OS.CISCO_IOS, "show line console 0")
class ShowLineConsole0Parser(BaseParser[ShowLineConsole0Result]):
    r"""Parser for 'show line console 0' on Cisco IOS.

    Parses the console line summary table and the detailed metadata block
    (line number, location, type, length/width, baud rate, status,
    capabilities, modem state, timeouts, transports, etc.).
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowLineConsole0Result:
        """Parse 'show line console 0' output.

        Args:
            output: Raw CLI output from 'show line console 0' command.

        Returns:
            Parsed console line configuration and status.

        Raises:
            ValueError: If required fields cannot be parsed from output.
        """
        result: dict = {}
        timeouts: dict = {}
        state = _ParseState()
        in_tty_table: list[bool] = [False]

        for line in output.splitlines():
            _parse_line(line, result, timeouts, state, in_tty_table)

        if timeouts:
            result["timeouts"] = cast(TimeoutsEntry, timeouts)

        for required in _REQUIRED_FIELDS:
            if required not in result:
                msg = f"Missing required field: {required}"
                raise ValueError(msg)

        return cast(ShowLineConsole0Result, result)
