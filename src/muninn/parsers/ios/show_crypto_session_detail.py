"""Parser for 'show crypto session detail' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class IkeSaEntry(TypedDict):
    """Schema for an IKE Security Association."""

    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    sa_status: str
    capabilities: NotRequired[str]
    connid: NotRequired[int]
    lifetime: NotRequired[str]


IkeSaTree = dict[str, dict[str, dict[str, dict[str, IkeSaEntry]]]]


class IpsecSaEntry(TypedDict):
    """Schema for an IPsec Security Association (inbound or outbound)."""

    spi: str
    transform: NotRequired[str]
    in_use_settings: NotRequired[str]
    conn_id: NotRequired[int]
    flow_id: NotRequired[str]


class IpsecFlowEntry(TypedDict):
    """Schema for an IPsec flow within a crypto session."""

    active_sas: int
    origin: str
    pkts_encaps: NotRequired[int]
    pkts_encrypt: NotRequired[int]
    pkts_digest: NotRequired[int]
    pkts_decaps: NotRequired[int]
    pkts_decrypt: NotRequired[int]
    pkts_verify: NotRequired[int]
    local_crypto_endpt: NotRequired[str]
    remote_crypto_endpt: NotRequired[str]
    path_mtu: NotRequired[int]
    ip_mtu: NotRequired[int]
    current_outbound_spi: NotRequired[str]
    inbound_esp_sas: NotRequired[list[IpsecSaEntry]]
    outbound_esp_sas: NotRequired[list[IpsecSaEntry]]


class CryptoSessionEntry(TypedDict):
    """Schema for a single crypto session."""

    peer_address: str
    peer_port: int
    status: str
    interface: NotRequired[str]
    uptime: NotRequired[str]
    session_status: NotRequired[str]
    fvrf: NotRequired[str]
    phase1_id: NotRequired[str]
    desc: NotRequired[str]
    username: NotRequired[str]
    profile: NotRequired[str]
    ivrf: NotRequired[str]
    ike_sa: NotRequired[IkeSaTree]
    ipsec_flow: NotRequired[dict[str, IpsecFlowEntry]]


class ShowCryptoSessionDetailResult(TypedDict):
    """Schema for 'show crypto session detail' parsed output."""

    sessions: dict[str, CryptoSessionEntry]


# --- Regex patterns ---

_CRYPTO_SESSION_HEADER_RE = re.compile(r"^\s*Crypto session current status\s*$")

_INTERFACE_RE = re.compile(r"^\s*Interface:\s+(\S+)\s*$")

_UPTIME_RE = re.compile(r"^\s*Uptime:\s+(.+?)\s*$")

_PEER_RE = re.compile(r"^\s*Peer:\s+(\S+)\s+port\s+(\d+)\s*$")

_STATUS_RE = re.compile(r"^\s*Status:\s+(.+?)\s*$")

_SESSION_STATUS_RE = re.compile(r"^\s*Session status:\s+(.+?)\s*$")

_FVRF_RE = re.compile(r"^\s*FVRF:\s+(\S+)\s*$")

_IVRF_RE = re.compile(r"^\s*IVRF:\s+(\S+)\s*$")

_PHASE1_ID_RE = re.compile(r"^\s*Phase1_id:\s+(\S+)\s*$")

_DESC_RE = re.compile(r"^\s*Desc:\s+(.+?)\s*$")

_USERNAME_RE = re.compile(r"^\s*Username:\s+(.+?)\s*$")

_PROFILE_RE = re.compile(r"^\s*Profile:\s+(.+?)\s*$")

# IKE SA: local 10.0.0.1/500 remote 10.1.1.1/500 Active
_IKE_SA_RE = re.compile(
    r"^\s*IKE\s+SA:\s+local\s+(\S+)/(\d+)"
    r"\s+remote\s+(\S+)/(\d+)\s+(\S+)\s*$",
    re.IGNORECASE,
)

# Capabilities:D connid:1001 lifetime:23:55:10
_IKE_DETAIL_RE = re.compile(
    r"^\s*Capabilities:(\S*)\s+connid:(\d+)\s+lifetime:(\S+)\s*$"
)

# IPSEC FLOW: permit ip ...
_IPSEC_FLOW_RE = re.compile(r"^\s*IPSEC FLOW:\s+(.+?)\s*$", re.IGNORECASE)

_ACTIVE_SAS_RE = re.compile(r"^\s*Active SAs:\s+(\d+),\s+origin:\s+(.+?)\s*$")

_PKTS_ENCAPS_LINE_RE = re.compile(
    r"#pkts encaps:\s+(\d+).*?"
    r"#pkts encrypt:\s+(\d+).*?"
    r"#pkts digest:\s+(\d+)"
)

_PKTS_DECAPS_LINE_RE = re.compile(
    r"#pkts decaps:\s+(\d+).*?"
    r"#pkts decrypt:\s+(\d+).*?"
    r"#pkts verify:\s+(\d+)"
)

_LOCAL_REMOTE_ENDPT_RE = re.compile(
    r"^\s*local crypto endpt\.?:\s+(\S+),"
    r"\s+remote crypto endpt\.?:\s+(\S+)\s*$"
)

_PATH_MTU_RE = re.compile(r"^\s*path mtu\s+(\d+),\s+ip mtu\s+(\d+)")

_OUTBOUND_SPI_RE = re.compile(r"^\s*current outbound spi:\s+(0x[0-9A-Fa-f]+)")

_INBOUND_ESP_HEADER_RE = re.compile(r"^\s*inbound esp sas:\s*$")
_OUTBOUND_ESP_HEADER_RE = re.compile(r"^\s*outbound esp sas:\s*$")
_INBOUND_AH_HEADER_RE = re.compile(r"^\s*inbound ah sas:\s*$")
_OUTBOUND_AH_HEADER_RE = re.compile(r"^\s*outbound ah sas:\s*$")
_INBOUND_PCP_HEADER_RE = re.compile(r"^\s*inbound pcp sas:\s*$")
_OUTBOUND_PCP_HEADER_RE = re.compile(r"^\s*outbound pcp sas:\s*$")

# All SA section headers for boundary detection
_SA_SECTION_HEADERS = (
    _INBOUND_ESP_HEADER_RE,
    _OUTBOUND_ESP_HEADER_RE,
    _INBOUND_AH_HEADER_RE,
    _OUTBOUND_AH_HEADER_RE,
    _INBOUND_PCP_HEADER_RE,
    _OUTBOUND_PCP_HEADER_RE,
)

_SPI_RE = re.compile(r"^\s*spi:\s+(0x[0-9A-Fa-f]+)")

_SA_TRANSFORM_RE = re.compile(r"^\s*transform:\s+(.+?)\s*$")

_SA_IN_USE_RE = re.compile(r"^\s*in use settings\s*=\s*\{(.+?)\}\s*$")

_SA_CONN_ID_RE = re.compile(r"^\s*conn\s+id:\s*(\d+),\s*flow_id:\s*(\S+?)(?:,|$)")

# Mapping of simple peer-level fields to their regex and dict key
_PEER_FIELD_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_SESSION_STATUS_RE, "session_status"),
    (_STATUS_RE, "status"),
    (_FVRF_RE, "fvrf"),
    (_IVRF_RE, "ivrf"),
    (_PHASE1_ID_RE, "phase1_id"),
    (_DESC_RE, "desc"),
    (_USERNAME_RE, "username"),
    (_PROFILE_RE, "profile"),
]


def _normalize_spi(raw: str) -> str:
    """Normalize an SPI hex string to canonical 0x uppercase form."""
    return raw.upper().replace("0X", "0x")


def _is_sa_section_header(line: str) -> bool:
    """Check if line is any SA section header (esp/ah/pcp)."""
    return any(p.match(line) for p in _SA_SECTION_HEADERS)


def _split_session_blocks(output: str) -> list[list[str]]:
    """Split output into per-session blocks.

    Each block starts at an Interface: line and contains all lines
    through the next Interface: or end of output. Lines before the
    first Interface: that contain a Peer: are also captured.
    """
    lines = output.splitlines()
    blocks: list[list[str]] = []
    current: list[str] = []

    for line in lines:
        if _CRYPTO_SESSION_HEADER_RE.match(line):
            if current:
                blocks.append(current)
                current = []
            continue

        if _INTERFACE_RE.match(line):
            if current:
                blocks.append(current)
                current = []
            current.append(line)
            continue

        if line.strip():
            current.append(line)

    if current:
        blocks.append(current)

    return blocks


def _try_parse_sa_fields(line: str, sa: dict) -> bool:
    """Attempt to parse SA detail fields into the given dict.

    Returns True if the line was consumed.
    """
    m = _SA_TRANSFORM_RE.match(line)
    if m:
        sa["transform"] = m.group(1)
        return True

    m = _SA_IN_USE_RE.match(line)
    if m:
        sa["in_use_settings"] = m.group(1).strip().rstrip(",")
        return True

    m = _SA_CONN_ID_RE.match(line)
    if m:
        sa["conn_id"] = int(m.group(1))
        sa["flow_id"] = m.group(2)
        return True

    return False


def _parse_ipsec_sa_block(
    lines: list[str], start: int
) -> tuple[list[IpsecSaEntry], int]:
    """Parse inbound/outbound esp sas sub-block.

    Returns:
        Tuple of (list of SA entries, next line index).
    """
    sas: list[IpsecSaEntry] = []
    idx = start
    current_sa: dict | None = None

    while idx < len(lines):
        line = lines[idx]

        if _is_sa_section_header(line):
            break
        if _IKE_SA_RE.match(line) or _IPSEC_FLOW_RE.match(line):
            break

        m = _SPI_RE.match(line)
        if m:
            if current_sa is not None:
                sas.append(current_sa)  # type: ignore[arg-type]
            current_sa = {"spi": _normalize_spi(m.group(1))}
            idx += 1
            continue

        if current_sa is not None and _try_parse_sa_fields(line, current_sa):
            idx += 1
            continue

        idx += 1

    if current_sa is not None:
        sas.append(current_sa)  # type: ignore[arg-type]

    return sas, idx


def _try_parse_flow_counters(line: str, flow: dict) -> bool:
    """Attempt to parse packet/byte counter lines into flow dict.

    Returns True if the line was consumed.
    """
    m = _PKTS_ENCAPS_LINE_RE.search(line)
    if m:
        flow["pkts_encaps"] = int(m.group(1))
        flow["pkts_encrypt"] = int(m.group(2))
        flow["pkts_digest"] = int(m.group(3))
        return True

    m = _PKTS_DECAPS_LINE_RE.search(line)
    if m:
        flow["pkts_decaps"] = int(m.group(1))
        flow["pkts_decrypt"] = int(m.group(2))
        flow["pkts_verify"] = int(m.group(3))
        return True

    return False


def _try_parse_flow_metadata(line: str, flow: dict) -> bool:
    """Attempt to parse flow metadata fields.

    Returns True if the line was consumed.
    """
    m = _LOCAL_REMOTE_ENDPT_RE.match(line)
    if m:
        flow["local_crypto_endpt"] = m.group(1)
        flow["remote_crypto_endpt"] = m.group(2)
        return True

    m = _PATH_MTU_RE.match(line)
    if m:
        flow["path_mtu"] = int(m.group(1))
        flow["ip_mtu"] = int(m.group(2))
        return True

    m = _OUTBOUND_SPI_RE.match(line)
    if m:
        flow["current_outbound_spi"] = _normalize_spi(m.group(1))
        return True

    return False


def _try_parse_esp_sas(
    line: str, lines: list[str], idx: int, flow: dict
) -> tuple[bool, int]:
    """Try to parse ESP SA sections or skip other SA headers.

    Returns:
        Tuple of (consumed, next line index).
    """
    if _INBOUND_ESP_HEADER_RE.match(line):
        sas, idx = _parse_ipsec_sa_block(lines, idx + 1)
        if sas:
            flow["inbound_esp_sas"] = sas
        return True, idx

    if _OUTBOUND_ESP_HEADER_RE.match(line):
        sas, idx = _parse_ipsec_sa_block(lines, idx + 1)
        if sas:
            flow["outbound_esp_sas"] = sas
        return True, idx

    if _is_sa_section_header(line):
        return True, idx + 1

    return False, idx


def _parse_ipsec_flow(
    lines: list[str], start: int
) -> tuple[IpsecFlowEntry | None, int]:
    """Parse an IPSEC FLOW block including sub-SA details.

    Returns:
        Tuple of (flow entry, next line index).
    """
    idx = start
    flow: dict = {}

    while idx < len(lines):
        line = lines[idx]

        if _IKE_SA_RE.match(line) or _IPSEC_FLOW_RE.match(line):
            break

        m = _ACTIVE_SAS_RE.match(line)
        if m:
            flow["active_sas"] = int(m.group(1))
            flow["origin"] = m.group(2)
            idx += 1
            continue

        if _try_parse_flow_counters(line, flow):
            idx += 1
            continue

        if _try_parse_flow_metadata(line, flow):
            idx += 1
            continue

        consumed, idx = _try_parse_esp_sas(line, lines, idx, flow)
        if consumed:
            continue

        idx += 1

    if not flow:
        return None, idx

    return flow, idx  # type: ignore[return-value]


def _parse_context_lines(lines: list[str], peer_idx: int, entry: dict) -> None:
    """Parse Interface/Uptime/Session status lines before the Peer: line."""
    for line in lines[:peer_idx]:
        m = _INTERFACE_RE.match(line)
        if m:
            entry["interface"] = canonical_interface_name(m.group(1), os=OS.CISCO_IOS)
            continue

        m = _UPTIME_RE.match(line)
        if m:
            entry["uptime"] = m.group(1)
            continue

        m = _SESSION_STATUS_RE.match(line)
        if m:
            entry["status"] = m.group(1)


def _try_parse_peer_field(line: str, entry: dict) -> bool:
    """Attempt to parse a simple peer-level field.

    Returns True if the line was consumed.
    """
    for pattern, key in _PEER_FIELD_PATTERNS:
        m = pattern.match(line)
        if m:
            entry[key] = m.group(1)
            return True
    return False


def _store_ike_sa(
    ike_sas: IkeSaTree,
    local_addr: str,
    local_port: int,
    remote_addr: str,
    remote_port: int,
    ike_entry: IkeSaEntry,
) -> None:
    """Store an IKE SA using nested endpoint hierarchy keys."""
    local_port_key = str(local_port)
    remote_port_key = str(remote_port)

    if local_addr not in ike_sas:
        ike_sas[local_addr] = {}
    if local_port_key not in ike_sas[local_addr]:
        ike_sas[local_addr][local_port_key] = {}
    if remote_addr not in ike_sas[local_addr][local_port_key]:
        ike_sas[local_addr][local_port_key][remote_addr] = {}

    ike_sas[local_addr][local_port_key][remote_addr][remote_port_key] = ike_entry


def _parse_ike_sa(lines: list[str], idx: int, ike_sas: IkeSaTree) -> int:
    """Parse an IKE SA line and optional detail line.

    Returns the next line index.
    """
    m = _IKE_SA_RE.match(lines[idx])
    if not m:
        return idx + 1

    local_addr = m.group(1)
    local_port = int(m.group(2))
    remote_addr = m.group(3)
    remote_port = int(m.group(4))
    sa_status = m.group(5)

    ike_entry: IkeSaEntry = {
        "local_address": local_addr,
        "local_port": local_port,
        "remote_address": remote_addr,
        "remote_port": remote_port,
        "sa_status": sa_status,
    }

    # Check next line for capabilities/connid/lifetime
    if idx + 1 < len(lines):
        dm = _IKE_DETAIL_RE.match(lines[idx + 1])
        if dm:
            ike_entry["capabilities"] = dm.group(1)
            ike_entry["connid"] = int(dm.group(2))
            ike_entry["lifetime"] = dm.group(3)
            idx += 1

    _store_ike_sa(
        ike_sas,
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        ike_entry,
    )
    return idx + 1


def _parse_peer_body(lines: list[str], start: int, entry: dict) -> None:
    """Parse lines after the Peer: header, populating entry in-place."""
    idx = start
    ike_sas: IkeSaTree = {}
    ipsec_flows: dict[str, IpsecFlowEntry] = {}

    while idx < len(lines):
        line = lines[idx]

        if _try_parse_peer_field(line, entry):
            idx += 1
            continue

        if _IKE_SA_RE.match(line):
            idx = _parse_ike_sa(lines, idx, ike_sas)
            continue

        m = _IPSEC_FLOW_RE.match(line)
        if m:
            flow_entry, idx = _parse_ipsec_flow(lines, idx + 1)
            if flow_entry is not None:
                ipsec_flows[m.group(1)] = flow_entry
            continue

        idx += 1

    if ike_sas:
        entry["ike_sa"] = ike_sas
    if ipsec_flows:
        entry["ipsec_flow"] = ipsec_flows


def _parse_session_block(
    lines: list[str],
) -> CryptoSessionEntry | None:
    """Parse a single session block into a CryptoSessionEntry."""
    if not lines:
        return None

    peer_idx = next(
        (i for i, line in enumerate(lines) if _PEER_RE.match(line)),
        -1,
    )
    if peer_idx < 0:
        return None

    header = _PEER_RE.match(lines[peer_idx])
    if not header:
        return None

    entry: dict = {
        "peer_address": header.group(1),
        "peer_port": int(header.group(2)),
        "status": "UP-ACTIVE",
    }

    _parse_context_lines(lines, peer_idx, entry)
    _parse_peer_body(lines, peer_idx + 1, entry)

    return entry  # type: ignore[return-value]


@register(OS.CISCO_IOS, "show crypto session detail")
class ShowCryptoSessionDetailParser(
    BaseParser[ShowCryptoSessionDetailResult],
):
    """Parser for 'show crypto session detail' on IOS."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SECURITY})

    @classmethod
    def parse(cls, output: str) -> ShowCryptoSessionDetailResult:
        """Parse 'show crypto session detail' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed crypto session details keyed by peer address.

        Raises:
            ValueError: If no crypto session entries found in output.
        """
        blocks = _split_session_blocks(output)
        sessions: dict[str, CryptoSessionEntry] = {}

        for block_lines in blocks:
            result = _parse_session_block(block_lines)
            if result is None:
                continue
            peer_key = result["peer_address"]
            sessions[peer_key] = result

        if not sessions:
            msg = "No crypto session detail entries found in output"
            raise ValueError(msg)

        return {"sessions": sessions}
