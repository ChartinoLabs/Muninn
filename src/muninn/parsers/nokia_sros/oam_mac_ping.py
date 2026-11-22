"""Parser for 'oam mac-ping' command on Nokia SR OS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag


class MacPingRequest(TypedDict):
    """Schema for a single ``[Send request ...]`` marker."""

    sequence: int
    size_bytes: NotRequired[int]


class MacPingResponse(TypedDict):
    """Schema for a single mac-ping response row.

    The Node-id field on Nokia SR OS is encoded as
    ``<router_ip>:sap<port>:<tag>``. Where the parser can split the
    components apart, ``router``, ``port`` and ``tag`` are exposed as
    individual fields. ``node_id`` always carries the raw value as
    printed by the device.

    The ``path`` field captures everything that the device prints
    between the node-id and the RTT column. For successful responses
    this is typically ``In-Band`` or ``Out-of-Band``; for failed
    responses it is a longer status string such as
    ``No FIB on Egress In-Band``.
    """

    sequence: int
    node_id: str
    router: NotRequired[str]
    port: NotRequired[str]
    tag: NotRequired[str]
    path: str
    rtt_ms: NotRequired[float]


class OamMacPingResult(TypedDict):
    """Schema for ``oam mac-ping`` parsed output on Nokia SR OS."""

    requests: dict[str, MacPingRequest]
    responses: dict[str, MacPingResponse]


# ``[Send request Seq. 1, Size 126]``
_SEND_REQUEST_RE = re.compile(
    r"^\[Send\s+request\s+Seq\.\s+(?P<seq>\d+)"
    r"(?:,\s*Size\s+(?P<size>\d+))?\s*\]\s*$"
)

# ``Seq Node-id ... Path RTT`` header line
_HEADER_RE = re.compile(
    r"^Seq\s+Node-id\b.*\bPath\b.*\bRTT\b\s*$",
    re.IGNORECASE,
)

# Separator rows of dashes/equals
_SEPARATOR_RE = re.compile(r"^[=\-]{4,}$")

# Response row, e.g.:
#   1   192.0.2.4:sap1/1/2:100                 No FIB on Egress In-Band  0.153ms
#
# Strategy: anchor on the leading sequence number and node-id token
# (no whitespace), then capture everything up to the trailing RTT.
_RESPONSE_RE = re.compile(
    r"^(?P<seq>\d+)\s+"
    r"(?P<node_id>\S+)\s+"
    r"(?P<path>.+?)"
    r"(?:\s+(?P<rtt>[\d.]+)\s*ms)?"
    r"\s*$"
)

# Decompose ``<router>:sap<port>:<tag>``
_NODE_ID_SAP_RE = re.compile(
    rf"^(?P<router>{IPV4_ADDRESS}):sap(?P<port>[^:]+):(?P<tag>\S+)$"
)


@register(OS.NOKIA_SROS, "oam mac-ping")
class OamMacPingParser(BaseParser[OamMacPingResult]):
    """Parser for ``oam mac-ping`` on Nokia SR OS.

    The command issues one or more Layer-2 OAM ping requests and
    prints a tabular summary of the responses received. Each
    ``[Send request Seq. N, Size M]`` marker introduces a probe;
    response rows follow underneath the column header
    ``Seq Node-id Path RTT``.

    Returns a dict with two sub-dicts: ``requests`` keyed by the
    sequence number of the probe, and ``responses`` keyed by the
    sequence number of the response. The two dicts are independent
    so that timed-out probes (which produce a request entry but no
    response) can still be observed.

    Raises:
        ValueError: If no response rows or send-request markers can
            be parsed.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.CONNECTIVITY,
            ParserTag.MAC,
        }
    )

    @classmethod
    def parse(cls, output: str) -> OamMacPingResult:
        """Parse ``oam mac-ping`` output into a structured result.

        Args:
            output: Raw CLI output from the ``oam mac-ping`` command.

        Returns:
            Parsed mac-ping result with per-probe request markers and
            per-response data rows.
        """
        requests: dict[str, MacPingRequest] = {}
        responses: dict[str, MacPingResponse] = {}

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if _SEPARATOR_RE.match(line):
                continue
            if _HEADER_RE.match(line):
                continue

            send_match = _SEND_REQUEST_RE.match(line)
            if send_match:
                cls._record_request(send_match, requests)
                continue

            response_match = _RESPONSE_RE.match(line)
            if response_match:
                cls._record_response(response_match, responses)

        if not requests and not responses:
            msg = "No mac-ping requests or responses found in output"
            raise ValueError(msg)

        return cast(OamMacPingResult, {"requests": requests, "responses": responses})

    @staticmethod
    def _record_request(
        match: re.Match[str],
        requests: dict[str, MacPingRequest],
    ) -> None:
        sequence = int(match.group("seq"))
        request: MacPingRequest = {"sequence": sequence}
        size = match.group("size")
        if size is not None:
            request["size_bytes"] = int(size)
        requests[str(sequence)] = request

    @staticmethod
    def _record_response(
        match: re.Match[str],
        responses: dict[str, MacPingResponse],
    ) -> None:
        sequence = int(match.group("seq"))
        node_id = match.group("node_id")
        path = (match.group("path") or "").strip()
        if not path:
            # A response row with no Path column is not a valid data
            # row; silently skip to avoid mis-classifying unrelated
            # text that happens to start with a digit.
            return

        response: MacPingResponse = {
            "sequence": sequence,
            "node_id": node_id,
            "path": path,
        }

        node_match = _NODE_ID_SAP_RE.match(node_id)
        if node_match:
            response["router"] = node_match.group("router")
            response["port"] = node_match.group("port")
            response["tag"] = node_match.group("tag")

        rtt = match.group("rtt")
        if rtt is not None:
            response["rtt_ms"] = float(rtt)

        responses[str(sequence)] = response
