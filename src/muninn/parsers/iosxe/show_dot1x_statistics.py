"""Parser for 'show dot1x statistics' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_SPACE_RE
from muninn.registry import register
from muninn.tags import ParserTag

_KV_RE = re.compile(r"(?P<key>\w+)\s*=\s*(?P<value>\d+)")


class ShowDot1xStatisticsResult(TypedDict):
    """Schema for 'show dot1x statistics' parsed output."""

    rx_start: NotRequired[int]
    rx_logoff: NotRequired[int]
    rx_resp: NotRequired[int]
    rx_resp_id: NotRequired[int]
    rx_req: NotRequired[int]
    rx_invalid: NotRequired[int]
    rx_len_err: NotRequired[int]
    rx_total: NotRequired[int]
    tx_start: NotRequired[int]
    tx_logoff: NotRequired[int]
    tx_resp: NotRequired[int]
    tx_req: NotRequired[int]
    re_tx_req: NotRequired[int]
    re_tx_req_fail: NotRequired[int]
    tx_req_id: NotRequired[int]
    re_tx_req_id: NotRequired[int]
    re_tx_req_id_fail: NotRequired[int]
    tx_total: NotRequired[int]


# Map from CLI counter names to schema field names.
_KEY_MAP: dict[str, str] = {
    "RxStart": "rx_start",
    "RxLogoff": "rx_logoff",
    "RxResp": "rx_resp",
    "RxRespID": "rx_resp_id",
    "RxReq": "rx_req",
    "RxInvalid": "rx_invalid",
    "RxLenErr": "rx_len_err",
    "RxTotal": "rx_total",
    "TxStart": "tx_start",
    "TxLogoff": "tx_logoff",
    "TxResp": "tx_resp",
    "TxReq": "tx_req",
    "ReTxReq": "re_tx_req",
    "ReTxReqFail": "re_tx_req_fail",
    "TxReqID": "tx_req_id",
    "ReTxReqID": "re_tx_req_id",
    "ReTxReqIDFail": "re_tx_req_id_fail",
    "TxTotal": "tx_total",
}


def _extract_counters(output: str) -> dict[str, int]:
    """Extract dot1x counter key-value pairs from raw output."""
    result: dict[str, int] = {}
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or SEPARATOR_DASH_SPACE_RE.match(stripped):
            continue
        for match in _KV_RE.finditer(line):
            field = _KEY_MAP.get(match.group("key"))
            if field is not None:
                result[field] = int(match.group("value"))
    return result


@register(OS.CISCO_IOSXE, "show dot1x statistics")
class ShowDot1xStatisticsParser(BaseParser[ShowDot1xStatisticsResult]):
    """Parser for 'show dot1x statistics' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SECURITY})

    @classmethod
    def parse(cls, output: str) -> ShowDot1xStatisticsResult:
        """Parse 'show dot1x statistics' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed dot1x global statistics counters.

        Raises:
            ValueError: If no statistics counters are found.
        """
        result = _extract_counters(output)

        if not result:
            msg = "No dot1x statistics counters found in output"
            raise ValueError(msg)

        return cast(ShowDot1xStatisticsResult, result)
