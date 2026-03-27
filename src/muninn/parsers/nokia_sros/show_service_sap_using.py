"""Parser for 'show service sap-using' command on Nokia SR OS."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class SapEntry(TypedDict):
    """Schema for a single SAP entry."""

    service_id: str
    ingress_qos: str
    ingress_filter: str
    egress_qos: str
    egress_filter: str
    admin_state: str
    oper_state: str


# Top-level result is a dict keyed by SAP ID (PortId)
ShowServiceSapUsingResult = dict[str, SapEntry]


@register(OS.NOKIA_SROS, "show service sap-using")
class ShowServiceSapUsingParser(BaseParser[ShowServiceSapUsingResult]):
    """Parser for 'show service sap-using' command on Nokia SR OS.

    Parses the tabular SAP summary output, returning a dict keyed
    by SAP ID (PortId) with each value containing SAP attributes.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INTERFACES,
        }
    )

    # Separator lines used to delimit table sections
    _SEPARATOR = re.compile(r"^[=\-]{10,}$")

    # Header lines identifying column headers (used to skip)
    _HEADER = re.compile(r"^\s*PortId\s+SvcId\s+Ing\.", re.I)
    _HEADER_CONT = re.compile(r"^\s*QoS\s+Fltr\s+QoS\s+Fltr", re.I)

    # Title line
    _TITLE = re.compile(r"^\s*Service Access Points\s*$", re.I)

    # Summary line like "Number of SAPs : 5"
    _SUMMARY = re.compile(r"^\s*Number of SAPs\s*:", re.I)

    # Footnote line
    _FOOTNOTE = re.compile(r"^\s*\*\s+indicates\s+that\s+", re.I)

    # SAP data row pattern
    # PortId  SvcId  Ing.QoS  Ing.Fltr  Egr.QoS  Egr.Fltr  Adm  Opr
    _SAP_ROW = re.compile(
        r"^(?P<port_id>\S+)\s+"
        r"(?P<svc_id>\S+)\s+"
        r"(?P<ing_qos>\S+)\s+"
        r"(?P<ing_fltr>\S+)\s+"
        r"(?P<egr_qos>\S+)\s+"
        r"(?P<egr_fltr>\S+)\s+"
        r"(?P<admin>Up|Down)\s+"
        r"(?P<oper>Up|Down)$"
    )

    @classmethod
    def _is_skip_line(cls, line: str) -> bool:
        """Return True for lines that are not data rows."""
        stripped = line.strip()
        if not stripped:
            return True
        if cls._SEPARATOR.match(stripped):
            return True
        if cls._HEADER.match(stripped):
            return True
        if cls._HEADER_CONT.match(stripped):
            return True
        if cls._TITLE.match(stripped):
            return True
        if cls._SUMMARY.match(stripped):
            return True
        if cls._FOOTNOTE.match(stripped):
            return True
        return False

    @classmethod
    def parse(cls, output: str) -> ShowServiceSapUsingResult:
        """Parse 'show service sap-using' output on Nokia SR OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by SAP ID (PortId), each value a SapEntry dict.

        Raises:
            ValueError: If no SAP entries can be parsed.
        """
        result: dict[str, SapEntry] = {}

        for line in output.splitlines():
            if cls._is_skip_line(line):
                continue

            match = cls._SAP_ROW.match(line.strip())
            if match is None:
                continue

            port_id = match.group("port_id")
            entry: SapEntry = {
                "service_id": match.group("svc_id"),
                "ingress_qos": match.group("ing_qos"),
                "ingress_filter": match.group("ing_fltr"),
                "egress_qos": match.group("egr_qos"),
                "egress_filter": match.group("egr_fltr"),
                "admin_state": match.group("admin"),
                "oper_state": match.group("oper"),
            }
            result[port_id] = entry

        if not result:
            msg = "No SAP entries found in output"
            raise ValueError(msg)

        return cast(ShowServiceSapUsingResult, result)
