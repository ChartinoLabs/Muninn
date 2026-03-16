"""Common regex patterns shared across parsers.

This module provides reusable regex building blocks for parsing network
device CLI output.  Each pattern is exposed as a plain string constant
(for embedding inside larger expressions) **and** as a pre-compiled
``re.Pattern`` (for direct matching).

Naming convention::

    FOO     – raw pattern string, e.g. IPV4_ADDRESS
    FOO_RE  – compiled re.compile object, e.g. IPV4_ADDRESS_RE
"""

import re

# ---------------------------------------------------------------------------
# IPv4
# ---------------------------------------------------------------------------

# Matches a dotted-decimal IPv4 address (no prefix-length).
IPV4_ADDRESS = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

# Matches an IPv4 CIDR prefix, e.g. 10.0.0.0/24.
IPV4_PREFIX = IPV4_ADDRESS + r"/\d{1,2}"

IPV4_ADDRESS_RE = re.compile(IPV4_ADDRESS)
IPV4_PREFIX_RE = re.compile(IPV4_PREFIX)

# ---------------------------------------------------------------------------
# MAC address  (Cisco dotted notation: aaaa.bbbb.cccc)
# ---------------------------------------------------------------------------

# Matches a Cisco-style dotted MAC address, e.g. 0012.7fff.04d7.
MAC_ADDRESS = r"[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}"

MAC_ADDRESS_RE = re.compile(MAC_ADDRESS)

# ---------------------------------------------------------------------------
# Table / section separator lines
# ---------------------------------------------------------------------------

# Line consisting entirely of three or more dashes.
SEPARATOR_DASH = r"^-{3,}$"

# Line consisting only of dashes and whitespace (columnar table divider).
SEPARATOR_DASH_SPACE = r"^[-\s]+$"

SEPARATOR_DASH_RE = re.compile(SEPARATOR_DASH, re.MULTILINE)
SEPARATOR_DASH_SPACE_RE = re.compile(SEPARATOR_DASH_SPACE, re.MULTILINE)

# ---------------------------------------------------------------------------
# Interface name detection
# ---------------------------------------------------------------------------

# Matches the start of a Cisco interface name (any common abbreviation).
# Does not anchor to start/end of line so it can be embedded freely.
# Use with re.IGNORECASE.
INTERFACE_LIKE = (
    r"(?:Gi(?:g(?:abit(?:Ethernet)?)?)?|Fa(?:s(?:t(?:Ethernet)?)?)?|"
    r"Eth(?:ernet)?|"
    r"Te(?:n(?:Gig(?:abit(?:Ethernet)?)?)?)?|"
    r"Fo(?:r(?:ty(?:Gig(?:abit(?:Ethernet)?)?)?)?)?|"
    r"Hu(?:n(?:dred(?:Gig(?:E|abit(?:Ethernet)?)?)?)?)?|"
    r"Twe(?:ntyFiveGig(?:E|abit(?:Ethernet)?)?)?|"
    r"AppGigabitEthernet|"
    r"mgmt|Management|Lo(?:opback)?|Vlan|Po(?:rt-channel)?|"
    r"Tu(?:nnel)?|Se(?:rial)?|nve|BDI)"
    r"\d"
)

INTERFACE_LIKE_RE = re.compile(INTERFACE_LIKE, re.IGNORECASE)
