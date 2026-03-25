# Muninn

Muninn is a library that transforms unstructured network device CLI output into structured, type-hinted Python data structures.

## Why Muninn?

- **Standalone** - No framework dependencies. Install and use it in any Python project.
- **Simple API** - `Muninn().parse(os, command, output)` and you're done.
- **Well-tested** - Every parser has test cases with platform and software version metadata.
- **Type-aware** - Import individual parsers to get `TypedDict` return types that describe the parsed data structure, enabling IDE autocompletion and better AI-assisted coding.
- **Extensible** - Load your own local parsers alongside built-in ones.

## Quick Examples

### Auto-Discovering Parsers

Create a `Muninn` instance and call `parse()` with an OS identifier, the CLI command, and the raw output. Muninn automatically finds and runs the right parser:

```python
from typing import Any

import muninn

mn = muninn.Muninn()

raw_output = """
Neighbor ID     Pri   State           Dead Time   Address         Interface
10.1.1.1          1   FULL/DR         00:00:38    192.168.1.1     Ethernet1/1
10.1.1.2          1   FULL/BDR        00:00:33    192.168.1.2     Ethernet1/2
"""

result: dict[str, Any] = mn.parse("nxos", "show ip ospf neighbor", raw_output)
```

Returns:

```json
{
  "10.1.1.1": {
    "priority": 1,
    "state": "FULL/DR",
    "dead_time": "00:00:38",
    "address": "192.168.1.1",
    "interface": "Ethernet1/1"
  },
  "10.1.1.2": {
    "priority": 1,
    "state": "FULL/BDR",
    "dead_time": "00:00:33",
    "address": "192.168.1.2",
    "interface": "Ethernet1/2"
  }
}
```

### Using a Parser Directly

You can also import a specific parser and call it directly. This gives you access to the parser's `TypedDict` return type, which enables IDE autocompletion and helps AI coding assistants reason about the structure of the parsed data:

```python
from muninn.parsers.nxos.show_ip_ospf_neighbor import (
    ShowIpOspfNeighborParser,
    ShowIpOspfNeighborResult,
)

raw_output = """
Neighbor ID     Pri   State           Dead Time   Address         Interface
10.1.1.1          1   FULL/DR         00:00:38    192.168.1.1     Ethernet1/1
10.1.1.2          1   FULL/BDR        00:00:33    192.168.1.2     Ethernet1/2
"""

result: ShowIpOspfNeighborResult = ShowIpOspfNeighborParser.parse(raw_output)
# IDE autocompletion and type checking work here
```

## Supported Platforms

| Platform | OS Aliases |
|----------|-----------|
| Cisco NX-OS | `nxos`, `cisco_nxos`, `nexus`, `nx-os` |
| Cisco IOS-XE | `iosxe`, `cisco_iosxe`, `ios-xe` |
| Cisco IOS | `ios`, `cisco_ios` |
| Cisco IOS-XR | `iosxr`, `cisco_iosxr`, `ios-xr` |

Browse all available parsers in the [Parser Library](library.md).

## Next Steps

- [Installation](getting-started/installation.md) - Install Muninn via `pip` or `uv`
- [Quick Start](getting-started/quickstart.md) - Walk through the basics of parsing CLI output
- [Configuration](user-guide/configuration.md) - Customize execution mode, parser paths, and fallback behavior
