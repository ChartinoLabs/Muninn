# Muninn

A standalone CLI output parser library for network devices.

## Overview

Muninn transforms unstructured CLI output from network devices into structured Python dictionaries. Named after Odin's raven of memory in Norse mythology, Muninn "remembers" how to parse CLI output into structured data.

## Design Goals

- **Standalone**: No framework dependencies. Just `pip install muninn` and use it.
- **Simple API**: `muninn.parse(os, command, output)` → `dict`
- **Well-tested**: Comprehensive test coverage with platform/version metadata
- **Type-aware**: Native Python type hints for clarity

## Quick Example

```python
import muninn

raw_output = """
Neighbor ID     Pri   State           Dead Time   Address         Interface
10.1.1.1          1   FULL/DR         00:00:38    192.168.1.1     Ethernet1/1
10.1.1.2          1   FULL/BDR        00:00:33    192.168.1.2     Ethernet1/2
"""

result = muninn.parse("nxos", "show ip ospf neighbor", raw_output)
# Returns structured dict keyed by neighbor ID
```

## Documentation

- [Design Principles](docs/01-design-principles.md) - Core philosophy and technical decisions

## Status

Early development. See the design principles document for project direction.
