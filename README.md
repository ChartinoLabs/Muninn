# Muninn

[![CI](https://github.com/ChartinoLabs/Muninn/actions/workflows/main_branch_push_pull.yml/badge.svg)](https://github.com/ChartinoLabs/Muninn/actions/workflows/main_branch_push_pull.yml)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit)](https://github.com/pre-commit/pre-commit)
[![PyPI version](https://img.shields.io/pypi/v/muninn-parsers)](https://pypi.org/project/muninn-parsers/)
[![PyPI downloads](https://img.shields.io/pypi/dm/muninn-parsers)](https://pypi.org/project/muninn-parsers/)
[![Python versions](https://img.shields.io/pypi/pyversions/muninn-parsers)](https://pypi.org/project/muninn-parsers/)
[![License](https://img.shields.io/pypi/l/muninn-parsers)](https://github.com/ChartinoLabs/Muninn/blob/main/LICENSE)

Muninn is a library that transforms unstructured network device CLI output into structured, type-hinted Python data structures.

## Why Muninn?

- **Standalone** - No framework dependencies. Install and use it in any Python project.
- **Simple API** - `Muninn().parse(os, command, output)` and you're done.
- **Well-tested** - Every parser has test cases with platform and software version metadata.
- **Type-aware** - Import individual parsers to get `TypedDict` return types that describe the parsed data structure, enabling IDE autocompletion and better AI-assisted coding.
- **Extensible** - Load your own local parsers alongside built-in ones.

## Installation

Muninn can be quickly and easily installed with `uv` as shown below:

```bash
uv add muninn-parsers
```

Or, if you prefer good old-fashioned `pip`, you can do so as shown below:

```bash
pip install muninn-parsers
```

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

## Documentation

Full documentation is available at **[chartinolabs.github.io/Muninn](https://chartinolabs.github.io/Muninn/)**.

- [Changelog](CHANGELOG.md) - Release history built from changelog fragments
- [Changelog Fragments Guide](changes/README.md) - How to add release-note fragments
- [Releasing](RELEASING.md) - How to compile release notes and cut a release

## Acknowledgments

- **CLI output fixtures** — Some test fixtures in this project use CLI output samples sourced from the [Cisco Genieparser](https://github.com/CiscoTestAutomation/genieparser) and [Network to Code ntc-templates](https://github.com/networktocode/ntc-templates) repositories.
- **Schema inspiration** — Parsed data schemas for some parsers were heavily inspired by the schema structures in the [Cisco GenieParser](https://github.com/CiscoTestAutomation/genieparser) repository.

## Status

Early development. See the [Design Philosophy](https://chartinolabs.github.io/Muninn/design/) page for project direction.
