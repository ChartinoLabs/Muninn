# Quick Start

This guide walks through the basics of using Muninn to parse network device CLI output.

## Basic Usage

The core workflow is simple: create a `Muninn` instance and call `parse()` with three arguments:

1. **OS identifier** - which network operating system produced the output
2. **Command** - the CLI command that was run
3. **Output** - the raw text output from the device

```python
from typing import Any

import muninn

mn: muninn.Muninn = muninn.Muninn()

raw_output: str = """
*04:45:00.857 UTC Thu Aug 7 2025
"""

result: dict[str, Any] = mn.parse("iosxe", "show clock", raw_output)
print(result)
# {'time': '04:45:00.857', 'timezone': 'UTC', 'day_of_week': 'Thu',
#  'month': 'Aug', 'day': '7', 'year': '2025'}
```

## OS Identifiers

Muninn accepts flexible OS identifiers. These all resolve to the same platform:

```python
mn.parse("nxos", "show clock", output)
mn.parse("cisco_nxos", "show clock", output)
mn.parse("nexus", "show clock", output)
mn.parse("nx-os", "show clock", output)
```

You can also use the `OS` enum directly:

```python
from muninn import OS

mn.parse(OS.CISCO_NXOS, "show clock", output)
```

## Class-Level Parsing

For one-off parsing without managing an instance:

```python
from typing import Any

import muninn

result: dict[str, Any] = muninn.Muninn.parse("iosxe", "show clock", raw_output)
```

## Handling Errors

Muninn raises specific exceptions for different failure modes:

```python
from typing import Any

from muninn import EmptyOutputError, Muninn, ParseError, ParserNotFoundError

mn: Muninn = Muninn()

try:
    result: dict[str, Any] = mn.parse("iosxe", "show clock", raw_output)
except EmptyOutputError:
    print("Device returned empty output")
except ParserNotFoundError:
    print("No parser available for this OS/command combination")
except ParseError:
    print("Parser failed to extract structured data")
```

## Listing Available Parsers

To see what parsers are registered:

```python
from muninn import Muninn, OS

mn: Muninn = Muninn()

os_entry: OS
command: str
for os_entry, command in mn.registry.list_parsers():
    print(f"{os_entry.value.name}: {command}")
```

For richer metadata including tags:

```python
from muninn.registry import ParserInfo

info: ParserInfo
for info in mn.registry.list_parser_catalog():
    tags: str = ", ".join(sorted(info.tags))
    print(f"{info.os.value.name}: {info.command_template} [{tags}]")
```

## Next Steps

- [Configuration](../user-guide/configuration.md) - Customize execution mode and parser paths
- [Local Parsers](../user-guide/local-parsers.md) - Load your own parser modules
- [Parser Library](../library.md) - Browse all available parsers
