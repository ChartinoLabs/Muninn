# Writing Parsers

This guide covers how to write a new parser for Muninn, following the project's conventions and design principles.

## Parser Structure

Every parser consists of:

1. A `TypedDict` defining the output schema
2. A parser class extending `BaseParser`
3. A `@register()` decorator binding it to an OS and command
4. A `tags` class variable categorizing the parser
5. A `parse()` classmethod that transforms raw CLI output into structured data

### Minimal Example

```python
"""Parser for 'show privilege' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowPrivilegeResult(TypedDict):
    """Schema for 'show privilege' parsed output."""

    privilege_level: int


@register(OS.CISCO_IOSXE, "show privilege")
class ShowPrivilegeParser(BaseParser[ShowPrivilegeResult]):
    """Parser for 'show privilege' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    _PRIVILEGE_PATTERN = re.compile(r"Current privilege level is (?P<level>\d+)")

    @classmethod
    def parse(cls, output: str) -> ShowPrivilegeResult:
        for line in output.splitlines():
            match = cls._PRIVILEGE_PATTERN.search(line.strip())
            if match:
                return ShowPrivilegeResult(
                    privilege_level=int(match.group("level")),
                )

        msg = "No privilege level found in output"
        raise ValueError(msg)
```

## Key Conventions

### One Parser Per File

Each parser lives in its own file under `src/muninn/parsers/<os>/`. The filename mirrors the command with underscores replacing spaces:

- `show clock` -> `show_clock.py`
- `show ip ospf neighbor` -> `show_ip_ospf_neighbor.py`

### TypedDict Output Schemas

Parsers return plain dictionaries, but define a `TypedDict` for the return type. This provides IDE autocompletion without introducing runtime overhead.

```python
class ShowClockResult(TypedDict):
    time: str
    timezone: str
    day_of_week: str
    month: str
    day: str
    year: str
```

### Tags

Built-in parsers **must** define a non-empty `tags` set using one or more values from the `ParserTag` enum. Tags categorize parsers for browsing and filtering in the parser library.

```python
tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.OSPF, ParserTag.ROUTING})
```

The full set of available tags is defined in `muninn.tags.ParserTag`. If you feel a tag is missing for your parser's feature area, you're welcome to add a new `ParserTag` value as part of your contribution.

### Dict-of-Dicts Output Pattern

When output contains multiple entries keyed by a natural identifier (neighbor ID, interface name, etc.), use nested dictionaries rather than lists:

```python
# Preferred
{
    "10.1.1.1": {"state": "FULL", "interface": "Ethernet1/1"},
    "10.1.1.2": {"state": "FULL", "interface": "Ethernet1/2"},
}

# Avoid
[
    {"neighbor_id": "10.1.1.1", "state": "FULL", "interface": "Ethernet1/1"},
    {"neighbor_id": "10.1.1.2", "state": "FULL", "interface": "Ethernet1/2"},
]
```

Use nested dictionaries for hierarchical data rather than composite string keys:

```python
# Preferred
{
    "GigabitEthernet0/1": {
        "groups": {
            "5": {"state": "Active", "priority": 110}
        }
    }
}

# Avoid - composite key encodes multiple dimensions
{
    "GigabitEthernet0/1|5": {"state": "Active", "priority": 110}
}
```

### Multi-OS Parsers

A single parser class can be registered for multiple operating systems by stacking decorators:

```python
@register(OS.CISCO_NXOS, "show clock")
@register(OS.CISCO_IOS, "show clock")
@register(OS.CISCO_IOSXE, "show clock")
class ShowClockParser(BaseParser[ShowClockResult]):
    ...
```

## File Placement

```
src/muninn/parsers/
├── iosxe/
│   ├── __init__.py
│   ├── show_clock.py
│   └── show_privilege.py
├── nxos/
│   ├── __init__.py
│   └── show_clock.py     # if NX-OS needs a separate parser
└── ios/
    └── __init__.py
```

Parsers are auto-discovered at import time. Adding a new file is all that's needed - no `__init__.py` registration required.

## Next Steps

- [Parser Registration](parser-registration.md) - Literal vs regex command registration
- [Testing Parsers](testing-parsers.md) - How to write test fixtures
