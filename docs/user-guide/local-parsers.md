# Local Parsers

Muninn supports loading parser modules from local project paths without modifying the installed package. This is useful when you need to:

- Parse commands not yet covered by built-in parsers
- Work around a bug in a built-in parser or override its behavior for your environment
- Develop and test parsers before contributing them upstream

## Loading Local Parsers

### From Configured Paths

If parser paths are set via environment variable or `pyproject.toml`:

```python
import muninn

mn = muninn.Muninn()
mn.load_local_parsers()  # loads from configured parser_paths

result = mn.parse("nxos", "show ip ospf neighbor", raw_output)
```

### From Explicit Paths

Pass paths directly to `load_local_parsers()`:

```python
mn = muninn.Muninn()
mn.load_local_parsers(paths=["/path/to/my-parsers"])
```

## Writing a Local Parser

Local parsers follow the same structure as built-in parsers. Create a Python file in your local parser directory:

```
my-parsers/
└── show_custom_command.py
```

```python
"""Parser for 'show custom command' on NX-OS."""

from typing import TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ShowCustomCommandResult(TypedDict):
    """Schema for parsed output."""

    status: str
    count: int


@register(OS.CISCO_NXOS, "show custom command")
class ShowCustomCommandParser(BaseParser[ShowCustomCommandResult]):
    """Parser for 'show custom command'."""

    @classmethod
    def parse(cls, output: str) -> ShowCustomCommandResult:
        # Your parsing logic here
        ...
```

!!! note
    Unlike built-in parsers, local parsers do not *need* to define `tags` (although it doesn't hurt!) - the tags requirement only applies to built-in parsers. If you plan to [contribute your parser upstream](#contributing-local-parsers-upstream), you will need to add tags. See [Tags](../developer-guide/writing-parsers.md#tags) for the full list of available values.

## Execution Modes

When both a built-in and local parser exist for the same OS/command, the [execution mode](configuration.md#parser_execution_mode) determines priority:

| Mode | Behavior |
|------|----------|
| `local_first_fallback` (default) | Local parser runs first; built-in is tried on failure |
| `centralized_first_fallback` | Built-in parser runs first; local is tried on failure |
| `local_only` | Only local parsers are considered |

Fallback is triggered when a parser:

- Raises an exception
- Returns `None`
- Returns `{}` (when `fallback_on_invalid_result` is enabled)

```python
import muninn

mn = muninn.Muninn()
mn.configuration.set_execution_mode(muninn.ExecutionMode.LOCAL_ONLY)
mn.load_local_parsers(paths=["/path/to/my-parsers"])
```

For more information on how to configure the execution mode, see the [`parser_execution_mode`](configuration.md#parser_execution_mode) section of the Configuration page.

## Contributing Local Parsers Upstream

If your local parser works well, consider contributing it back to Muninn. The gap between a working local parser and an upstream contribution is small - the parsing logic itself doesn't need to change. You just need to add:

1. **Tags** - Built-in parsers require a non-empty `tags` set (local parsers don't). Add the appropriate `ParserTag` values to categorize your parser.
2. **Test fixtures** - Create a test case directory with `metadata.yaml`, `input.txt`, and `expected.json` so the parser is covered by CI.

That's it. The `@register()` decorator, `BaseParser` subclass, and `TypedDict` schema you already wrote are exactly what the upstream project expects.

See [Writing Parsers](../developer-guide/writing-parsers.md) and [Testing Parsers](../developer-guide/testing-parsers.md) for the full conventions.
