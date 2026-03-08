# Parser Registration

This guide describes how Muninn parser classes are registered and how command routing works for both exact commands and variable command forms.

## Overview

Parsers register themselves with the `@register(...)` decorator:

```python
from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


@register(OS.CISCO_IOSXE, "show clock")
class ShowClockParser(BaseParser):
    @classmethod
    def parse(cls, output: str) -> dict[str, str]:
        ...
```

Muninn supports two registration modes through the same `command=` argument:

- literal commands for exact command strings
- regex command patterns for commands with variable tokens

The mode is determined automatically.

## Literal Command Registration

If the registered command does not contain a named regex group, Muninn treats it as a literal command.

```python
@register(OS.CISCO_NXOS, "show ip bgp summary")
class ShowIpBgpSummaryParser(BaseParser):
    ...
```

Literal registrations are normalized before lookup:

- command matching is case-insensitive
- repeated whitespace is collapsed to a single space
- leading and trailing whitespace is ignored

So these commands all resolve to the same parser:

- `show ip bgp summary`
- `SHOW IP BGP SUMMARY`
- `  show   ip   bgp   summary  `

## Regex Command Registration

If the registered command contains at least one named regex group, Muninn treats it as a regex command pattern.

```python
@register(OS.CISCO_IOS, r"show ip ospf (?P<process_id>\d+)")
class ShowIpOspfProcessParser(BaseParser):
    ...
```

This allows one parser to match concrete command instances such as:

- `show ip ospf 1`
- `show ip ospf 100`

### Named Groups Are Required

Regex routing is only enabled by named groups such as `(?P<process_id>...)`.

- `show ip ospf (?P<process_id>\d+)` is a regex command pattern
- `show ip ospf (\d+)` is treated as a literal string, not a regex pattern

This keeps registration behavior predictable and makes documentation generation possible.

## Matching Behavior

Muninn always matches against the fully normalized command string.

- input commands are lowercased before lookup
- input commands have whitespace collapsed before lookup
- regex patterns are evaluated against the whole normalized command

Muninn performs full-command matching internally, so parser authors do not need to add anchors.

These registrations behave the same way:

```python
@register(OS.CISCO_IOS, r"show ip ospf (?P<process_id>\d+)")
@register(OS.CISCO_IOS, r"^show ip ospf (?P<process_id>\d+)$")
```

If a parser author includes a leading `^` or trailing `$`, Muninn strips those outer anchors and still applies whole-command matching.

## Lookup Priority

Command lookup uses the following order:

1. literal command registrations
2. regex command registrations

This means exact commands win before broader patterns.

For example:

```python
@register(OS.CISCO_IOS, "show ip ospf neighbors")
class ShowIpOspfNeighborsParser(BaseParser):
    ...


@register(OS.CISCO_IOS, r"show ip ospf (?P<token>\S+)")
class ShowIpOspfGenericParser(BaseParser):
    ...
```

`show ip ospf neighbors` resolves to the literal parser first.

## Source Precedence

When both built-in and local parsers are present, Muninn applies source precedence before considering lower-priority sources.

- if the active source tier has a literal match, lower tiers are ignored
- if the active source tier has a regex match, lower tiers are ignored

This preserves the existing built-in versus local override model.

## Ambiguity Rules

Regex registrations can overlap. If more than one regex pattern matches within the same source tier, Muninn raises `ParserAmbiguityError`.

Example:

```python
@register(OS.CISCO_IOS, r"show ip ospf (?P<token>\S+)")
class GenericParser(BaseParser):
    ...


@register(OS.CISCO_IOS, r"show ip ospf (?P<process_id>\d+)")
class ProcessParser(BaseParser):
    ...
```

Both patterns match `show ip ospf 5`, so Muninn raises an ambiguity error instead of guessing.

When authoring regex registrations:

- prefer literal keywords where possible
- use the narrowest valid regex for variables
- reserve broad patterns like `\S+` for cases that truly need them

## `doc_template`

Every registration exposes a documentation-friendly command template.

For literal commands, the template defaults to the normalized command string.

For simple regex patterns, Muninn can derive a template automatically from named groups:

```python
@register(
    OS.CISCO_IOS,
    r"show ip ospf (?P<process_id>\d+) vrf (?P<vrf_name>\S+)",
)
class ShowIpOspfVrfParser(BaseParser):
    ...
```

This produces the template:

```txt
show ip ospf <process-id> vrf <vrf-name>
```

### When `doc_template` Is Required

Complex regex patterns require an explicit `doc_template=`.

Typical examples:

- optional groups
- alternation
- nested regex groups
- patterns that are not simple literal tokens plus whole-token named groups

Example:

```python
@register(
    OS.CISCO_IOS,
    r"show ip bgp(?: vrf (?P<vrf_name>\S+))? summary",
    doc_template="show ip bgp [vrf <vrf-name>] summary",
)
class ShowIpBgpSummaryParser(BaseParser):
    ...
```

### `doc_template` Validation

If `doc_template` is provided for a regex registration, its placeholders must align exactly with the regex named groups.

Rules:

- use angle-bracket placeholders such as `<process-id>`
- placeholder names map to regex group names with hyphens converted to underscores
- placeholder and group sets must match exactly

Examples:

- regex group `process_id` maps to `<process-id>`
- regex group `vrf_name` maps to `<vrf-name>`

## Practical Guidance

Prefer literals for fixed commands:

```python
@register(OS.CISCO_IOSXE, "show ip ospf neighbor")
```

Use regex only when the command genuinely contains variable tokens:

```python
@register(OS.CISCO_IOSXE, r"show ip ospf (?P<process_id>\d+) vrf (?P<vrf_name>\S+)")
```

Prefer precise patterns over broad ones:

```python
# Better
@register(OS.CISCO_IOS, r"show ip ospf (?P<process_id>\d+)")

# Riskier
@register(OS.CISCO_IOS, r"show ip ospf (?P<token>\S+)")
```

## Introspection

Muninn's registry exposes documentation-friendly command templates through `list_parsers()` and richer registration metadata through `list_command_specs()`.

Use these outputs for docs, diagnostics, or coverage reporting rather than relying on raw regex strings.
