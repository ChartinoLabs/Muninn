# Parser Registration

Parsers register themselves with the `@register()` decorator. Muninn supports two registration modes through the same `command=` argument:

- **Literal commands** for exact command strings
- **Regex command patterns** for commands with variable tokens

The mode is determined automatically based on whether the command string contains named regex groups.

## Literal Command Registration

If the command does not contain a named regex group (`(?P<...>)`), Muninn treats it as a literal command.

```python
@register(OS.CISCO_NXOS, "show ip bgp summary")
class ShowIpBgpSummaryParser(BaseParser):
    ...
```

Literal registrations are normalized before lookup:

- Matching is case-insensitive
- Repeated whitespace is collapsed to a single space
- Leading and trailing whitespace is stripped

These all resolve to the same parser:

```python
mn.parse("nxos", "show ip bgp summary", output)
mn.parse("nxos", "SHOW IP BGP SUMMARY", output)
mn.parse("nxos", "  show   ip   bgp   summary  ", output)
```

## Regex Command Registration

If the command contains at least one named regex group, Muninn treats it as a regex pattern:

```python
@register(OS.CISCO_IOS, r"show ip ospf (?P<process_id>\d+)")
class ShowIpOspfProcessParser(BaseParser):
    ...
```

This matches concrete commands like `show ip ospf 1` and `show ip ospf 100`.

!!! important
    Only **named groups** (`(?P<name>...)`) trigger regex routing. Unnamed groups like `(\d+)` are treated as literal text.

### Full-Command Matching

Muninn always matches against the entire normalized command. You don't need anchors -- these behave identically:

```python
@register(OS.CISCO_IOS, r"show ip ospf (?P<process_id>\d+)")
@register(OS.CISCO_IOS, r"^show ip ospf (?P<process_id>\d+)$")
```

## Lookup Priority

1. **Literal** registrations are checked first
2. **Regex** registrations are checked only if no literal match exists

An exact command always wins over a broader pattern.

## Ambiguity Rules

If more than one regex pattern matches within the same source tier, Muninn raises `ParserAmbiguityError` instead of guessing:

```python
# These both match "show ip ospf 5" -- Muninn raises an error
@register(OS.CISCO_IOS, r"show ip ospf (?P<token>\S+)")
class GenericParser(BaseParser): ...

@register(OS.CISCO_IOS, r"show ip ospf (?P<process_id>\d+)")
class ProcessParser(BaseParser): ...
```

When authoring regex registrations:

- Prefer literal keywords where possible
- Use the narrowest valid regex for variable tokens
- Reserve broad patterns like `\S+` for cases that truly need them

## Documentation Templates

Every registration exposes a documentation-friendly command template.

For **literal commands**, the template defaults to the normalized command string.

For **simple regex patterns**, Muninn derives a template automatically from the named groups:

```python
@register(OS.CISCO_IOS, r"show ip ospf (?P<process_id>\d+) vrf (?P<vrf_name>\S+)")
```

Produces the template: `show ip ospf <process-id> vrf <vrf-name>`

### Explicit `doc_template`

Complex patterns (optional groups, alternation, nested groups) require an explicit `doc_template`:

```python
@register(
    OS.CISCO_IOS,
    r"show ip bgp(?: vrf (?P<vrf_name>\S+))? summary",
    doc_template="show ip bgp [vrf <vrf-name>] summary",
)
class ShowIpBgpSummaryParser(BaseParser):
    ...
```

Placeholder names in `doc_template` must align with named regex groups:

- Regex group `process_id` -> placeholder `<process-id>`
- Regex group `vrf_name` -> placeholder `<vrf-name>`
