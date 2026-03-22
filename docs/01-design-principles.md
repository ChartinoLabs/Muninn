# Muninn Design Principles

This document captures the core design principles guiding Muninn's development. These principles are informed by lessons learned from existing parser libraries, particularly Cisco's Genie parsers, and aim to avoid repeating known technical debt patterns.

## Guiding Philosophy

Muninn is a **standalone CLI output parser library**. It transforms unstructured text output from network devices into structured Python dictionaries. Nothing more, nothing less.

## Core Principles

### 1. Complete Independence from Huginn

**Problem in Genie**: Genie parsers are arguably the most malleable and customizable community-driven parser system in the network automation ecosystem. However, they've severely limited their usability by tightly coupling to the PyATS/Genie ecosystem. Users cannot use Genie parsers without installing PyATS, creating mock device objects, and navigating framework abstractions.

**Muninn's Approach**: Muninn has zero knowledge of or dependency on Huginn. The interface is deliberately simple:

```python
import muninn

result = muninn.parse("nxos", "show ip ospf neighbor", raw_output_string)
```

- No device objects required
- No connection handling
- No framework concepts
- Just: OS identifier + command + raw text → structured dict

Features that complement Huginn integration may be desirable, but Muninn must be fully usable without ever installing Huginn. A user should be able to `pip install muninn` and use it in any Python project.

### 2. Modular Parser Organization

**Problem in Genie**: Monolithic parser files where a single file like `show_ospf.py` contains 15+ different command parsers. This makes maintenance difficult, increases cognitive load, and complicates testing.

**Muninn's Approach**: One parser per file (or logical grouping of very closely related parsers). Code reuse through shared parsing utilities is encouraged - many CLI commands share sections of identical output that benefit from shared parsing logic - but bundling entire feature sets into single files is avoided.

Structure:
```
src/muninn/
├── parsers/
│   ├── __init__.py      # Auto-discovers all parser modules
│   ├── iosxe/
│   │   ├── __init__.py
│   │   ├── show_clock.py
│   │   ├── show_privilege.py
│   │   └── ...
│   └── nxos/
│       └── ...
└── common/
    └── patterns.py  # Shared regex patterns, parsing utilities (future)
```

Parsers are auto-discovered at import time using `pkgutil.walk_packages`. Adding a new parser only requires creating the file - no `__init__.py` maintenance needed.

Parser classes register command support with `@register(...)`. Registrations may be either:

- exact literal commands such as `show clock`
- named-group regex command patterns such as `show ip ospf (?P<process_id>\d+)`

Literal commands are resolved before regex patterns, and regex matching always happens against normalized whole-command input. See [Parser Registration](03-parser-registration.md) for the authoring rules and validation behavior.

### 3. Native Python Typing Over Custom Schema Engines

**Problem in Genie**: Uses a custom schema engine (`Schema`, `Any()`, `Optional()`) that exists primarily to generate documentation for the Genie parser website. This provides no IDE support, no standard validation, and requires learning non-standard patterns.

**Muninn's Approach**: Leverage native Python type hints where practical. The goal is to provide structure and documentation benefits without requiring exotic dependencies.

**Important constraint**: Parsers return raw dictionaries, not Pydantic models or dataclass instances. The priority is:

1. Return plain `dict` objects (JSON-serializable, no special types)
2. Use `TypedDict` to define parser output schemas for IDE support
3. Document expected output schemas in the TypedDict definitions

Each parser defines a `TypedDict` for its return type, providing IDE autocompletion while maintaining JSON-serializable output:

```python
from typing import TypedDict

class ShowClockResult(TypedDict):
    time: str
    timezone: str
    day_of_week: str
    month: str
    day: str
    year: str

@register(OS.CISCO_IOSXE, "show clock")
class ShowClockParser(BaseParser):
    @classmethod
    def parse(cls, output: str) -> ShowClockResult:
        ...
```

#### Optional: `SchemaDoc` and `Annotated` for targeted schemas

Most parsers should keep ordinary field types (`str`, `int`, `float`, `bool`, nested `TypedDict`, and so on). That remains the default.

For **specific, high-traffic parsers**—or wherever the output shape is easy to misunderstand in generated documentation—Muninn provides `SchemaDoc` in `muninn.schema_doc`. Attach it with `typing.Annotated` to describe **what a value represents**, including dynamic dict keys and fields that would otherwise look like undifferentiated strings or numbers:

```python
from typing import Annotated, TypedDict

from muninn.schema_doc import SchemaDoc

VlanKey = Annotated[
    str,
    SchemaDoc(
        "VLAN id string used as the mapping key (digits from the CLI label; "
        "leading zeros preserved where applicable)."
    ),
]

class ExampleResult(TypedDict):
    vlans: dict[VlanKey, dict[str, object]]
    metric: Annotated[int, SchemaDoc("IGP metric as shown in the routing table.")]
```

**Guidelines:**

- **Not mandatory** and not a goal for blanket coverage. Use judgment so parser modules stay mostly parsing logic, not annotation boilerplate.
- **Any base type** works: `Annotated[str, SchemaDoc(...)]`, `Annotated[int, SchemaDoc(...)]`, `Annotated[float, SchemaDoc(...)]`, and so on—not only strings.
- **Runtime unchanged**: `Annotated` metadata is for static analysis and future documentation tooling; `parse()` still returns plain JSON-serializable `dict` values (ordinary strings and numbers at runtime).
- **Wide parsers**: Prefer documenting the outer structure and a few important keys or nested maps; annotating every leaf field rarely pays off.

Users who want type hints can import the TypedDict or parser class directly.

### 4. Dictionaries of Dictionaries Output Pattern

**Observation from Genie**: The "dictionaries of dictionaries" pattern for representing parsed data is actually quite good. It provides a clean, predictable, and easy-to-consume structure.

**Muninn's Approach**: Adopt this pattern. Parsed output should be keyed by meaningful identifiers (neighbor IDs, interface names, VRF names) rather than returning lists of objects that require iteration to find specific entries.

For example, prefer this:

```json
{
    "10.1.1.1": {"state": "FULL", "interface": "Ethernet1/1"},
    "10.1.1.2": {"state": "FULL", "interface": "Ethernet1/2"}
}
```

Instead of this:

```json
[
    {"neighbor_id": "10.1.1.1", "state": "FULL", "interface": "Ethernet1/1"},
    {"neighbor_id": "10.1.1.2", "state": "FULL", "interface": "Ethernet1/2"}
]
```

The nested structure depth will sometimes be significant - this is unavoidable when CLI output itself contains deeply hierarchical data. We're constrained by vendor CLI implementations.

#### Nested keys vs. composite string keys

**Anti-pattern:** Building dict keys by concatenating identifiers into one string—often with delimiters such as `|`, `/`, or `:`—so the key encodes multiple dimensions at once (for example `GigabitEthernet0/1|5` for interface plus HSRP group, or `object:1` merged with unrelated fields). This makes the schema harder to consume, obscures structure, invites parsing bugs, and is not a substitute for proper nesting.

**Preferred:** When the device semantics are hierarchical (one interface has many HSRP groups, one object has many children, etc.), **nest dictionaries** so each key level represents a single conceptual dimension. For example, prefer:

```json
{
  "GigabitEthernet0/1": {
    "groups": {
      "5": { "state": "Active", "priority": 110 },
      "10": { "state": "Standby", "priority": 100 }
    }
  }
}
```

over a flat map whose keys are opaque composite strings.

**Legitimate flat keys:** A single real-world identifier that is already one string in the CLI (VRF name, neighbor router-id, canonical interface name as the sole index) remains appropriate as one dict key. The rule targets **encoding multiple independent attributes into one key** where nesting would mirror the data model.

The pipe character (`|`) is a common delimiter in composite keys. **Fixture CI** (below) rejects `|` in JSON object **keys** in parser `expected.json` files. String **values** taken from device output may still contain `|`.

#### Parser fixture checks (CI)

`tests/parsers/test_fixture_json_conventions.py` validates every `expected.json` under `tests/parsers/`:

- **List-of-dicts:** fails when a non-empty list contains only objects if a keyed dict would be natural (per the patterns above).
- **Pipe in keys:** fails when any object key contains U+007C (`|`).

Each check has its own opt-out set in `test_fixture_json_conventions.py` (`_LIST_OF_DICTS_EXEMPT_EXPECTED_FILES` vs. `_PIPE_IN_DICT_KEY_EXEMPT_EXPECTED_FILES`) so a legacy list-of-dicts fixture does not automatically skip the pipe-in-key rule, and vice versa.

### 5. Test Metadata for Platform/Version Tracking

**Problem in Genie**: Test data exists (golden input/output files), but there's no metadata indicating which hardware platforms or software versions the test data came from. Users have no visibility into parser coverage or reliability for their specific environment.

**Muninn's Approach**: Every test case should include metadata:

- **Platform**: Hardware model (e.g., "Nexus 9300", "Catalyst 9400", "ASR 1000")
- **Software Version**: OS version (e.g., "NX-OS 10.3(2)", "IOS-XE 17.12.1")

This metadata serves multiple purposes:

1. **User confidence**: Users can see at a glance whether their platform/version is tested
2. **Coverage tracking**: Maintainers can identify gaps (e.g., "no tests for IOS 15.x")
3. **Regression context**: When a parser breaks, metadata helps identify if it's a version-specific issue

Example test metadata structure (format TBD):

```yaml
# tests/nxos/ospf/show_ip_ospf_neighbor/test_001.yaml
metadata:
  platform: Nexus 9336C-FX2
  software_version: NX-OS 10.3(2)
```

### 6. Items We're Not Prioritizing

The following are acknowledged but not primary concerns:

**Regex compilation location**: Genie compiles 40+ regex patterns inside methods (on every call). While not optimal, this is a minor performance consideration compared to architectural decisions. We may optimize later but won't obsess over it initially.

**Verbose nested dict construction**: The `if key not in dict` pattern repeated throughout Genie parsers is verbose but functional. If cleaner patterns emerge naturally (helper functions, `defaultdict`, etc.), we'll use them, but this isn't a primary driver.

## Summary

| Aspect             | Genie Approach                | Muninn Approach                       |
| ------------------ | ----------------------------- | ------------------------------------- |
| Framework coupling | Requires PyATS/device objects | Zero dependencies, pure function      |
| File organization  | Monolithic feature files      | One parser per file, shared utilities |
| Type system        | Custom schema engine          | Native Python typing                  |
| Output format      | Dict of dicts                 | Dict of dicts (same, it's good)       |
| Test metadata      | None                          | Platform/version/source tracking      |
| Parser interface   | `device.parse("command")`     | `muninn.parse(os, command, output)`   |

## Related Documents

- [Testing Strategy](02-testing-strategy.md) - Test file structure and metadata format
- [Parser Registration](03-parser-registration.md) - Literal and regex command registration rules
- Parser output schemas: `TypedDict` by default; optional `SchemaDoc` with `typing.Annotated` for selected parsers (see **§3** above)
