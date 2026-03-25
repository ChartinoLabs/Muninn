# Design Philosophy

Muninn's design is informed by lessons learned from existing parser ecosystems in the network automation space, particularly Cisco's [Genie parsers](https://github.com/CiscoTestAutomation/genieparser) and TextFSM-based template repositories like [ntc-templates](https://github.com/networktocode/ntc-templates). Both are valuable tools that have served the community well, but each carries trade-offs that Muninn aims to address.

## Guiding Principle

Muninn is a standalone CLI output parser library. It transforms unstructured text output from network devices into structured Python data structures. Nothing more, nothing less.

Muninn also aims to offer a superior developer experience through modern Python type hinting practices. Every parser defines a `TypedDict` that describes the structure of its output, enabling faster and more confident development - especially for users leveraging AI coding assistants that can reason about typed data structures.

## Comparison with Existing Approaches

### Cisco Genie Parsers

Genie parsers are arguably the most flexible and customizable community-driven parser system in the network automation ecosystem. They support a wide range of platforms, handle complex and deeply hierarchical output well, and have years of production use behind them.

However, Genie parsers are tightly coupled to the PyATS/Genie framework. You cannot use Genie parsers by themselves without installing PyATS, creating mock device objects, and navigating framework abstractions. This limits adoption for users who simply want to parse CLI output in a standalone script or application.

Other areas where Muninn takes a different path:

| Aspect | Genie | Muninn |
|--------|-------|--------|
| **Dependencies** | Requires PyATS framework and device objects | Zero framework dependencies |
| **Type system** | Custom schema engine (`Schema`, `Any()`, `Optional()`) | Native Python `TypedDict` |
| **IDE support** | None - custom schema provides no autocompletion | Full autocompletion via `TypedDict` return types |
| **Test metadata** | Golden files with no platform/version provenance | Every test case tracks platform and software version |

Muninn acknowledges that Genie got the output format right. The dict-of-dicts pattern, where parsed data is keyed by meaningful identifiers like neighbor IDs or interface names, is clean and predictable. Muninn adopts this pattern directly.

### TextFSM / ntc-templates

ntc-templates is a community-maintained repository of TextFSM templates for parsing network device output. It has broad device coverage, integrates seamlessly with Netmiko (`use_textfsm=True`), and is accessible to network engineers who may not be comfortable writing Python parsing logic.

TextFSM's template language works well for flat, tabular output. However, it has fundamental limitations when dealing with the kind of data network parsers frequently encounter:

| Aspect | ntc-templates / TextFSM | Muninn |
|--------|------------------------|--------|
| **Output structure** | Always returns a list of flat dicts - no nesting is possible | Returns keyed, nested dicts that mirror the data's natural hierarchy |
| **Type information** | Scalar values are always strings; some fields use TextFSM's `List` type to return a list of strings | `TypedDict` schemas with proper Python types (`int`, `str`, `bool`) |
| **Hierarchical data** | Not supported - the template language can only produce flat records | Native Python logic handles arbitrary nesting |
| **IDE / AI support** | No type hints on results | Full autocompletion and type checking via `TypedDict` |
| **Debugging** | Requires tracing state machine logic across a separate template file | Standard Python debugging in a single `.py` file |
| **Template language** | Domain-specific (TextFSM syntax) | Standard Python - no new language to learn |

TextFSM is a great fit when you need quick parsing of simple, tabular commands across many device types. Where it struggles is complex output with multiple levels of nesting, conditional sections, or values that need type conversion. These are exactly the cases where a Python-native parser has the most room to express the output cleanly.

## Design Decisions

### Standalone by Default

Muninn has no knowledge of or dependency on any connection library or automation framework. The interface is deliberately minimal:

```python
import muninn

mn = muninn.Muninn()
result = mn.parse("nxos", "show ip ospf neighbor", raw_output)
```

No device objects. No connection handling. No framework concepts. Just an OS identifier, a command, and raw text in - structured data out. A user should be able to `pip install muninn-parsers` and use it in any Python project.

### One Parser Per File

Each parser lives in its own file. This keeps individual files focused, makes it easy to find the parser for a given command, and simplifies testing. Shared parsing utilities for common output patterns (e.g., interface name normalization) are encouraged, but bundling entire feature sets into a single file is not.

### Native Python Typing

Parsers return plain `dict` objects that are JSON-serializable with no special types. Each parser also defines a `TypedDict` that describes the structure of its return value. This gives users a choice:

- Use `Muninn().parse()` for a quick `dict[str, Any]` result with no extra imports
- Import the parser directly to get `TypedDict`-annotated results with full IDE autocompletion and type checking

The `TypedDict` approach also benefits AI-assisted coding - language models can reason about the structure of parsed data when type information is available.

### Dict-of-Dicts Output

Parsed output is keyed by natural identifiers (neighbor IDs, interface names, VRF names) rather than returned as lists of objects. This makes lookups direct (`result["10.1.1.1"]`) instead of requiring iteration.

When device output is hierarchical, Muninn uses nested dictionaries to reflect that hierarchy.

### Test Metadata

Every test case includes metadata tracking the hardware platform and software version the test data came from. This serves three purposes:

1. **User confidence** - users can see whether their platform/version combination is tested
2. **Coverage tracking** - maintainers can identify gaps
3. **Regression context** - when a parser breaks, metadata helps determine if it's version-specific
