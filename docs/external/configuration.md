# Muninn Configuration

Muninn resolves runtime configuration from three sources, in this order:

1. API overrides (highest precedence)
2. Environment variables
3. `pyproject.toml` under `[tool.muninn]`

Programmatic overrides are set through a runtime's `configuration` object:

```python
import muninn

runtime = muninn.MuninnRuntime()
runtime.configuration.set_execution_mode("local_only")
runtime.configuration.set_fallback_on_invalid_result(True)
runtime.configuration.set_parser_paths(["/path/to/local/parsers"])
```

If you are using local parser files, the typical startup flow is: create a runtime,
load your local parsers once, then parse normally. This is usually done at app
startup, not before every parse call.

```python
import muninn

runtime = muninn.MuninnRuntime()
runtime.load_local_parsers()

result = runtime.parse("nxos", "show ip ospf neighbor", raw_output)
```

## Available Settings

### `parser_paths`

`parser_paths` tells Muninn where your local parser files live. This is most useful when you want one stable configuration that works across machines and environments without hard-coding paths in application code. After setting it (via env or `pyproject.toml`), call `runtime.load_local_parsers()` once at startup and Muninn will discover parsers from those locations.

Environment variable:

```bash
export MUNINN_PARSER_PATHS="/opt/muninn/parsers:/srv/team-overlays"
```

`pyproject.toml`:

```toml
[tool.muninn]
parser_paths = ["/opt/muninn/parsers", "/srv/team-overlays"]
```

API override:

```python
runtime.configuration.set_parser_paths(["/opt/muninn/parsers", "/srv/team-overlays"])
```

### `parser_execution_mode`

`parser_execution_mode` controls which parser Muninn prefers when both a built-in parser and a local parser can handle the same command. `local_first_fallback` (default) prefers your local parser, `centralized_first_fallback` prefers the built-in parser, and `local_only` uses only local parsers. Choose this setting based on whether you want local customizations to override built-ins or only fill in gaps.

Environment variable:

```bash
export MUNINN_PARSER_EXECUTION_MODE="local_only"
```

`pyproject.toml`:

```toml
[tool.muninn]
parser_execution_mode = "local_only"
```

API override:

```python
runtime.configuration.set_execution_mode("local_only")
```

### `fallback_on_invalid_result`

`fallback_on_invalid_result` controls what happens when a parser returns no useful data (`None` or `{}`). When this is `true` (default), Muninn will try the next eligible parser, which is usually what you want for resilience. When this is `false`, only raised exceptions trigger fallback, so an empty return is treated as a final result from that parser.

Environment variable:

```bash
export MUNINN_FALLBACK_ON_INVALID_RESULT="true"
```

`pyproject.toml`:

```toml
[tool.muninn]
fallback_on_invalid_result = true
```

API override:

```python
runtime.configuration.set_fallback_on_invalid_result(True)
```
