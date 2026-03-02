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

## Available Settings

### `parser_paths`

`parser_paths` defines where Muninn should look for local parser modules when `runtime.load_local_parsers()` is called without an explicit `paths=` argument. This setting controls discovery only; it does not automatically import overlays unless your application calls `runtime.load_local_parsers()`. Use this when you want a stable default overlay path policy across environments.

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

`parser_execution_mode` controls candidate ordering and whether built-in parsers are considered at all. `local_first_fallback` (default) tries local overlays before built-ins, `centralized_first_fallback` does the reverse, and `local_only` disables built-in candidates entirely. This setting directly changes which parser wins for the same `(os, command)` key.

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

`fallback_on_invalid_result` determines whether Muninn should continue to the next parser candidate when the current parser returns `None` or `{}`. When enabled (default: `true`), empty/none results are treated similarly to parse failures for fallback purposes; when disabled, only raised exceptions trigger fallback. This is useful when teams want strict handling for intentionally empty outputs.

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
