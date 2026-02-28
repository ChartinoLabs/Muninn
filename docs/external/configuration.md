# Muninn Configuration

Muninn resolves runtime configuration from three sources, in this order:

1. API overrides (highest precedence)
2. Environment variables
3. `pyproject.toml` under `[tool.muninn]`

## Available Settings

### Parser overlays

- `parser_paths` (`MUNINN_PARSER_PATHS`)
  - Path-separated list of directories containing local parser modules.
  - Loaded at import time to register local parser candidates.

### Parser execution mode

- `parser_execution_mode` (`MUNINN_PARSER_EXECUTION_MODE`)
  - `local_first_fallback` (default)
  - `centralized_first_fallback`
  - `local_only`

### Fallback behavior

- `fallback_on_invalid_result` (`MUNINN_FALLBACK_ON_INVALID_RESULT`)
  - Defaults to `true`.
  - If enabled, fallback is triggered when a parser returns `None` or `{}`.
  - Parser exceptions always trigger fallback.
