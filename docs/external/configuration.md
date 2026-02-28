# Muninn Configuration

Muninn resolves runtime configuration from three sources, in this order:

1. API overrides (highest precedence)
2. Environment variables
3. `pyproject.toml` under `[tool.muninn]`

At the moment, Muninn does not expose any user-facing runtime configuration
items. This page documents the source model that future configuration items
will follow.
