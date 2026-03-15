# Changelog Fragments

Muninn uses [towncrier](https://towncrier.readthedocs.io/) to manage release notes.
Each pull request should include a changelog fragment file in this directory.

## File Naming

Fragment files follow the pattern `<PR_or_issue>.<type>`:

```txt
changes/123.parser_added
changes/124.parser_fixed
changes/125.core_added
changes/126.core_fixed
changes/127.breaking
changes/128.internal
```

For local changes not tied to a PR number yet, use an orphan fragment with `+`:

```txt
changes/+my-change.internal
```

## Fragment Types

| Type | Description |
|---|---|
| `parser_added` | New parser coverage for additional commands/platforms |
| `parser_updated` | Behavior updates or schema evolution for existing parsers |
| `parser_fixed` | Bug fixes to parser behavior or parsing accuracy |
| `core_added` | New non-parser library features |
| `core_fixed` | Bug fixes in core library functionality |
| `breaking` | Backward-incompatible changes |
| `internal` | CI/CD, tooling, docs process, refactors, or maintenance work |

## Writing Good Fragments

Each fragment should contain one concise, user-facing statement.
Empty or whitespace-only fragments fail CI.

Good:

```txt
Added parser support for `show bgp ipv6 unicast summary` on NX-OS.
```

Avoid implementation-heavy details when user impact can be described directly.

## Building a Release Changelog

Run the following command during release prep:

```bash
uv run towncrier build --version X.Y.Z --yes
```

This compiles fragments into `CHANGELOG.md` and removes consumed fragment files.
