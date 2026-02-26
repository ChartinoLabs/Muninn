# Releasing Muninn

This project uses [towncrier](https://towncrier.readthedocs.io/) for changelog management.

## Release Steps

1. Ensure the working tree is clean and all tests pass.
2. Build the changelog from fragments:

   ```bash
   uv run towncrier build --version X.Y.Z --yes
   ```

3. Commit the updated `CHANGELOG.md` and removed fragment files.
4. Bump `project.version` in `pyproject.toml` if needed.
5. Tag and publish the release according to the repository's normal release flow.

## Notes

- Towncrier consumes (deletes) fragment files after build.
- Use `uv run towncrier build --draft --version X.Y.Z` to preview output before finalizing.
