# Releasing Muninn

This document describes the complete procedure for cutting a new release of Muninn.

## Prerequisites

- You have push access to the `main` branch
- You have permission to create tags on the repository
- [uv](https://docs.astral.sh/uv/) is installed locally

## Step-by-Step Release Procedure

### 1. Verify Changelog Fragments Exist

Check that there are pending changelog fragments in the `changes/` directory:

```shell
ls changes/
```

You should see files like `123.parser_added`, `456.core_fixed`, `+description.internal`, etc. If there are no fragments, there is nothing to release.

### 2. Preview the Changelog (Optional)

Preview the changelog output before finalizing:

```shell
uv run towncrier build --draft --version X.Y.Z
```

### 3. Compile the Changelog

Run towncrier with the new version number (following [semver](https://semver.org/)):

```shell
uv run towncrier build --version X.Y.Z
```

This will:

- Compile fragments into `CHANGELOG.md`
- Delete the consumed fragment files from `changes/`

### 4. Review the Generated Changelog Entry

Open `CHANGELOG.md` and review the new entry at the top. Verify that:

- All expected changes are listed
- Descriptions are accurate and user-facing
- PR links are correct

### 5. Commit the Changelog

Stage and commit the compiled changelog and the removed fragment files:

```shell
git add CHANGELOG.md changes/
git commit -m "Release vX.Y.Z"
```

### 6. Push to `main`

Push the release commit to `main` and wait for CI to pass:

```shell
git push origin main
```

Monitor the CI pipeline to confirm all checks pass before proceeding. Do **not** create the tag until CI is green.

### 7. Tag the Release

Once CI passes on `main`, create the version tag:

```shell
git tag vX.Y.Z
```

### 8. Push the Tag

Push the tag to trigger the release pipeline:

```shell
git push origin vX.Y.Z
```

### 9. Monitor the Release

After pushing the tag, the CI pipeline (`publish.yml`) automatically:

1. **Builds the package** — creates sdist and wheel via `uv build`, with the version derived from the git tag (hatch-vcs)
2. **Verifies version consistency** — confirms the built package version matches the tag
3. **Creates a GitHub Release** — extracts the version's section from `CHANGELOG.md` and publishes it as release notes
4. **Publishes to PyPI** — uploads `muninn-parsers` to PyPI using `pypa/gh-action-pypi-publish`

Monitor these jobs in the GitHub Actions tab to confirm they all succeed.

## Version Management

Muninn uses [hatch-vcs](https://github.com/ofek/hatch-vcs) for dynamic versioning. There is no hardcoded version in `pyproject.toml` — the version is derived entirely from git tags.

- **Tagged commits** (e.g., `v0.1.0`) produce exact versions: `0.1.0`
- **Untagged commits** produce dev versions: `0.1.dev358+gc73a125`

## Troubleshooting

### CI fails after pushing `main`

Fix the issue, push again, and wait for CI to pass before tagging. The tag must point to a commit where CI is green.

### Version mismatch error during build

The publish workflow verifies that the package version matches the git tag. If this fails:

- Ensure the tag follows the `vX.Y.Z` format
- Ensure the tag is on the correct commit (the release commit on `main`)
- Ensure `fetch-depth: 0` is set in the checkout step so hatch-vcs has full git history

### GitHub Release shows "No changelog entry found"

The release job extracts the section from `CHANGELOG.md` matching the tag version. Verify that:

- The version heading in `CHANGELOG.md` matches the tag (e.g., tag `v0.1.0` expects a `## 0.1.0 - YYYY-MM-DD` heading)
- The release commit with `CHANGELOG.md` changes is an ancestor of the tagged commit
