# Real exporter integration tests

These tests create real dependency installs for each package manager and verify that
`scripts/export-packages.mjs` produces valid scanner-ready `packages.json` output.

## Run

```bash
node tests/run-real-exporter-tests.mjs
```

The test runner uses projects in `tests/projects/`:

- `tests/projects/npm-project`
- `tests/projects/pnpm-project`
- `tests/projects/yarn-project`
- `tests/projects/bun-project`

Checks performed per project:

- installs dependencies with that manager
- runs exporter with explicit `--manager`
- validates output schema and exact versions
- validates known dependencies are present
