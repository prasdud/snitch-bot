# snitch-bot

![rat](rat.webp)

Watches your `packages.json` for vulnerabilities and malicious packages using the [OSV](https://osv.dev) database. Sends alerts to Slack every 4 hours.

## How it works

1. Reads `packages.json` — a list of `{name, version}` packages
2. Batch queries OSV for known vulnerabilities
3. For each vuln found, fetches full details and derives severity (CRITICAL / HIGH / MEDIUM / LOW)
4. Finds the safe version to upgrade to
5. Sends a Slack alert with the package, severity, and recommended action

Malicious packages (`MAL-` IDs) are flagged separately with instructions to remove and rotate secrets.

## Setup

1. Clone the repo and create a `.env` file:
   ```
   SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
   ```

2. Install dependencies:
   ```bash
   python -m venv .venv
   .venv/bin/pip install requests schedule python-dotenv cvss
   ```

3. Edit `packages.json` with your packages:
   ```json
   [
     {"name": "axios", "version": "1.14.1"},
     {"name": "lodash", "version": "4.17.21"}
   ]
   ```

## Run

```bash
# Run once and keep running (checks every 4 hours)
.venv/bin/python main.py

# Dry run — prints Slack messages without sending
.venv/bin/python main.py --dry-run
```

Works with npm, pnpm, bun, and yarn.

## Generate `packages.json` (npm/pnpm/yarn/bun)

To build a scanner-ready merged list with exact resolved versions:

```bash
node scripts/export-packages.mjs --out packages.json
```

The script auto-detects package manager from lockfiles (`bun`, `pnpm`, `yarn`, `npm`), collects dependency trees, deduplicates by `name@version`, and writes:

```json
[
  {"name": "axios", "version": "1.14.1"}
]
```

You can also force a manager explicitly:

```bash
node scripts/export-packages.mjs --manager bun --out packages.json
```

Notes:
- Bun uses `bun list --all` text output; parsing is best-effort based on `name@version` tokens.
- npm/pnpm/yarn modes consume JSON output from their respective CLIs.
