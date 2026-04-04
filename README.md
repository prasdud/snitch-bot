# snitch-bot

![rat](rat.webp)

Watches your `packages.json` for vulnerabilities and malicious packages using the [OSV](https://osv.dev) database. Sends alerts to Slack every 4 hours.

## How it works

1. Reads `packages.json` as a list of `{name, version}` packages.
2. Calls `POST /v1/querybatch` to get vulnerability IDs for each package/version.
3. Fetches full details per vulnerability from `GET /v1/vulns/{id}`.
4. Derives severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`).
5. Persists raw findings to `scan-findings.json`.
6. Deduplicates to one alert per `name@version` (highest severity vuln), and writes `deduped-alerts.json`.
7. Sends Slack alerts from `deduped-alerts.json` and records sent keys in `cache.json`.

Malicious packages (`MAL-` IDs) are flagged as `CRITICAL` with stronger remediation guidance.

## Output artifacts

- `scan-findings.json`: raw/enriched vulnerability findings collected during a run.
- `deduped-alerts.json`: final one-alert-per-package payload used for Slack delivery.
- `cache.json`: cooldown cache to avoid re-alerting identical package/version + selected vulnerability within the dedupe window.

## Setup

1. Clone the repo and create a `.env` file:
   ```
   SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
   ```

2. Install dependencies:
   ```bash
   python3 -m venv .venv
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

## Alert semantics

- Alerts are deduplicated per `package@version` for each run.
- If a package/version has multiple vulnerabilities, only the highest-severity vulnerability is sent.
- Alert includes `Vulns found: N` so you can see total vuln count behind the selected top issue.
- If the same package appears in `packages.json` with different versions, each version can alert separately.

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

## Notes

- OSV `querybatch` does not return severity. Severity is derived only after fetching full vuln details.
- Recommended upgrade is best-effort from available fixed versions in OSV data.
