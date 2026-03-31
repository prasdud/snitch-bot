'''
read packages.json (packageName: versionNumber)
hit https://api.osv.dev/v1/querybatch with content of packages.json get vuln ids
fetch each id -> get full details
derive severity
find safe version (first version before affected range)
slack: package, severity, affected versions, recommended action
'''

import json
import os
import time
import schedule
import requests
import sys
from cvss import CVSS3
from dotenv import load_dotenv
from pathlib import Path

load_dotenv()

# ─── Constants ───────────────────────────────────────────────────────────────

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL  = "https://api.osv.dev/v1/vulns"
SLACK_WEBHOOK = os.environ["SLACK_WEBHOOK_URL"]
PACKAGES_FILE = Path("packages.json")
DRY_RUN       = "--dry-run" in sys.argv

# ─── Core Functions ──────────────────────────────────────────────────────────

def read_packages():
    try:
        packages = json.loads(PACKAGES_FILE.read_text())
    except FileNotFoundError:
        print(f"[snitch] ERROR: {PACKAGES_FILE} not found")
        return []
    except json.JSONDecodeError as e:
        print(f"[snitch] ERROR: Failed to parse {PACKAGES_FILE}: {e}")
        return []
    print(f"[snitch] Loaded {len(packages)} packages")
    return packages


def batch_query(packages):
    print(f"[snitch] Querying OSV for {len(packages)} packages...")
    # ecosystem "npm" covers npm, pnpm, bun, and yarn — they share the same registry
    queries = [
        {"version": p["version"], "package": {"name": p["name"], "ecosystem": "npm"}}
        for p in packages
    ]
    try:
        res = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=30)
        res.raise_for_status()
        results = res.json().get("results", [])
    except requests.RequestException as e:
        print(f"[snitch] ERROR: OSV batch query failed: {e}")
        return []
    print(f"[snitch] OSV responded OK")
    return results


def get_full_details(vuln_id):
    print(f"[snitch] Fetching details for {vuln_id}...")
    res = requests.get(f"{OSV_VULN_URL}/{vuln_id}", timeout=30)
    res.raise_for_status()
    return res.json()


def derive_severity(vuln):
    vuln_id = vuln.get("id", "")

    if vuln_id.startswith("MAL-"):
        severity = "CRITICAL"
        print(f"[snitch] {vuln_id} → severity: {severity} (malicious package)")
        return severity

    db_severity = vuln.get("database_specific", {}).get("severity")
    if db_severity:
        severity = db_severity.upper()
        print(f"[snitch] {vuln_id} → severity: {severity} (from database_specific)")
        return severity

    severity_list = vuln.get("severity", [])
    if severity_list:
        score_str = severity_list[0].get("score", "")
        try:
            score = CVSS3(score_str).base_score
            if score >= 9.0: severity = "CRITICAL"
            elif score >= 7.0: severity = "HIGH"
            elif score >= 4.0: severity = "MEDIUM"
            else: severity = "LOW"
            print(f"[snitch] {vuln_id} → severity: {severity} (from CVSS score {score})")
            return severity
        except Exception:
            pass

    print(f"[snitch] {vuln_id} → severity: UNKNOWN (no severity data)")
    return "UNKNOWN"


def find_safe_version(vuln):
    affected = vuln.get("affected", [])

    for entry in affected:
        for r in entry.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    version = event["fixed"]
                    print(f"[snitch] {vuln['id']} → safe version: {version}")
                    return version

    print(f"[snitch] {vuln['id']} → safe version: not found")
    return None


def send_slack_alert(package, vuln, severity, safe_version):
    is_mal = vuln.get("id", "").startswith("MAL-")

    emoji  = "🚨" if is_mal else "⚠️"
    action = "Do NOT downgrade — nuke it entirely. Rotate all secrets." if is_mal \
             else f"Upgrade to `{safe_version}`" if safe_version \
             else "No safe version found — check manually."

    message = (
        f"{emoji} *{'MALICIOUS PACKAGE' if is_mal else 'Vulnerability Detected'}*\n"
        f"*Package:* `{package['name']}@{package['version']}`\n"
        f"*ID:* {vuln['id']}\n"
        f"*Summary:* {vuln.get('summary', 'N/A')}\n"
        f"*Severity:* {severity}\n"
        f"*Action:* {action}"
    )

    if DRY_RUN:
        print(f"[snitch] DRY RUN — Slack message would be:\n")
        print("─" * 60)
        print(message)
        print("─" * 60)
        return

    print(f"[snitch] Sending Slack alert for {vuln['id']}...")
    try:
        res = requests.post(SLACK_WEBHOOK, json={"text": message}, timeout=10)
        res.raise_for_status()
    except requests.RequestException as e:
        print(f"[snitch] ERROR: Slack alert failed for {vuln['id']}: {e}")
        return
    print(f"[snitch] Slack alert sent")


# ─── Main Check ──────────────────────────────────────────────────────────────

def check():
    print(f"\n[snitch] Starting check {'(DRY RUN)' if DRY_RUN else ''}...")
    packages = read_packages()
    if not packages:
        print("[snitch] No packages to check, skipping.")
        return
    results  = batch_query(packages)
    if not results:
        print("[snitch] No results from OSV, skipping.")
        return
    total    = 0

    for package, result in zip(packages, results):
        vuln_ids = [v["id"] for v in result.get("vulns", [])]

        if not vuln_ids:
            print(f"[snitch] {package['name']}@{package['version']} → clean")
            continue

        print(f"[snitch] {package['name']}@{package['version']} → {len(vuln_ids)} vuln(s) found")

        for vuln_id in vuln_ids:
            try:
                vuln         = get_full_details(vuln_id)
                severity     = derive_severity(vuln)
                safe_version = find_safe_version(vuln)
                send_slack_alert(package, vuln, severity, safe_version)
                total += 1
                time.sleep(0.2)
            except Exception as e:
                print(f"[snitch] Error processing {vuln_id}: {e}")

    print(f"[snitch] Check complete. {total} alert(s) sent.\n")


# ─── Scheduler ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if DRY_RUN:
        print("[snitch] Dry run mode — no Slack messages will be sent")
        check()
    else:
        check()
        schedule.every(4).hours.do(check)
        print("[snitch] Snitch-bot running...")
        while True:
            try:
                schedule.run_pending()
            except Exception as e:
                print(f"[snitch] ERROR: Unexpected error in scheduler: {e}")
            time.sleep(60)
