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
import math
from datetime import datetime, timezone
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
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")
SLACK_CHANNEL_ID = os.environ.get("SLACK_CHANNEL_ID")
PACKAGES_FILE = Path("packages.json")
CACHE_FILE   = Path("cache.json")
BATCH_SIZE   = 500
DEDUP_HOURS  = 24 * 7
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
    results = []

    for i in range(0, len(queries), BATCH_SIZE):
        chunk = queries[i:i + BATCH_SIZE]
        chunk_idx = (i // BATCH_SIZE) + 1
        total_chunks = (len(queries) + BATCH_SIZE - 1) // BATCH_SIZE
        print(f"[snitch] OSV chunk {chunk_idx}/{total_chunks} ({len(chunk)} queries)")
        try:
            res = requests.post(OSV_BATCH_URL, json={"queries": chunk}, timeout=30)
            res.raise_for_status()
            chunk_results = res.json().get("results", [])
        except requests.RequestException as e:
            print(f"[snitch] ERROR: OSV batch query failed on chunk {chunk_idx}: {e}")
            return []
        results.extend(chunk_results)

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


def load_cache():
    try:
        cache = json.loads(CACHE_FILE.read_text())
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as e:
        print(f"[snitch] ERROR: Failed to parse {CACHE_FILE}: {e}. Using empty cache.")
        return {}
    if not isinstance(cache, dict):
        print(f"[snitch] ERROR: Invalid {CACHE_FILE} format. Using empty cache.")
        return {}
    print(f"[snitch] Loaded {len(cache)} cache entries")
    return cache


def save_cache(cache):
    CACHE_FILE.write_text(json.dumps(cache, indent=2, sort_keys=True))


def cache_key(package, vuln_id):
    return f"{package['name']}@{package['version']}::{vuln_id}"


def check_cache_for_duplicate(key, cache, cooldown_hours=DEDUP_HOURS):
    last_sent = cache.get(key)
    if not last_sent:
        return False

    cooldown_seconds = cooldown_hours * 3600
    age_seconds = int(time.time()) - int(last_sent)
    if age_seconds < cooldown_seconds:
        return True

    return False


def mark_cache_sent(key, cache):
    cache[key] = int(time.time())
    save_cache(cache)


def post_slack_message(message, thread_ts=None):
    if DRY_RUN:
        print(f"[snitch] DRY RUN — Slack message would be:\n")
        print("─" * 60)
        print(message)
        if thread_ts:
            print(f"[thread_ts: {thread_ts}]")
        print("─" * 60)
        return True, None

    if SLACK_BOT_TOKEN and SLACK_CHANNEL_ID:
        payload = {
            "channel": SLACK_CHANNEL_ID,
            "text": message,
        }
        if thread_ts:
            payload["thread_ts"] = thread_ts

        try:
            res = requests.post(
                "https://slack.com/api/chat.postMessage",
                headers={
                    "Authorization": f"Bearer {SLACK_BOT_TOKEN}",
                    "Content-Type": "application/json; charset=utf-8",
                },
                json=payload,
                timeout=10,
            )
            res.raise_for_status()
            data = res.json()
            if not data.get("ok"):
                print(f"[snitch] ERROR: Slack API error: {data.get('error', 'unknown_error')}")
                return False, None
            return True, data.get("ts")
        except requests.RequestException as e:
            print(f"[snitch] ERROR: Slack API request failed: {e}")
            return False, None

    payload = {"text": message}
    if thread_ts:
        payload["thread_ts"] = thread_ts

    try:
        res = requests.post(SLACK_WEBHOOK, json=payload, timeout=10)
        res.raise_for_status()
    except requests.RequestException as e:
        print(f"[snitch] ERROR: Slack webhook failed: {e}")
        return False, None
    return True, None


def create_run_thread(packages_count):
    started_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    message = (
        "🧵 *Snitch Scan Started*\n"
        f"*Started:* {started_at}\n"
        f"*Packages:* {packages_count}\n"
        f"*Mode:* {'DRY RUN' if DRY_RUN else 'LIVE'}"
    )
    sent, ts = post_slack_message(message)
    return ts if sent else None


def send_scan_complete_summary(metrics):
    duration_seconds = metrics["duration_seconds"]
    minutes, seconds = divmod(int(duration_seconds), 60)
    duration_display = f"{minutes:02d}:{seconds:02d}"

    message = (
        "✅ *Snitch Scan Complete*\n"
        f"*Started:* {metrics['started_at']}\n"
        f"*Duration:* {duration_display}\n"
        f"*Packages:* total={metrics['packages_total']} affected={metrics['affected_packages']} clean={metrics['clean_packages']}\n"
        f"*Severity:* C={metrics['severity_counts']['CRITICAL']} H={metrics['severity_counts']['HIGH']} M={metrics['severity_counts']['MEDIUM']} L={metrics['severity_counts']['LOW']} U={metrics['severity_counts']['UNKNOWN']}\n"
        f"*Alerts:* sent={metrics['alerts_sent']} skipped={metrics['alerts_skipped']} failed={metrics['alerts_failed']}\n"
        f"*OSV:* batch_calls={metrics['osv_batch_calls']} detail_fetches={metrics['osv_detail_fetches']}"
    )
    sent, _ = post_slack_message(message)
    if not sent:
        print("[snitch] ERROR: Failed to send scan complete summary")

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

    print(f"[snitch] Sending Slack alert for {vuln['id']}...")
    sent, _ = post_slack_message(message, thread_ts=send_slack_alert.thread_ts)
    if not sent:
        print(f"[snitch] ERROR: Slack alert failed for {vuln['id']}")
        return False
    print(f"[snitch] Slack alert sent")
    return True


send_slack_alert.thread_ts = None


# ─── Main Check ──────────────────────────────────────────────────────────────

def check():
    print(f"\n[snitch] Starting check {'(DRY RUN)' if DRY_RUN else ''}...")
    started_at = datetime.now(timezone.utc)
    cache = load_cache()
    packages = read_packages()
    if not packages:
        print("[snitch] No packages to check, skipping.")
        return
    results  = batch_query(packages)
    if not results:
        print("[snitch] No results from OSV, skipping.")
        return

    osv_batch_calls = math.ceil(len(packages) / BATCH_SIZE)
    send_slack_alert.thread_ts = create_run_thread(len(packages))
    total    = 0
    skipped_total = 0
    failed_total = 0
    affected_packages = 0
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }
    osv_detail_fetches = 0

    for package, result in zip(packages, results):
        vuln_ids = [v["id"] for v in result.get("vulns", [])]

        if not vuln_ids:
            # print(f"[snitch] {package['name']}@{package['version']} → clean")
            continue

        affected_packages += 1

        print(f"[snitch] {package['name']}@{package['version']} → {len(vuln_ids)} vuln(s) found")

        for vuln_id in vuln_ids:
            try:
                key = cache_key(package, vuln_id)
                if check_cache_for_duplicate(key, cache):
                    print(f"[snitch] Duplicate alert skipped: {key}")
                    skipped_total += 1
                    continue

                vuln         = get_full_details(vuln_id)
                osv_detail_fetches += 1
                severity     = derive_severity(vuln)
                if severity in severity_counts:
                    severity_counts[severity] += 1
                elif severity == "MODERATE":
                    severity_counts["MEDIUM"] += 1
                else:
                    severity_counts["UNKNOWN"] += 1
                safe_version = find_safe_version(vuln)
                sent = send_slack_alert(package, vuln, severity, safe_version)
                if sent:
                    total += 1
                    # if not DRY_RUN:
                    mark_cache_sent(key, cache)
                else:
                    failed_total += 1
                time.sleep(0.2)
            except Exception as e:
                print(f"[snitch] Error processing {vuln_id}: {e}")
                failed_total += 1

    clean_packages = len(packages) - affected_packages
    metrics = {
        "started_at": started_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "duration_seconds": time.time() - started_at.timestamp(),
        "packages_total": len(packages),
        "affected_packages": affected_packages,
        "clean_packages": clean_packages,
        "severity_counts": severity_counts,
        "alerts_sent": total,
        "alerts_skipped": skipped_total,
        "alerts_failed": failed_total,
        "osv_batch_calls": osv_batch_calls,
        "osv_detail_fetches": osv_detail_fetches,
    }
    send_scan_complete_summary(metrics)

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
