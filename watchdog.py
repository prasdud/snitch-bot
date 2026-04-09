'''
watchdog
watches over repositories PR
especially the packages.json and lockfiles and runs the same loop
main.py runs as cron, this only triggers on commits on PR

add it to a repo
init lock files
store that in cache
For a PR, on every new commit, run a action
if checksum(old_lockfile) != checksum(new_lockfile):
    run the loop
    report vulns as a comment
    update cache
else
    pass

'''

GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
GA_BASE_BRANCH = os.environ["GA_BASE_BRANCH"]
GA_HEAD_SHA = os.environ["GA_HEAD_SHA"]
GA_PR_NUMBER = os.environ["GA_PR_NUMBER"]
GA_REPO_URL = os.environ["GA_REPO_URL"]
GA_MANIFEST_PATH = os.environ["GA_MANIFEST_PATH"]
GA_LOCKFILE_PATH = os.environ["GA_LOCKFILE_PATH"]


# ─── Main Check ──────────────────────────────────────────────────────────────

def check():
    print(f"\n[watchdog] Starting watchdog")

    # TODO: compute checksum of lockfile on base branch vs head
    # if checksums match, print "[watchdog] Lockfile unchanged, skipping." and return

    # TODO: replace with diff-based package extraction
    # git diff GA_BASE_BRANCH...GA_HEAD_SHA -- GA_LOCKFILE_PATH
    # parse only added lines (+) to extract package name + version
    packages = read_packages()

    scan_findings = []
    if not packages:
        print("[watchdog] No packages to check, skipping.")
        return

    results = batch_query(packages)
    if not results:
        print("[watchdog] No results from OSV, skipping.")
        return

    affected_packages = 0
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }

    for package, result in zip(packages, results):
        vuln_ids = [v["id"] for v in result.get("vulns", [])]

        if not vuln_ids:
            continue

        affected_packages += 1
        print(f"[watchdog] {package['name']}@{package['version']} → {len(vuln_ids)} vuln(s) found")

        for vuln_id in vuln_ids:
            try:
                vuln = get_full_details(vuln_id)
                severity = derive_severity(vuln)
                safe_version = find_safe_version(vuln)
                scan_findings.append({
                    'package': package,
                    'vuln': vuln,
                    'severity': severity,
                    'safe_version': safe_version
                })
                time.sleep(0.2)
            except Exception as e:
                print(f"[watchdog] Error processing {vuln_id}: {e}")

    deduped_alerts = clean_duplicate_vuln(scan_findings)

    for alert in deduped_alerts:
        severity = alert["severity"]
        if severity in severity_counts:
            severity_counts[severity] += 1
        elif severity == "MODERATE":
            severity_counts["MEDIUM"] += 1
        else:
            severity_counts["UNKNOWN"] += 1

    # TODO: post_or_update_pr_comment(deduped_alerts, severity_counts, GA_HEAD_SHA, GA_PR_NUMBER)
    # find existing bot comment on PR by marker string, PATCH if found, POST if not
    # format as markdown table: package | version | vuln_id | severity | safe_version
    # include GA_HEAD_SHA at top so reviewers know which commit triggered it
    # if clean, update comment to reflect that — don't leave stale vuln comment

    # TODO: sys.exit(1) if severity_counts CRITICAL or HIGH > 0

    print(f"[watchdog] Check complete.")


# ─── Entry ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    check()