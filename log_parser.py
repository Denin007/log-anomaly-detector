#!/usr/bin/env python3
"""
Log Anomaly Detector
Author: Denin Sajan
Description: Parses Linux auth.log files to detect brute force attacks
             and suspicious login patterns. Generates structured reports.
"""

import re
import sys
from datetime import datetime
from collections import defaultdict

# ─── Configuration ───────────────────────────────────────────────────────────
LOG_FILE    = "sample_logs/auth.log"
REPORT_FILE = "reports/investigation_report.txt"
THRESHOLD   = 5   # failed attempts to trigger alert
WINDOW_SECS = 60  # time window in seconds

# ─── Regex Patterns ──────────────────────────────────────────────────────────
FAILED_PATTERN   = re.compile(
    r'(\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*(?:Failed password|authentication failure).*rhost=(\S+)'
)
ACCEPTED_PATTERN = re.compile(
    r'(\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Accepted password for (\S+) from (\S+)'
)

def parse_timestamp(ts_str):
    """Convert log timestamp to datetime object."""
    try:
        return datetime.strptime(f"2024 {ts_str.strip()}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

def parse_log(filepath):
    """Read log file and extract failed and successful login events."""
    failed   = defaultdict(list)   # ip -> [timestamps]
    accepted = []                  # list of (timestamp, user, ip)

    try:
        with open(filepath, "r", errors="ignore") as f:
            for line in f:
                # Check for failed attempts
                match = FAILED_PATTERN.search(line)
                if match:
                    ts  = parse_timestamp(match.group(1))
                    ip  = match.group(2).split("=")[-1]  # clean rhost= prefix
                    if ts and ip:
                        failed[ip].append(ts)

                # Check for successful logins
                match = ACCEPTED_PATTERN.search(line)
                if match:
                    ts   = parse_timestamp(match.group(1))
                    user = match.group(2)
                    ip   = match.group(3)
                    if ts:
                        accepted.append((ts, user, ip))

    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {filepath}")
        sys.exit(1)

    return failed, accepted

def detect_brute_force(failed, threshold, window):
    """Detect IPs with rapid repeated failures within a time window."""
    alerts = []
    for ip, timestamps in failed.items():
        timestamps.sort()
        for i in range(len(timestamps)):
            window_hits = [
                t for t in timestamps[i:]
                if (t - timestamps[i]).total_seconds() <= window
            ]
            if len(window_hits) >= threshold:
                alerts.append({
                    "ip"         : ip,
                    "count"      : len(timestamps),
                    "window_hits": len(window_hits),
                    "first_seen" : timestamps[0].strftime("%b %d %H:%M:%S"),
                    "last_seen"  : timestamps[-1].strftime("%b %d %H:%M:%S"),
                })
                break  # one alert per IP
    alerts.sort(key=lambda x: x["count"], reverse=True)
    return alerts

def generate_report(failed, accepted, alerts):
    """Write structured investigation report to file and print summary."""

    total_failed   = sum(len(v) for v in failed.values())
    total_accepted = len(accepted)
    unique_ips     = len(failed)

    lines = []
    lines.append("=" * 70)
    lines.append("  LOG ANOMALY DETECTOR — INVESTIGATION REPORT")
    lines.append("  Author  : Denin Sajan")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 70)

    lines.append("\n[1] EXECUTIVE SUMMARY")
    lines.append(f"    Total failed login attempts : {total_failed}")
    lines.append(f"    Total successful logins     : {total_accepted}")
    lines.append(f"    Unique source IPs           : {unique_ips}")
    lines.append(f"    Brute force alerts raised   : {len(alerts)}")
    lines.append(f"    Detection threshold         : {THRESHOLD} failures in {WINDOW_SECS}s")

    lines.append("\n[2] BRUTE FORCE ALERTS (HIGH PRIORITY)")
    if alerts:
        for i, a in enumerate(alerts, 1):
            lines.append(f"\n    [{i}] ALERT — Brute Force Detected")
            lines.append(f"        Source IP    : {a['ip']}")
            lines.append(f"        Total Fails  : {a['count']}")
            lines.append(f"        Burst (window): {a['window_hits']} attempts in {WINDOW_SECS}s")
            lines.append(f"        First Seen   : {a['first_seen']}")
            lines.append(f"        Last Seen    : {a['last_seen']}")
            lines.append(f"        Severity     : HIGH")
            lines.append(f"        Action       : Escalate to SOC L2 — recommend IP block")
    else:
        lines.append("    No brute force activity detected.")

    lines.append("\n[3] TOP 10 OFFENDING IPs")
    top_ips = sorted(failed.items(), key=lambda x: len(x[1]), reverse=True)[:10]
    for ip, ts in top_ips:
        lines.append(f"    {ip:<45} {len(ts):>5} failed attempts")

    lines.append("\n[4] SUCCESSFUL LOGINS LOG")
    if accepted:
        for ts, user, ip in sorted(accepted):
            lines.append(f"    {ts.strftime('%b %d %H:%M:%S')}  user={user:<15} from={ip}")
    else:
        lines.append("    No successful logins found in log.")

    lines.append("\n[5] RECOMMENDATIONS")
    lines.append("    - Block all IPs flagged in Section 2 at the firewall level")
    lines.append("    - Enable fail2ban or equivalent intrusion prevention")
    lines.append("    - Disable root SSH login (PermitRootLogin no)")
    lines.append("    - Enforce SSH key-based authentication")
    lines.append("    - Review successful logins for post-compromise activity")
    lines.append("    - Escalate confirmed incidents to Incident Response team")

    lines.append("\n" + "=" * 70)
    lines.append("  END OF REPORT")
    lines.append("=" * 70)

    report_text = "\n".join(lines)

    # Write to file
    with open(REPORT_FILE, "w") as f:
        f.write(report_text)

    # Print to terminal
    print(report_text)
    print(f"\n[✓] Report saved to: {REPORT_FILE}")

def main():
    print("[*] Starting Log Anomaly Detector...")
    print(f"[*] Parsing: {LOG_FILE}")

    failed, accepted = parse_log(LOG_FILE)
    alerts           = detect_brute_force(failed, THRESHOLD, WINDOW_SECS)

    print(f"[*] Parsed {sum(len(v) for v in failed.values())} failed attempts from {len(failed)} IPs")
    print(f"[*] Detected {len(alerts)} brute force alert(s)")
    print("[*] Generating report...\n")

    generate_report(failed, accepted, alerts)

if __name__ == "__main__":
    main()
