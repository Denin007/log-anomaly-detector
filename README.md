# Log Anomaly Detector

A Python-based security tool that parses Linux auth.log files to detect brute force attacks and suspicious SSH login patterns — producing structured investigation reports in the format used by SOC analysts.

## What It Does

- Parses real Linux authentication logs (/var/log/auth.log format)
- Detects brute force attacks using a sliding time-window algorithm
- Identifies top offending IPs ranked by attack volume
- Logs all successful authentications for post-compromise review
- Generates a structured investigation report with severity ratings, escalation recommendations, and remediation steps

## Sample Output

    [1] EXECUTIVE SUMMARY
        Total failed login attempts : 489
        Total successful logins     : 0
        Unique source IPs           : 47
        Brute force alerts raised   : 39
        Detection threshold         : 5 failures in 60s

    [2] BRUTE FORCE ALERTS (HIGH PRIORITY)
        ALERT — Brute Force Detected
        Source IP     : 218.188.2.4
        Total Fails   : 14
        Severity      : HIGH
        Action        : Escalate to SOC L2 — recommend IP block

## Tools and Dataset

- Language: Python 3
- Dataset: Loghub Linux 2k — real SSH authentication logs used in academic security research
- No external libraries required — built on Python standard library only

## How to Run

    git clone https://github.com/Denin007/log-anomaly-detector.git
    cd log-anomaly-detector
    python3 log_parser.py

Report is saved to reports/investigation_report.txt

## Detection Logic

The tool uses a sliding window algorithm — for each IP address, it scans all recorded failure timestamps and checks whether N or more failures occur within a configurable time window (default: 5 failures in 60 seconds). This mirrors the detection methodology used in production SIEM rule tuning.

## Skills Demonstrated

- Log parsing and pattern matching with Python regex
- Brute force detection algorithm design
- SOC-style incident documentation and escalation reporting
- Real dataset analysis: 489 events, 47 IPs, 39 alerts generated
- Security recommendations aligned to NIST and CIS controls

## Author

Denin Sajan — MSc Cyber Security
LinkedIn: https://linkedin.com/in/denin-sajan
GitHub: https://github.com/Denin007/denin-sajan
