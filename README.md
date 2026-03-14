# Python Security Log Analyzer (SOC Utility)

A lightweight SOC-style log analysis tool that parses ISO8601-like logs, extracts IPs, summarizes events, and detects security alerts.

## Features

- Parses logs with timestamp, log level, message, and optional IP extraction
- Summarizes counts by level, timestamp range, top messages, and top source IPs
- Runs security detections:
  - Brute-force detection from repeated failed login attempts
  - Suspicious high-volume IP activity
  - Error spike detection
- Optional anomaly detection via IsolationForest (scikit-learn)
- Supports CLI output: text summary, JSON output, alerts-only mode

## Usage

1. Create a log file (example `sample.log`):

```
2026-03-14T10:00:00 [INFO] Server started
2026-03-14T10:01:00 [WARN] High memory usage
2026-03-14T10:02:00 [ERROR] Could not connect to database
2026-03-14 10:03:00 [INFO] Request completed
```

2. Run:

```bash
python main.py sample.log
```

3. Write to output file:

```bash
python main.py sample.log -o report.txt
```

4. Show security alerts only:

```bash
python main.py sample.log --alerts-only
```

5. Output JSON with summary and alerts:

```bash
python main.py sample.log --json
```

6. Print version:

```bash
python main.py --version
```

## Example output

### Normal summary
```
Log Analysis Summary:
  Parsed entries: 57
  Failed parse lines: 0
  Levels:
    INFO: 40
    WARN: 9
    ERROR: 8
  First timestamp: 2026-03-14T08:00:00
  Last timestamp: 2026-03-14T11:30:55
  Top messages:
    6 × Request completed: /api/data
    ...
  Top IPs:
    192.168.1.10: 14 events

Security Alerts:
- [HIGH] Possible brute force login attack from 192.168.1.10
- [MEDIUM] High-volume event activity from a single IP from 45.22.10.5
```

### Alerts-only mode
```
Security Alerts:
- [HIGH] Possible brute force login attack from 192.168.1.10
- [MEDIUM] High-volume event activity from a single IP from 45.22.10.5
```
