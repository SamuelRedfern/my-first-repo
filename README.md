# Python Log Analyzer

A simple Python log analyzer that parses ISO8601-like timestamped log lines and summarizes counts by level, time range, and top messages.

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

4. View security alerts:

```bash
python main.py sample.log --alerts-only
```

5. JSON output including alerts:

```bash
python main.py sample.log --json
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
