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
