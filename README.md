# Python Security Log Analyzer (SOC Utility)

A lightweight SOC-style log analysis tool that parses ISO8601-like logs, extracts IPs, summarizes events, detects security alerts, and enriches selected alerts with MITRE ATT&CK mappings.

## Features

- Parses logs with timestamp, log level, message, and optional IP extraction
- Summarizes counts by level, timestamp range, top messages, and top source IPs
- Runs security detections:
  - Brute-force detection from repeated failed login attempts
  - Suspicious high-volume IP activity in a time window
  - Error spike detection with IP breakdown
- Runs anomaly detection with Isolation Forest (`scikit-learn`)
- Enriches mapped alerts with MITRE ATT&CK tactic and technique metadata
- Supports CLI output: text summary, JSON output, alerts-only mode

## Requirements

- Python 3
- Runtime dependencies from `requirements.txt`

## Setup

1. Create a virtual environment:

```powershell
python -m venv venv
```

2. Activate it:

```powershell
.\venv\Scripts\Activate.ps1
```

3. Install runtime dependencies:

```powershell
python -m pip install -r requirements.txt
```

## Usage

1. Create a log file, for example `sample.log`:

```text
2026-03-14T10:00:00 [INFO] Server started
2026-03-14T10:01:00 [WARN] High memory usage
2026-03-14T10:02:00 [ERROR] Could not connect to database
2026-03-14 10:03:00 [INFO] Request completed
```

2. Run the analyzer:

```powershell
python main.py sample.log
```

3. Write the report to a file:

```powershell
python main.py sample.log -o report.txt
```

4. Show alerts only:

```powershell
python main.py sample.log --alerts-only
```

5. Output JSON:

```powershell
python main.py sample.log --json
```

6. Print the version:

```powershell
python main.py --version
```

## MITRE ATT&CK Mapping

The current ATT&CK enrichment is intentionally conservative.

- `brute_force` alerts are mapped to:
  - `TA0006 Credential Access`
  - `T1110 Brute Force`
- Other alerts are currently left unmapped and displayed as `Not directly mapped`

This keeps the project accurate by only attaching ATT&CK metadata where the signal is strong.

## Example Output

### Alerts-only mode

```text
Security Alerts:
- [LOW] Suspicious failed login rate from 203.0.113.77
  MITRE ATT&CK: TA0006 Credential Access -> T1110 Brute Force
- [LOW] Suspicious failed login rate from 45.33.22.19
  MITRE ATT&CK: TA0006 Credential Access -> T1110 Brute Force
- [LOW] Suspicious failed login rate from 91.134.17.42
  MITRE ATT&CK: TA0006 Credential Access -> T1110 Brute Force
- [HIGH] Unusual IP behavior detected using Isolation Forest from 203.0.113.77
  MITRE ATT&CK: Not directly mapped
```

### JSON alert example

```json
{
  "type": "brute_force",
  "severity": "LOW",
  "ip": "203.0.113.77",
  "count": 10,
  "description": "Suspicious failed login rate",
  "meta": {
    "window_minutes": 1,
    "threshold": 5,
    "window_count": 10,
    "first_seen": "2026-03-14T17:02:01",
    "last_seen": "2026-03-14T17:02:10"
  },
  "mitre_attack": [
    {
      "tactic": "Credential Access",
      "tactic_id": "TA0006",
      "technique": "Brute Force",
      "technique_id": "T1110",
      "confidence": "high",
      "mapping_note": "Repeated failed login attempts align with ATT&CK Brute Force."
    }
  ]
}
```
