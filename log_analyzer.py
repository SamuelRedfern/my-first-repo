import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

LOG_PATTERN = re.compile(r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)(?:\s+\[(?P<level>\w+)\])?\s*(?P<message>.*)$")

@dataclass
class LogEntry:
    timestamp: datetime
    level: str
    message: str
    raw: str


def parse_log_line(line: str) -> Optional[LogEntry]:
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None
    timestamp_text = match.group("timestamp")
    level = (match.group("level") or "INFO").upper()
    message = match.group("message") or ""
    try:
        timestamp = datetime.fromisoformat(timestamp_text.replace(" ", "T"))
    except ValueError:
        return None
    return LogEntry(timestamp=timestamp, level=level, message=message, raw=line.rstrip("\n"))


def analyze_logs(lines: List[str]) -> Dict[str, object]:
    parsed: List[LogEntry] = []
    failed_lines = 0
    for i, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        entry = parse_log_line(line)
        if entry is None:
            failed_lines += 1
            continue
        parsed.append(entry)

    if not parsed:
        return {
            "total": 0,
            "failed_lines": failed_lines,
            "levels": {},
            "first_timestamp": None,
            "last_timestamp": None,
            "top_messages": [],
        }

    levels: Dict[str, int] = {}
    msg_counts: Dict[str, int] = {}

    for e in parsed:
        levels[e.level] = levels.get(e.level, 0) + 1
        msg_counts[e.message] = msg_counts.get(e.message, 0) + 1

    top_messages = sorted(msg_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
    first_ts = min(e.timestamp for e in parsed)
    last_ts = max(e.timestamp for e in parsed)

    return {
        "total": len(parsed),
        "failed_lines": failed_lines,
        "levels": levels,
        "first_timestamp": first_ts.isoformat(),
        "last_timestamp": last_ts.isoformat(),
        "top_messages": top_messages,
    }


def format_summary(summary: Dict[str, object]) -> str:
    lines = [
        f"Log Analysis Summary:",
        f"  Parsed entries: {summary['total']}",
        f"  Failed parse lines: {summary['failed_lines']}",
    ]
    levels: Dict[str, int] = summary.get("levels", {})
    if levels:
        lines.append("  Levels:")
        for level, count in sorted(levels.items(), key=lambda kv: kv[1], reverse=True):
            lines.append(f"    {level}: {count}")

    if summary.get("first_timestamp"):
        lines.append(f"  First timestamp: {summary['first_timestamp']}")
    if summary.get("last_timestamp"):
        lines.append(f"  Last timestamp: {summary['last_timestamp']}")

    if summary.get("top_messages"):
        lines.append("  Top messages:")
        for msg, count in summary["top_messages"]:
            scrub = msg if len(msg) <= 100 else msg[:97] + "..."
            lines.append(f"    {count} × {scrub}")

    return "\n".join(lines)


def load_file(path: Path) -> List[str]:
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def analyze_file(path: Path) -> Dict[str, object]:
    lines = load_file(path)
    return analyze_logs(lines)


import argparse
