import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

LOG_PATTERN = re.compile(r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)(?:\s+\[(?P<level>\w+)\])?\s*(?P<message>.*)$")
IP_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")


@dataclass
class LogEntry:
    timestamp: datetime
    level: str
    message: str
    raw: str
    ip: Optional[str] = None


@dataclass
class AnalysisResult:
    summary: Dict[str, object]
    parsed_entries: List[LogEntry]


def extract_ip_from_text(text: str) -> Optional[str]:
    match = IP_PATTERN.search(text)
    if not match:
        return None
    return match.group(0)


def parse_log_line(line: str) -> Optional[LogEntry]:
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None
    timestamp_text = match.group("timestamp")
    level = (match.group("level") or "INFO").upper()
    message = match.group("message") or ""
    ip = extract_ip_from_text(message)
    try:
        timestamp = datetime.fromisoformat(timestamp_text.replace(" ", "T"))
    except ValueError:
        return None
    return LogEntry(timestamp=timestamp, level=level, message=message, raw=line.rstrip("\n"), ip=ip)


def analyze_logs(lines: List[str]) -> AnalysisResult:
    parsed: List[LogEntry] = []
    failed_lines = 0
    for line in lines:
        if not line.strip():
            continue
        entry = parse_log_line(line)
        if entry is None:
            failed_lines += 1
            continue
        parsed.append(entry)

    if not parsed:
        return AnalysisResult(
            summary={
                "total": 0,
                "failed_lines": failed_lines,
                "levels": {},
                "first_timestamp": None,
                "last_timestamp": None,
                "top_messages": [],
                "ip_counts": {},
                "ip_error_counts": {},
                "ip_unique_message_counts": {},
                "top_ips": [],
            },
            parsed_entries=[],
        )

    levels: Dict[str, int] = {}
    msg_counts: Dict[str, int] = {}
    ip_counts: Dict[str, int] = {}
    ip_error_counts: Dict[str, int] = {}
    ip_messages: Dict[str, Set[str]] = {}

    for entry in parsed:
        levels[entry.level] = levels.get(entry.level, 0) + 1
        msg_counts[entry.message] = msg_counts.get(entry.message, 0) + 1
        if entry.ip:
            ip_counts[entry.ip] = ip_counts.get(entry.ip, 0) + 1
            ip_messages.setdefault(entry.ip, set()).add(entry.message)
            if entry.level == "ERROR":
                ip_error_counts[entry.ip] = ip_error_counts.get(entry.ip, 0) + 1

    top_messages = sorted(msg_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
    top_ips = sorted(ip_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
    first_ts = min(entry.timestamp for entry in parsed)
    last_ts = max(entry.timestamp for entry in parsed)

    return AnalysisResult(
        summary={
            "total": len(parsed),
            "failed_lines": failed_lines,
            "levels": levels,
            "first_timestamp": first_ts.isoformat(),
            "last_timestamp": last_ts.isoformat(),
            "top_messages": top_messages,
            "ip_counts": ip_counts,
            "ip_error_counts": ip_error_counts,
            "ip_unique_message_counts": {ip: len(msgs) for ip, msgs in ip_messages.items()},
            "top_ips": top_ips,
        },
        parsed_entries=parsed,
    )


def format_summary(summary: Dict[str, object]) -> str:
    lines = [
        "Log Analysis Summary:",
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
            lines.append(f"    {count} x {scrub}")

    ip_counts = summary.get("ip_counts", {})
    if ip_counts:
        lines.append("  Top IPs:")
        top_ips = sorted(ip_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
        for ip, count in top_ips:
            lines.append(f"    {ip}: {count} events")

    return "\n".join(lines)


def load_file(path: Path) -> List[str]:
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def analyze_file(path: Path) -> AnalysisResult:
    lines = load_file(path)
    return analyze_logs(lines)
