import re
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Deque, Dict, List, Optional, Tuple

from log_analyzer import LogEntry

FAILED_LOGIN_PATTERNS = re.compile(r"failed .*login|login .*failed|authentication failed|invalid credentials", re.I)
IP_EVENTS_THRESHOLD = 80
IP_ACTIVITY_WINDOW_MINUTES = 10
BRUTE_FORCE_RULES = [
    {"count": 50, "minutes": 15, "severity": "HIGH", "description": "Likely brute force login attack"},
    {"count": 20, "minutes": 5, "severity": "MEDIUM", "description": "Possible brute force login activity"},
    {"count": 5, "minutes": 1, "severity": "LOW", "description": "Suspicious failed login rate"},
]
ERROR_SPIKE_THRESHOLD = 10
ERROR_SPIKE_WINDOW_MINUTES = 10


@dataclass
class SecurityAlert:
    type: str
    severity: str
    ip: Optional[str]
    count: int
    description: str
    meta: Dict[str, object]

    def to_dict(self) -> Dict[str, object]:
        return {
            "type": self.type,
            "severity": self.severity,
            "ip": self.ip,
            "count": self.count,
            "description": self.description,
            "meta": self.meta,
        }


def _sliding_window_peak(times: List[datetime], window_minutes: int) -> Tuple[int, Optional[datetime], Optional[datetime]]:
    if not times:
        return 0, None, None

    window: Deque[datetime] = deque()
    peak_count = 0
    peak_start: Optional[datetime] = None
    peak_end: Optional[datetime] = None
    window_span = timedelta(minutes=window_minutes)

    for timestamp in times:
        window.append(timestamp)
        while window and timestamp - window[0] > window_span:
            window.popleft()
        if len(window) > peak_count:
            peak_count = len(window)
            peak_start = window[0]
            peak_end = timestamp

    return peak_count, peak_start, peak_end


def detect_brute_force(entries: List[LogEntry]) -> List[SecurityAlert]:
    ip_failed: Dict[str, List[datetime]] = defaultdict(list)
    for entry in entries:
        if entry.ip is None:
            continue
        if FAILED_LOGIN_PATTERNS.search(entry.message):
            ip_failed[entry.ip].append(entry.timestamp)

    alerts: List[SecurityAlert] = []
    for ip, time_list in ip_failed.items():
        time_list.sort()
        for rule in BRUTE_FORCE_RULES:
            peak_count, peak_start, peak_end = _sliding_window_peak(time_list, rule["minutes"])
            if peak_count < rule["count"]:
                continue
            alerts.append(
                SecurityAlert(
                    type="brute_force",
                    severity=rule["severity"],
                    ip=ip,
                    count=peak_count,
                    description=rule["description"],
                    meta={
                        "window_minutes": rule["minutes"],
                        "threshold": rule["count"],
                        "window_count": peak_count,
                        "first_seen": peak_start.isoformat() if peak_start else None,
                        "last_seen": peak_end.isoformat() if peak_end else None,
                    },
                )
            )
            break
    return alerts


def detect_suspicious_ip_activity(
    entries: List[LogEntry],
    threshold: int = IP_EVENTS_THRESHOLD,
    window_minutes: int = IP_ACTIVITY_WINDOW_MINUTES,
) -> List[SecurityAlert]:
    ip_times: Dict[str, List[datetime]] = defaultdict(list)
    ip_levels: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for entry in entries:
        if entry.ip:
            ip_times[entry.ip].append(entry.timestamp)
            ip_levels[entry.ip][entry.level] += 1

    alerts: List[SecurityAlert] = []
    for ip, times in ip_times.items():
        times.sort()
        peak_count, peak_start, peak_end = _sliding_window_peak(times, window_minutes)
        if peak_count >= threshold:
            severity = "HIGH" if peak_count >= threshold * 2 else "MEDIUM"
            alerts.append(
                SecurityAlert(
                    type="suspicious_ip_activity",
                    severity=severity,
                    ip=ip,
                    count=peak_count,
                    description="High-volume event activity from a single IP in a short time window",
                    meta={
                        "window_minutes": window_minutes,
                        "peak_event_count": peak_count,
                        "first_seen": peak_start.isoformat() if peak_start else None,
                        "last_seen": peak_end.isoformat() if peak_end else None,
                        "level_counts": dict(ip_levels[ip]),
                    },
                )
            )
    return alerts


def detect_error_spike(
    entries: List[LogEntry],
    threshold: int = ERROR_SPIKE_THRESHOLD,
    window_minutes: int = ERROR_SPIKE_WINDOW_MINUTES,
) -> List[SecurityAlert]:
    error_entries = [entry for entry in entries if entry.level == "ERROR"]
    if len(error_entries) < threshold:
        return []

    error_entries.sort(key=lambda entry: entry.timestamp)
    alerts: List[SecurityAlert] = []
    window: Deque[LogEntry] = deque()
    window_delta = timedelta(minutes=window_minutes)
    peak_window: List[LogEntry] = []

    for entry in error_entries:
        window.append(entry)
        while window and entry.timestamp - window[0].timestamp > window_delta:
            window.popleft()
        if len(window) > len(peak_window):
            peak_window = list(window)

    if len(peak_window) < threshold:
        return []

    ip_breakdown: Dict[str, int] = defaultdict(int)
    for entry in peak_window:
        ip_breakdown[entry.ip or "unknown"] += 1

    alerts.append(
        SecurityAlert(
            type="error_spike",
            severity="HIGH" if len(peak_window) >= threshold * 2 else "MEDIUM",
            ip=None,
            count=len(peak_window),
            description=f"Error spike detected: {len(peak_window)} ERROR logs in {window_minutes} min",
            meta={
                "window_minutes": window_minutes,
                "events": len(peak_window),
                "first_seen": peak_window[0].timestamp.isoformat(),
                "last_seen": peak_window[-1].timestamp.isoformat(),
                "ip_breakdown": dict(ip_breakdown),
            },
        )
    )
    return alerts


def run_security_detections(entries: List[LogEntry]) -> List[Dict[str, object]]:
    alerts: List[SecurityAlert] = []
    alerts.extend(detect_brute_force(entries))
    alerts.extend(detect_suspicious_ip_activity(entries))
    alerts.extend(detect_error_spike(entries))
    return [alert.to_dict() for alert in alerts]
