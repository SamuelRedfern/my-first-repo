import re
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from log_analyzer import LogEntry

FAILED_LOGIN_PATTERNS = re.compile(r"failed .*login|login .*failed|authentication failed|invalid credentials", re.I)
IP_EVENTS_THRESHOLD = 80
BRUTE_FORCE_THRESHOLD = 10
BRUTE_FORCE_WINDOW_MINUTES = 5
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


def detect_brute_force(entries: List[LogEntry], threshold: int = BRUTE_FORCE_THRESHOLD,
                       window_minutes: int = BRUTE_FORCE_WINDOW_MINUTES) -> List[SecurityAlert]:
    ip_failed: Dict[str, List[datetime]] = defaultdict(list)
    for entry in entries:
        if entry.ip is None:
            continue
        if FAILED_LOGIN_PATTERNS.search(entry.message):
            ip_failed[entry.ip].append(entry.timestamp)

    alerts: List[SecurityAlert] = []
    for ip, time_list in ip_failed.items():
        time_list.sort()
        window = deque()
        window_span = timedelta(minutes=window_minutes)
        for ts in time_list:
            window.append(ts)
            while window and ts - window[0] > window_span:
                window.popleft()
            if len(window) > threshold:
                alerts.append(SecurityAlert(
                    type="brute_force",
                    severity="HIGH",
                    ip=ip,
                    count=len(window),
                    description="Possible brute force login attack",
                    meta={
                        "window_minutes": window_minutes,
                        "threshold": threshold,
                        "window_count": len(window),
                    },
                ))
                break
    return alerts


def detect_suspicious_ip_activity(entries: List[LogEntry], threshold: int = IP_EVENTS_THRESHOLD) -> List[SecurityAlert]:
    ip_counts: Dict[str, int] = defaultdict(int)
    for entry in entries:
        if entry.ip:
            ip_counts[entry.ip] += 1

    alerts: List[SecurityAlert] = []
    for ip, count in ip_counts.items():
        if count >= threshold:
            severity = "MEDIUM" if count < threshold * 2 else "HIGH"
            alerts.append(SecurityAlert(
                type="suspicious_ip_activity",
                severity=severity,
                ip=ip,
                count=count,
                description="High-volume event activity from a single IP",
                meta={"event_count": count},
            ))
    return alerts


def detect_error_spike(entries: List[LogEntry], threshold: int = ERROR_SPIKE_THRESHOLD,
                       window_minutes: int = ERROR_SPIKE_WINDOW_MINUTES) -> List[SecurityAlert]:
    error_times = [entry.timestamp for entry in entries if entry.level == "ERROR"]
    if len(error_times) < threshold:
        return []

    error_times.sort()
    alerts: List[SecurityAlert] = []
    window = deque()
    window_delta = timedelta(minutes=window_minutes)
    for ts in error_times:
        window.append(ts)
        while window and ts - window[0] > window_delta:
            window.popleft()
        if len(window) >= threshold:
            alerts.append(SecurityAlert(
                type="error_spike",
                severity="MEDIUM",
                ip=None,
                count=len(window),
                description=f"Error spike detected: {len(window)} ERROR logs in {window_minutes} min",
                meta={"window_minutes": window_minutes, "events": len(window)},
            ))
            break
    return alerts


def run_security_detections(entries: List[LogEntry]) -> List[Dict[str, object]]:
    alerts: List[SecurityAlert] = []
    alerts.extend(detect_brute_force(entries))
    alerts.extend(detect_suspicious_ip_activity(entries))
    alerts.extend(detect_error_spike(entries))
    return [a.to_dict() for a in alerts]
