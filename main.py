import argparse
import json
from pathlib import Path
from typing import Dict, List

from log_analyzer import analyze_file, format_summary, load_file, parse_log_line
from anomaly_detection import detect_anomalies
from detections import run_security_detections

VERSION = "1.0.0"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Python Log Analyzer (SOC style)",
        epilog="Example: python main.py server.log --json --alerts-only"
    )

    parser.add_argument(
        "logfile",
        type=Path,
        help="Path to the log file to analyze"
    )

    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Optional output file path"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON summary instead of formatted text"
    )

    parser.add_argument(
        "--alerts-only",
        action="store_true",
        help="Show only security alerts"
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"log-analyzer {VERSION}"
    )

    return parser.parse_args()


def format_alerts(alerts: List[Dict[str, object]]) -> str:
    if not alerts:
        return "Security Alerts:\n  - None"
    lines = ["Security Alerts:"]
    for alert in alerts:
        ip_display = f" from {alert['ip']}" if alert.get("ip") else ""
        lines.append(f"- [{alert['severity']}] {alert['description']}{ip_display}")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()

    log_path: Path = args.logfile
    if not log_path.exists():
        print(f"Error: log file not found: {log_path}")
        return 1

    summary = analyze_file(log_path)
    entries = []
    for line in load_file(log_path):
        entry = parse_log_line(line)
        if entry is not None:
            entries.append(entry)

    security_alerts = run_security_detections(entries)
    anomaly_alerts = detect_anomalies(summary)
    combined_alerts = security_alerts + anomaly_alerts

    if args.alerts_only:
        if args.json:
            output_text = json.dumps({"alerts": combined_alerts}, indent=2, default=str)
        else:
            output_text = format_alerts(combined_alerts)
    else:
        if args.json:
            output_text = json.dumps(
                {
                    "summary": summary,
                    "alerts": combined_alerts,
                },
                indent=2,
                default=str,
            )
        else:
            output_text = format_summary(summary) + "\n\n" + format_alerts(combined_alerts)

    if args.output:
        args.output.write_text(output_text, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(output_text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())