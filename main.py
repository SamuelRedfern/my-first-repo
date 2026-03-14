import argparse
from pathlib import Path

from log_analyzer import analyze_file, format_summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Python Log Analyzer")
    parser.add_argument("logfile", type=Path, help="Path to log file")
    parser.add_argument("--output", "-o", type=Path, default=None, help="Optional output file path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    log_path: Path = args.logfile
    if not log_path.exists():
        print(f"Error: log file not found: {log_path}")
        return 1
    summary = analyze_file(log_path)
    report = format_summary(summary)
    if args.output:
        args.output.write_text(report, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
