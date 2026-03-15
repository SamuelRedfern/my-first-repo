import unittest

from detections import detect_brute_force, detect_error_spike, detect_suspicious_ip_activity
from log_analyzer import analyze_logs, parse_log_line
from mitre_attack import enrich_alerts_with_mitre_attack


class LogAnalyzerTests(unittest.TestCase):
    def test_parse_log_line_extracts_ip_and_level(self) -> None:
        entry = parse_log_line("2026-03-14T10:02:00 [ERROR] Could not connect to database from 10.0.0.5")

        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry.level, "ERROR")
        self.assertEqual(entry.ip, "10.0.0.5")

    def test_analyze_logs_separates_summary_from_parsed_entries(self) -> None:
        result = analyze_logs(
            [
                "2026-03-14T10:00:00 [INFO] Server started 192.168.1.10",
                "2026-03-14T10:01:00 [ERROR] Request failed 192.168.1.10",
            ]
        )

        self.assertEqual(result.summary["total"], 2)
        self.assertNotIn("parsed_entries", result.summary)
        self.assertEqual(len(result.parsed_entries), 2)


class DetectionTests(unittest.TestCase):
    def test_detect_brute_force_uses_peak_window_metadata(self) -> None:
        entries = [
            parse_log_line(f"2026-03-14T09:00:{second:02d} [WARNING] 203.0.113.77 Failed login attempt")
            for second in range(5)
        ]

        alerts = detect_brute_force([entry for entry in entries if entry is not None])

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].count, 5)
        self.assertEqual(alerts[0].meta["first_seen"], "2026-03-14T09:00:00")
        self.assertEqual(alerts[0].meta["last_seen"], "2026-03-14T09:00:04")

    def test_detect_suspicious_ip_activity_uses_time_window(self) -> None:
        entries = [
            parse_log_line(f"2026-03-14T10:00:{second:02d} [INFO] Request completed 198.51.100.8")
            for second in range(4)
        ]
        entries.extend(
            [
                parse_log_line(f"2026-03-14T10:20:{second:02d} [INFO] Request completed 198.51.100.8")
                for second in range(4)
            ]
        )

        alerts = detect_suspicious_ip_activity(
            [entry for entry in entries if entry is not None],
            threshold=5,
            window_minutes=1,
        )

        self.assertEqual(alerts, [])

    def test_detect_error_spike_reports_ip_breakdown(self) -> None:
        entries = [
            parse_log_line(f"2026-03-14T11:00:0{second} [ERROR] Auth failure 10.0.0.5")
            for second in range(3)
        ]
        entries.extend(
            [
                parse_log_line(f"2026-03-14T11:00:1{second} [ERROR] Auth failure 10.0.0.6")
                for second in range(2)
            ]
        )

        alerts = detect_error_spike(
            [entry for entry in entries if entry is not None],
            threshold=5,
            window_minutes=1,
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].meta["ip_breakdown"]["10.0.0.5"], 3)
        self.assertEqual(alerts[0].meta["ip_breakdown"]["10.0.0.6"], 2)

    def test_mitre_attack_mapping_enriches_brute_force_alerts(self) -> None:
        alerts = enrich_alerts_with_mitre_attack(
            [
                {
                    "type": "brute_force",
                    "severity": "HIGH",
                    "ip": "203.0.113.77",
                    "count": 25,
                    "description": "Likely brute force login attack",
                    "meta": {},
                }
            ]
        )

        self.assertEqual(alerts[0]["mitre_attack"][0]["technique_id"], "T1110")
        self.assertEqual(alerts[0]["mitre_attack"][0]["tactic_id"], "TA0006")

    def test_mitre_attack_mapping_leaves_other_alerts_unmapped(self) -> None:
        alerts = enrich_alerts_with_mitre_attack(
            [
                {
                    "type": "anomaly_ip_behavior",
                    "severity": "HIGH",
                    "ip": "203.0.113.77",
                    "count": 18,
                    "description": "Unusual IP behavior detected using Isolation Forest",
                    "meta": {},
                }
            ]
        )

        self.assertEqual(alerts[0]["mitre_attack"], [])


if __name__ == "__main__":
    unittest.main()
