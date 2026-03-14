from typing import Dict, List


def detect_anomalies(summary: Dict[str, object]) -> List[Dict[str, object]]:
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError:
        return [
            {
                "type": "anomaly_detection_unavailable",
                "severity": "LOW",
                "ip": None,
                "count": 0,
                "description": "scikit-learn not installed; anomaly detection unavailable",
                "meta": {},
            }
        ]

    ip_counts = summary.get("ip_counts", {})
    ip_error_counts = summary.get("ip_error_counts", {})
    ip_unique_message_counts = summary.get("ip_unique_message_counts", {})

    if not ip_counts:
        return []

    features = []
    ips = []
    for ip, count in ip_counts.items():
        ips.append(ip)
        features.append([
            float(count),
            float(ip_error_counts.get(ip, 0)),
            float(ip_unique_message_counts.get(ip, 0)),
        ])

    if len(features) < 3:
        return []

    clf = IsolationForest(contamination=0.1, random_state=42)
    clf.fit(features)
    preds = clf.predict(features)
    scores = clf.decision_function(features)

    anomalies = []
    for ip, pred, score in zip(ips, preds, scores):
        if pred == -1:
            sev = "HIGH" if score < -0.1 else "MEDIUM"
            anomalies.append({
                "type": "anomaly_ip_behavior",
                "severity": sev,
                "ip": ip,
                "count": int(ip_counts.get(ip, 0)),
                "description": "Unusual IP behavior detected by IsolationForest",
                "meta": {
                    "score": float(score),
                    "event_count": int(ip_counts.get(ip, 0)),
                    "error_count": int(ip_error_counts.get(ip, 0)),
                    "unique_message_count": int(ip_unique_message_counts.get(ip, 0)),
                },
            })
    return anomalies
