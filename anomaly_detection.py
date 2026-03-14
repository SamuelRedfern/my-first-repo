from typing import Dict, List


def detect_anomalies(summary: Dict[str, object]) -> List[Dict[str, object]]:
    """
    Detect anomalous IP behavior using Isolation Forest.

    Features used:
    - Total events per IP
    - Error events per IP
    - Unique message count per IP
    """

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

    # No IP data available
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

    # IsolationForest requires enough samples
    if len(features) < 3:
        return []

    model = IsolationForest(
        contamination=0.1,
        random_state=42
    )

    model.fit(features)

    predictions = model.predict(features)
    scores = model.decision_function(features)

    anomalies = []

    for ip, prediction, score in zip(ips, predictions, scores):

        if prediction == -1:

            severity = "HIGH" if score < -0.1 else "MEDIUM"

            anomalies.append({
                "type": "anomaly_ip_behavior",
                "severity": severity,
                "ip": ip,
                "count": int(ip_counts.get(ip, 0)),
                "description": "Unusual IP behavior detected using Isolation Forest",
                "meta": {
                    "score": float(score),
                    "event_count": int(ip_counts.get(ip, 0)),
                    "error_count": int(ip_error_counts.get(ip, 0)),
                    "unique_message_count": int(ip_unique_message_counts.get(ip, 0)),
                },
            })

    return anomalies