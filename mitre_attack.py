from copy import deepcopy
from typing import Dict, List

MITRE_MAPPINGS: Dict[str, List[Dict[str, str]]] = {
    "brute_force": [
        {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "Brute Force",
            "technique_id": "T1110",
            "confidence": "high",
            "mapping_note": "Repeated failed login attempts align with ATT&CK Brute Force.",
        }
    ]
}


def enrich_alerts_with_mitre_attack(alerts: List[Dict[str, object]]) -> List[Dict[str, object]]:
    enriched_alerts: List[Dict[str, object]] = []

    for alert in alerts:
        enriched = dict(alert)
        mappings = MITRE_MAPPINGS.get(str(alert.get("type")), [])
        enriched["mitre_attack"] = deepcopy(mappings)
        enriched_alerts.append(enriched)

    return enriched_alerts
