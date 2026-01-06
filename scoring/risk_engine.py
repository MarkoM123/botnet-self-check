# scoring/risk_engine.py

SEVERITY_WEIGHTS = {
    "low": 5,
    "medium": 15,
    "high": 30
}

CATEGORY_MULTIPLIER = {
    "process": 1.0,
    "network": 1.4,
    "dns": 1.5,
    "persistence": 1.6,
    "system": 1.2
}

CORRELATION_RULES = [
    {
        "requires": ["persistence", "network"],
        "bonus": 20,
        "reason": "Persistence combined with outbound network activity"
    },
    {
        "requires": ["dns", "network"],
        "bonus": 15,
        "reason": "Suspicious DNS behavior combined with network beaconing"
    },
    {
        "requires": ["process", "network"],
        "bonus": 10,
        "reason": "Suspicious process communicating over network"
    }
]


def risk_level(score: int) -> str:
    if score < 20:
        return "LOW"
    elif score < 50:
        return "MEDIUM"
    else:
        return "HIGH"


def calculate_risk(findings: list) -> dict:
    """
    findings = [
        {
            "category": "network",
            "severity": "high",
            "description": "Repeated outbound connections to rare IP",
            "confidence": 0.9
        }
    ]
    """

    total_score = 0
    categories_present = set()
    reasons = []

    for f in findings:
        severity_weight = SEVERITY_WEIGHTS.get(f["severity"], 0)
        category_factor = CATEGORY_MULTIPLIER.get(f["category"], 1.0)
        confidence = f.get("confidence", 1.0)

        score = severity_weight * category_factor * confidence
        total_score += score

        categories_present.add(f["category"])
        reasons.append(f["description"])

    for rule in CORRELATION_RULES:
        if all(cat in categories_present for cat in rule["requires"]):
            total_score += rule["bonus"]
            reasons.append(rule["reason"])

    total_score = min(int(total_score), 100)

    return {
        "risk_score": total_score,
        "risk_level": risk_level(total_score),
        "reasons": list(set(reasons))
    }
