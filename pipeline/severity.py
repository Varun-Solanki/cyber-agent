from datetime import datetime, timedelta
from typing import List

from core.schema import EnrichedThreat, SeverityResult
from utils.scoring import clamp

def score_threat(enriched: EnrichedThreat) -> EnrichedThreat:
    """
    Compute operational severity score (0–10).
    Deterministic and explainable.
    """
    threat = enriched.threat
    category = enriched.category

    score = 0.0
    rationale: list[str] = []

    # CVSS base score
    if threat.cvss_score is not None:
        score += threat.cvss_score
        rationale.append(f"CVSS base score {threat.cvss_score}")
    else:
        score += 3.0
        rationale.append("No CVSS score available (baseline risk assumed)")

    # Exploit availability
    if threat.exploit_available:
        score += 1.5
        rationale.append("Public exploit or PoC available")

    # Category weight
    if category == "RCE":
        score += 1.0
        rationale.append("Remote Code Execution impact")
    elif category == "PRIV_ESC":
        score += 0.8
        rationale.append("Privilege escalation impact")
    elif category == "MALWARE":
        score += 0.9
        rationale.append("Malware / exploit code detected")
    elif category == "SUPPLY_CHAIN":
        score += 1.2
        rationale.append("Supply chain risk")
    elif category == "DOS":
        score += 0.5
        rationale.append("Service availability impact")

    # Source urgency
    if threat.source == "GITHUB":
        score += 0.5
        rationale.append("Active exploit observed in the wild")

    # Freshness
    if threat.published_at:
        age = datetime.utcnow() - threat.published_at
        if age < timedelta(days=7):
            score += 0.5
            rationale.append("Recently published threat")

    score = clamp(score, 0.0, 10.0)

    if score >= 9.0:
        level = "CRITICAL"
    elif score >= 7.0:
        level = "HIGH"
    elif score >= 4.0:
        level = "MEDIUM"
    else:
        level = "LOW"

    enriched.severity = SeverityResult(
        score=round(score, 1),
        level=level,
        rationale=rationale,
    )

    return enriched

def score_all(
    enriched_threats: List[EnrichedThreat],
) -> List[EnrichedThreat]:
    return [score_threat(e) for e in enriched_threats]
