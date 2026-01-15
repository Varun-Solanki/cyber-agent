from collections import defaultdict
# from logging import CRITICAL
from typing import Dict, List, Literal

from core.schema import EnrichedThreat
from datetime import datetime

SOURCE_PRIORITY = {
    "NVD": 3,
    "GITHUB": 2,
    "RSS": 1,
}

DECISION_PRIORITY = {
    "ESCALATE": 3,
    "TRACK": 2,
    "IGNORE": 1,
}




def correlate_threats(
    threats: List[EnrichedThreat],
) -> Dict[str, List[EnrichedThreat]]:
    """
    Deterministically group enriched threats that refer to
    the same real-world security issue.
    """
    buckets: Dict[str, List[EnrichedThreat]] = defaultdict(list)

    for enriched in threats:
        key = _correlation_key(enriched)
        buckets[key].append(enriched)

    return dict(buckets)


def _correlation_key(enriched: EnrichedThreat) -> str:
    threat = enriched.threat

    # 1. CVE-based correlation (authoritative)
    if threat.source == "NVD":
        return f"cve:{threat.id}"

    # 2. Shared public PoC link
    if threat.poc_links:
        # Deterministic: always take the first sorted link
        poc = sorted(threat.poc_links)[0]
        return f"poc:{poc}"

    # 3. Affected product surface (best-effort)
    if threat.affected_products:
        product = sorted(threat.affected_products)[0]
        return f"product:{product}"

    # 4. Absolute fallback
    return f"id:{threat.id}"

SOURCE_PRIORITY = {
    "NVD": 3,
    "GITHUB": 2,
    "RSS": 1,
}


def select_primary(
    group: List[EnrichedThreat],
) -> EnrichedThreat:
    """
    Select the single authoritative representative
    for a correlated threat group.
    """

    def sort_key(enriched: EnrichedThreat):
        threat = enriched.threat
        severity_score = enriched.severity.score

        published = threat.published_at or datetime.max

        return (
            -severity_score,                          # higher severity first
            -int(threat.exploit_available),           # exploit beats no exploit
            -SOURCE_PRIORITY[threat.source],          # NVD > GITHUB > RSS
            published,                                # earlier first
            threat.id,                                # stable tie-breaker
        )

    return sorted(group, key=sort_key)[0]

def attach_supporting_evidence(
    primary: EnrichedThreat,
    group: List[EnrichedThreat],
) -> None:
    """
    Attach non-primary correlated threats as references
    for auditability and traceability.
    """
    for enriched in group:
        if enriched is primary:
            continue

        src = enriched.threat.source
        ref_id = enriched.threat.id

        primary.threat.references.append(
            f"correlated:{src}:{ref_id}"
        )
        primary.threat.references = sorted(set(primary.threat.references)) #deduplicating i.e removing any possible duplicates


def deduplicate(
    correlated: Dict[str, List[EnrichedThreat]],
) -> List[EnrichedThreat]:
    deduped: List[EnrichedThreat] = []

    for group in correlated.values():
        primary = select_primary(group)
        attach_supporting_evidence(primary, group)
        deduped.append(primary)

    return deduped

def _clamp(value: float) -> float:
    return max(0.0, min(10.0, value))

def _severity_level(
    score: float,
) -> Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"




def adjust_severity(enriched: EnrichedThreat) -> None:
    """
    Adjust severity based on cross-source corroboration.
    Mutates severity in-place, deterministically.
    """
    delta = 0.0
    reasons = []

    threat = enriched.threat
    severity = enriched.severity

    # Exploit availability boost
    if threat.exploit_available:
        delta += 1.5
        reasons.append("Public exploit available")

    # Correlation boost (supporting evidence)
    correlated_count = sum(
        1 for ref in threat.references if ref.startswith("correlated:")
    )

    if correlated_count >= 2:
        delta += 2.0
        reasons.append("Multiple corroborating sources")
    elif correlated_count == 1:
        delta += 1.0
        reasons.append("Single corroborating source")

    # RSS-only dampening
    if (
        threat.source == "RSS"
        and not threat.exploit_available
        and enriched.severity.score < 5.0
    ):
        delta -= 1.0
        reasons.append("Low-confidence RSS-only signal")

    # Apply and clamp
    old_score = severity.score
    new_score = _clamp(old_score + delta)

    severity.score = new_score
    severity.level = _severity_level(new_score)
    severity.rationale.extend(reasons)


def assign_decision(enriched: EnrichedThreat) -> None:
    """
    Assign an operational decision label to a threat.
    Decision is attached via threat tags.
    """
    severity = enriched.severity
    threat = enriched.threat

    decision: str

    # Hard override
    if severity.level == "CRITICAL":
        decision = "ESCALATE"

    elif threat.exploit_available and severity.score >= 7.0:
        decision = "ESCALATE"

    # Standard rules
    elif severity.score >= 8.0:
        decision = "ESCALATE"
    elif severity.score >= 5.0:
        decision = "TRACK"
    else:
        decision = "IGNORE"

    # Attach decision deterministically
    threat.tags.append(f"decision:{decision}")


def _get_decision(enriched: EnrichedThreat) -> str:
    for tag in enriched.threat.tags:
        if tag.startswith("decision:"):
            return tag.split(":", 1)[1]
    return "IGNORE"  # absolute fallback

def prioritize(
    threats: List[EnrichedThreat],
) -> List[EnrichedThreat]:
    """
    Deterministically order threats by operational priority.
    """

    def sort_key(enriched: EnrichedThreat):
        threat = enriched.threat
        severity = enriched.severity

        decision = _get_decision(enriched)
        decision_rank = DECISION_PRIORITY[decision]

        published = threat.published_at or datetime(1970, 1, 1)


        return (
            -decision_rank,                 # ESCALATE > TRACK > IGNORE
            -severity.score,                # higher severity first
            -int(threat.exploit_available), # exploit beats no exploit
            published,         # newer first
            threat.id,                      # stable tie-breaker
        )

    return sorted(threats, key=sort_key)

