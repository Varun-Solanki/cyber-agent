# pipeline/classify.py

from core.schema import UnifiedThreat, ThreatCategory
from typing import List
from core.schema import EnrichedThreat

def classify_threat(threat: UnifiedThreat) -> ThreatCategory:
    """
    Determine high-level threat category.

    Deterministic, rule-based, explainable.
    """

    text = f"{threat.title} {threat.description}".lower()
    tags = [t.lower() for t in threat.tags]
    cwes = threat.cwe_ids

    # -----------------------------
    # Remote Code Execution
    # -----------------------------
    if (
        "remote code execution" in text
        or "rce" in text
        or any(cwe in {"CWE-78", "CWE-94", "CWE-502"} for cwe in cwes)
    ):
        return "RCE"

    # -----------------------------
    # Privilege Escalation
    # -----------------------------
    if (
        "privilege escalation" in text
        or "priv esc" in text
        or "elevation of privilege" in text
        or "root access" in text
    ):
        return "PRIV_ESC"

    # -----------------------------
    # Information Disclosure
    # -----------------------------
    if (
        "information disclosure" in text
        or "data leak" in text
        or "exposed" in text
        or any(cwe.startswith("CWE-20") or cwe.startswith("CWE-22") for cwe in cwes)
    ):
        return "INFO_DISCLOSURE"

    # -----------------------------
    # Denial of Service
    # -----------------------------
    if (
        "denial of service" in text
        or "dos" in text
        or "service crash" in text
    ):
        return "DOS"

    # -----------------------------
    # Supply Chain
    # -----------------------------
    if (
        "supply chain" in text
        or "dependency confusion" in text
        or "malicious package" in text
    ):
        return "SUPPLY_CHAIN"

    # -----------------------------
    # Malware / Exploit Code
    # -----------------------------
    if threat.source == "GITHUB" and threat.exploit_available:
        return "MALWARE"

    # -----------------------------
    # Misconfiguration
    # -----------------------------
    if (
        "misconfiguration" in text
        or "default credentials" in text
        or "open bucket" in text
    ):
        return "MISCONFIG"

    return "UNKNOWN"


