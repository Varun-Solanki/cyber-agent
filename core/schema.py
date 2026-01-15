from dataclasses import dataclass, field
from typing import List, Optional, Literal
from datetime import datetime


# -----------------------------
# Source of the intelligence
# -----------------------------
ThreatSource = Literal[
    "NVD",      # Official CVE data
    "RSS",      # Security news / advisories
    "GITHUB"    # Public exploits / PoCs
]


# -----------------------------
# High-level threat class
# -----------------------------
ThreatCategory = Literal[
    "RCE",
    "PRIV_ESC",
    "INFO_DISCLOSURE",
    "DOS",
    "SUPPLY_CHAIN",
    "MALWARE",
    "MISCONFIG",
    "UNKNOWN"
]


# -----------------------------
# Core normalized threat object
# -----------------------------
@dataclass
class UnifiedThreat:
    """
    Canonical representation of a security threat.

    Every downstream phase (classification, scoring, decision, reporting)
    operates ONLY on this object.
    """

    # Identity & provenance
    id: str                         # CVE-ID, RSS hash, or repo full_name
    source: ThreatSource

    # Human-readable context
    title: str
    description: str

    # Time signals (may be missing for some sources)
    published_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    # Affected surface
    affected_products: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)

    # Vulnerability metadata
    cvss_score: Optional[float] = None
    cwe_ids: List[str] = field(default_factory=list)

    # Exploit intelligence (inferred, not blindly copied)
    exploit_available: bool = False
    poc_links: List[str] = field(default_factory=list)

    # References & enrichment
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    # Raw traceability (important for audits & debugging)
    raw_source: Optional[dict] = None


# -----------------------------
# Severity output model
# -----------------------------
@dataclass
class SeverityResult:
    """
    Operational severity, NOT a CVSS replacement.

    This represents how dangerous the threat is in practice,
    given exploitability and context.
    """

    score: float                     # 0.0 – 10.0
    level: Literal[
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ]
    rationale: List[str]             # Human-readable reasons


# -----------------------------
# Classified + scored threat
# -----------------------------
@dataclass
class EnrichedThreat:
    """
    Output of Phase 2.

    This is the handoff object into Phase 3 (decisioning).
    """

    threat: UnifiedThreat
    category: ThreatCategory
    severity: SeverityResult
