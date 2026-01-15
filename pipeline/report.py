from pathlib import Path
from datetime import datetime
from typing import List

from core.schema import EnrichedThreat


def generate_report(
    threats: List[EnrichedThreat],
) -> str:
    """
    Generate a human-readable Markdown threat intelligence report.
    Input threats must already be prioritized.
    """

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = []

    # -----------------------------
    # Header
    # -----------------------------
    lines.append("# Autonomous Threat Intelligence Report")
    lines.append(f"Generated: {now}")
    lines.append("")

    # -----------------------------
    # Agent Execution Summary
    # -----------------------------
    lines.extend([
        "## Agent Execution Summary",
        "",
        "- **Recon Agent**",
        "  - Queried sources: NVD CVE Feed, Security RSS Feeds, GitHub PoC Search",
        "",
        "- **Classification Agent**",
        "  - Applied deterministic rule-based threat classification",
        "",
        "- **Severity Agent**",
        "  - Computed operational severity scores (0.0–10.0)",
        "",
        "- **Decision Agent**",
        "  - Correlated multi-source intelligence",
        "  - Deduplicated overlapping threats",
        "  - Applied decision and prioritization rules",
        "",
    ])

    # -----------------------------
    # Decision Summary
    # -----------------------------
    decisions = {"ESCALATE": [], "TRACK": [], "IGNORE": []}

    for t in threats:
        for tag in t.threat.tags:
            if tag.startswith("decision:"):
                decision = tag.split(":", 1)[1]
                decisions[decision].append(t)
                break

    lines.extend([
        "## Decision Summary",
        "",
        f"- **ESCALATE:** {len(decisions['ESCALATE'])} threats",
        f"- **TRACK:** {len(decisions['TRACK'])} threats",
        f"- **IGNORE:** {len(decisions['IGNORE'])} threats",
        "",
    ])

    # -----------------------------
    # ESCALATE
    # -----------------------------
    lines.append("## ESCALATE")
    lines.append("")

    if not decisions["ESCALATE"]:
        lines.append("_No threats required immediate escalation._")
        lines.append("")
    else:
        for et in decisions["ESCALATE"]:
            lines.extend(_format_threat_detail(et))

    # -----------------------------
    # TRACK
    # -----------------------------
    lines.append("## TRACK")
    lines.append("")

    if not decisions["TRACK"]:
        lines.append("_No threats required active tracking._")
        lines.append("")
    else:
        for et in decisions["TRACK"]:
            lines.extend(_format_threat_detail(et))

    # -----------------------------
    # IGNORE (Collapsed)
    # -----------------------------
    lines.append("## IGNORE (Suppressed)")
    lines.append("")
    lines.append(
        f"{len(decisions['IGNORE'])} low-confidence or low-impact threats were suppressed."
    )
    lines.append("")

    for et in decisions["IGNORE"]:
        lines.append(
            f"- {et.threat.id} (Score {et.severity.score})"
        )

    lines.append("")

    # -----------------------------
    # Methodology
    # -----------------------------
    lines.extend([
        "## Methodology & Explainability",
        "",
        "- All threat classification, scoring, and decisions are deterministic",
        "- No LLMs were used in scoring or decision-making",
        "- Severity scores include recorded rationale",
        "- Results are fully reproducible by re-running the pipeline",
        "",
    ])

    return "\n".join(lines)

def _format_threat_detail(et: EnrichedThreat) -> list[str]:
    """
    Format a single threat into detailed Markdown lines.
    """
    threat = et.threat
    severity = et.severity

    lines = [
        f"### {threat.id}",
        f"- **Category:** {et.category}",
        f"- **Severity:** {severity.score} ({severity.level})",
        f"- **Decision:** {next(t for t in threat.tags if t.startswith('decision:'))}",
        "- **Rationale:**",
    ]

    for reason in severity.rationale:
        lines.append(f"  - {reason}")

    if threat.references:
        lines.append("- **References:**")
        for ref in threat.references:
            lines.append(f"  - {ref}")

    lines.append("")
    return lines

from pathlib import Path
from datetime import datetime


REPORTS_DIR = Path("reports")
ARCHIVE_DIR = REPORTS_DIR / "archive"
LATEST_REPORT = REPORTS_DIR / "latest.md"


def write_report(markdown: str) -> None:
    """
    Write the latest report and archive the previous one if present.
    """

    REPORTS_DIR.mkdir(exist_ok=True)
    ARCHIVE_DIR.mkdir(exist_ok=True)

    # Archive existing latest report
    if LATEST_REPORT.exists():
        timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H-%M")
        archive_path = ARCHIVE_DIR / f"{timestamp}.md"
        LATEST_REPORT.replace(archive_path)

    # Write new latest report
    LATEST_REPORT.write_text(markdown, encoding="utf-8")
