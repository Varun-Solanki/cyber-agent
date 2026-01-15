from tools import tool_registry
from pipeline.recon import normalize_all
from pipeline.classify import classify_threat
from pipeline.severity import score_threat
from core.schema import SeverityResult
from pipeline.report import generate_report, write_report

from pipeline.decision import (
    correlate_threats,
    deduplicate,
    adjust_severity,
    assign_decision,
    prioritize,
)
from core.schema import EnrichedThreat
from core.logger import logger


def run_recon():
    return {
        "cves": tool_registry.run(
            "fetch_recent_cves", results_per_page=5, days_back=3
        ),
        "rss": tool_registry.run(
            "fetch_security_rss", limit=3
        ),
        "github": tool_registry.run(
            "search_github_pocs", limit=3
        ),
    }


if __name__ == "__main__":
    # -----------------------------
    # Phase 1: Recon
    # -----------------------------
    data = run_recon()
    logger.info("Recon completed")

    # -----------------------------
    # Phase 2: Normalize
    # -----------------------------
    threats = normalize_all(
        cves=data["cves"],
        rss_entries=data["rss"],
        github_repos=data["github"],
    )
    logger.info(f"Normalized {len(threats)} threats")

    # -----------------------------
    # Phase 2: Classify
    # -----------------------------
    enriched: list[EnrichedThreat] = []

    for threat in threats:
        category = classify_threat(threat)
        enriched.append(
            EnrichedThreat(
                threat=threat,
                category=category,
                severity=SeverityResult(
                    score=0.0, 
                    level="LOW",
                    rationale=["Initial placeholder severity"])
            )
        )

    # -----------------------------
    # Phase 2: Severity
    # -----------------------------
    enriched = [score_threat(e) for e in enriched]

    # -----------------------------
    # Phase 3: Correlation
    # -----------------------------
    correlated = correlate_threats(enriched)

    # -----------------------------
    # Phase 3: Deduplication
    # -----------------------------
    deduped = deduplicate(correlated)

    # -----------------------------
    # Phase 3: Severity Adjustment
    # -----------------------------
    for e in deduped:
        adjust_severity(e)

    # -----------------------------
    # Phase 3: Decision Assignment
    # -----------------------------
    for e in deduped:
        assign_decision(e)

    # -----------------------------
    # Phase 3: Prioritization
    # -----------------------------
    final_threats = prioritize(deduped)

    # -----------------------------
    # Phase 4: Normalize Output (Deduplicate Rationale)
    # -----------------------------
    for et in final_threats:
        et.severity.rationale = list(dict.fromkeys(et.severity.rationale))


    # -----------------------------
    # Phase 4: Reporting
    # -----------------------------
    report_md = generate_report(final_threats)
    write_report(report_md)

    # -----------------------------
    # CLI Summary
    # -----------------------------
    counts = {"ESCALATE": 0, "TRACK": 0, "IGNORE": 0}

    for et in final_threats:
        for tag in et.threat.tags:
            if tag.startswith("decision:"):
                counts[tag.split(":", 1)[1]] += 1
                break

    print("\n=== PIPELINE EXECUTION SUMMARY ===\n")
    print(f"ESCALATE: {counts['ESCALATE']}")
    print(f"TRACK:    {counts['TRACK']}")
    print(f"IGNORE:   {counts['IGNORE']}")
    print("\nReport written to reports/latest.md\n")

