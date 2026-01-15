# pipeline/recon.py

from datetime import datetime
from typing import List
import hashlib

from core.schema import UnifiedThreat
from utils.parsers import (
    extract_products_from_cve,
    extract_versions_from_cve,
    extract_cwe_ids,
    extract_keywords,
)
from core.logger import logger


# -----------------------------
# NVD CVE Normalization
# -----------------------------
def normalize_nvd_cve(cve: dict) -> UnifiedThreat:
    cve_id = cve.get("id") or "UNKNOWN-CVE"

    descriptions = cve.get("descriptions", [])
    description = descriptions[0]["value"] if descriptions else ""

    metrics = cve.get("metrics", {})
    cvss_score = None

    try:
        cvss_score = (
            metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        )
    except Exception:
        pass  # CVSS is optional, never crash

    references = [r["url"] for r in cve.get("references", [])]

    threat = UnifiedThreat(
        id=cve_id,
        source="NVD",
        title=cve_id,
        description=description,
        published_at=parse_time(cve.get("published")),
        updated_at=parse_time(cve.get("lastModified")),
        affected_products=extract_products_from_cve(cve),
        affected_versions=extract_versions_from_cve(cve),
        cvss_score=cvss_score,
        cwe_ids=extract_cwe_ids(cve),
        exploit_available=False,  # inferred later
        references=references,
        tags=extract_keywords(description),
        raw_source=cve,
    )

    return threat


# -----------------------------
# RSS Normalization
# -----------------------------
def normalize_rss_entry(entry: dict) -> UnifiedThreat:
    title = entry.get("title", "")
    summary = entry.get("summary", "")

    content = f"{title} {summary}".lower()
    exploit_keywords = ["exploit", "poc", "weaponized"]

    exploit_available = any(k in content for k in exploit_keywords)

    threat_id = f"RSS-{stable_hash(title)}"

    threat = UnifiedThreat(
        id=threat_id,
        source="RSS",
        title=title,
        description=summary,
        published_at=parse_time(entry.get("published")),
        affected_products=[],
        exploit_available=exploit_available,
        references=[str(entry["link"])] if entry.get("link") else [],
        tags=extract_keywords(content),
        raw_source=entry,
    )

    return threat


# -----------------------------
# GitHub PoC Normalization
# -----------------------------
def normalize_github_repo(repo: dict) -> UnifiedThreat:
    full_name = repo.get("full_name") or "unknown/repo"
    description = repo.get("description", "")

    threat = UnifiedThreat(
        id=full_name,
        source="GITHUB",
        title=full_name,
        description=description,
        published_at=parse_time(repo.get("created_at")),
        updated_at=parse_time(repo.get("updated_at")),
        affected_products=[],
        exploit_available=True,  # GitHub PoC implies exploit
        poc_links=[str(repo["html_url"])] if repo.get("html_url") else [],
        references=[str(repo["html_url"])] if repo.get("html_url") else [],
        tags=extract_keywords(description),
        raw_source=repo,
    )

    return threat


# -----------------------------
# Aggregation Entry Point
# -----------------------------
def normalize_all(
    cves: List[dict],
    rss_entries: List[dict],
    github_repos: List[dict],
) -> List[UnifiedThreat]:

    threats: List[UnifiedThreat] = []

    for cve in cves:
        try:
            threats.append(normalize_nvd_cve(cve))
        except Exception as e:
            logger.error(f"Failed to normalize CVE: {e}")

    for entry in rss_entries:
        try:
            threats.append(normalize_rss_entry(entry))
        except Exception as e:
            logger.error(f"Failed to normalize RSS entry: {e}")

    for repo in github_repos:
        try:
            threats.append(normalize_github_repo(repo))
        except Exception as e:
            logger.error(f"Failed to normalize GitHub repo: {e}")

    return threats


# -----------------------------
# Helpers
# -----------------------------
def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", ""))
    except Exception:
        return None

def stable_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
