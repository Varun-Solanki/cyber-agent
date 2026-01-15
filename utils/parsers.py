# utils/parsers.py

import re
from typing import List


# -----------------------------
# Keyword extraction (generic)
# -----------------------------
def extract_keywords(text: str, max_keywords: int = 10) -> List[str]:
    if not text:
        return []

    text = text.lower()
    words = re.findall(r"[a-z0-9_\\-]{4,}", text)

    stopwords = {
        "this", "that", "with", "from", "there", "their",
        "which", "about", "could", "would", "should",
        "vulnerability", "vulnerabilities", "allows",
    }

    keywords = [w for w in words if w not in stopwords]

    seen = set()
    unique = []
    for w in keywords:
        if w not in seen:
            seen.add(w)
            unique.append(w)

    return unique[:max_keywords]


# -----------------------------
# CVE-specific helpers
# -----------------------------
def extract_products_from_cve(cve: dict) -> List[str]:
    """
    Extract product names from NVD CPEs.
    Lossy by design, but consistent.
    """
    products = set()

    configurations = cve.get("configurations", {}).get("nodes", [])
    for node in configurations:
        for cpe in node.get("cpeMatch", []):
            uri = cpe.get("criteria")
            if uri:
                parts = uri.split(":")
                if len(parts) > 4:
                    products.add(parts[4])

    return list(products)


def extract_versions_from_cve(cve: dict) -> List[str]:
    versions = set()

    configurations = cve.get("configurations", {}).get("nodes", [])
    for node in configurations:
        for cpe in node.get("cpeMatch", []):
            if "versionStartIncluding" in cpe:
                versions.add(cpe["versionStartIncluding"])
            if "versionEndExcluding" in cpe:
                versions.add(cpe["versionEndExcluding"])

    return list(versions)


def extract_cwe_ids(cve: dict) -> List[str]:
    cwes = set()

    weaknesses = cve.get("weaknesses", [])
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            value = desc.get("value")
            if value and value.startswith("CWE-"):
                cwes.add(value)

    return list(cwes)
