# tools/cve_tool.py

import requests
from datetime import datetime, timedelta, timezone

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_recent_cves(
    results_per_page: int = 10,
    days_back: int = 7
):
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days_back)

    params = {
        "resultsPerPage": results_per_page,
        "pubStartDate": start.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "pubEndDate": end.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    }

    resp = requests.get(NVD_API, params=params, timeout=15)
    resp.raise_for_status()

    data = resp.json()

    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        cves.append({
            "id": cve["id"],
            "description": cve["descriptions"][0]["value"],
            "published": cve["published"]
        })

    return cves
