from tools.registry import ToolRegistry
from tools.cve_tool import fetch_recent_cves
from tools.rss_tool import fetch_rss_items
from tools.github_poc_tool import search_pocs  # name aligned

tool_registry = ToolRegistry()

tool_registry.register(
    name="fetch_recent_cves",
    description="Fetch recent CVEs from NVD",
    func=fetch_recent_cves
)

tool_registry.register(
    name="fetch_security_rss",
    description="Fetch recent security news from RSS feeds",
    func=fetch_rss_items
)

tool_registry.register(
    name="search_github_pocs",
    description="Search GitHub for CVE proof-of-concepts",
    func=search_pocs
)
