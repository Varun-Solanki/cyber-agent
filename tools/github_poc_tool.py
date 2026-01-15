import requests

GITHUB_SEARCH = "https://api.github.com/search/repositories"

def search_pocs(query: str = "CVE exploit", limit: int = 5):
    params = {
        "q": query,
        "sort": "updated",
        "order": "desc",
        "per_page": limit
    }

    resp = requests.get(GITHUB_SEARCH, params=params, timeout=15)
    resp.raise_for_status()

    items = resp.json().get("items", [])

    return [
        {
            "name": repo["full_name"],
            "url": repo["html_url"],
            "description": repo["description"]
        }
        for repo in items
    ]
