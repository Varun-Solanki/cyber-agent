import feedparser

DEFAULT_FEEDS = [
    "https://www.bleepingcomputer.com/feed/",
    "https://www.securityweek.com/feed/"
]

def fetch_rss_items(limit: int = 5):
    results = []

    for url in DEFAULT_FEEDS:
        feed = feedparser.parse(url)
        for entry in feed.entries[:limit]:
            results.append({
                "title": entry.title,
                "link": entry.link,
                "published": entry.get("published", "")
            })

    return results
