import requests
import base64
import os
from dotenv import load_dotenv

load_dotenv()

VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")


def check_url(url):
    if not VT_KEY:
        return {"error": "VirusTotal API key not configured"}
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": VT_KEY}
        r = requests.get(endpoint, headers=headers, timeout=10)
        if r.status_code == 404:
            submit = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=10,
            )
            return {"status": "submitted", "malicious": 0, "suspicious": 0}
        if r.status_code != 200:
            return {"error": f"VT returned {r.status_code}"}
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
        }
    except Exception as e:
        return {"error": str(e)}


def check_urls_batch(links, max_checks=5):
    results = {}
    checked = 0
    for link in links:
        if checked >= max_checks:
            break
        url = link["url"]
        results[url] = check_url(url)
        checked += 1
    return results
