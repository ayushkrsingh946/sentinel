import requests

def preview_link(user_url):
    # SSRF vulnerability
    resp = requests.get(user_url, timeout=5)
    return resp.text[:200]
