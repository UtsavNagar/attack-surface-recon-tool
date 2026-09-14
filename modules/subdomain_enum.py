"""
Passive subdomain discovery using crt.sh (certificate transparency logs).
This never touches the target directly - it only queries public CT log data.
"""
import requests


def enumerate_subdomains(domain, limit=10, timeout=15, retries=2):
    subdomains = set()
    error = None
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    for attempt in range(retries):
        try:
            resp = requests.get(url, timeout=timeout, headers={"User-Agent": "ASM-Recon-Tool"})
            if resp.status_code == 200 and resp.text.strip():
                data = resp.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for sub in name_value.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(domain) and "*" not in sub:
                            subdomains.add(sub)
                error = None
                break
            else:
                error = f"crt.sh returned status {resp.status_code}"
        except Exception as e:
            error = str(e)
            continue  # retry

    subdomains.add(domain)
    ordered = sorted(subdomains, key=lambda s: (s != domain, s))
    return {"subdomains": ordered[:limit], "total_found": len(subdomains), "error": error}
