import requests

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
    "Permissions-Policy",
]


def check_headers(hostname, timeout=6):
    result = {
        "scheme": None, "status_code": None, "server": None,
        "headers_present": [], "headers_missing": [], "error": None,
    }
    last_error = None
    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{hostname}",
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": "ASM-Recon-Tool"},
            )
            result["scheme"] = scheme
            result["status_code"] = resp.status_code
            result["server"] = resp.headers.get("Server")
            result["error"] = None  # clear any earlier scheme's failure
            for h in SECURITY_HEADERS:
                if h in resp.headers:
                    result["headers_present"].append(h)
                else:
                    result["headers_missing"].append(h)
            return result
        except Exception as e:
            last_error = str(e)
            continue
    result["error"] = last_error
    return result
