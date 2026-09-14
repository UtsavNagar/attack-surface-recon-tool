# Not every missing header is equally serious - weight them individually
# instead of treating "missing 1 header" the same as "missing all 6".
HEADER_SEVERITY = {
    "Strict-Transport-Security": "High",   # missing = plaintext downgrade possible
    "Content-Security-Policy": "Medium",   # missing = weaker XSS protection
    "X-Frame-Options": "Medium",           # missing = clickjacking risk
    "X-Content-Type-Options": "Low",
    "Referrer-Policy": "Low",
    "Permissions-Policy": "Low",
}


def compute_risk_summary(hosts):
    high = medium = low = 0
    open_ports_count = 0
    findings = []

    for h in hosts:
        for p in h.get("ports", []):
            open_ports_count += 1
            if p["risky"]:
                high += 1
                detail = f"Port {p['port']} ({p['service']}) is exposed and commonly targeted"
                if p.get("banner"):
                    detail += f" \u2014 banner: {p['banner']}"
                findings.append({"severity": "High", "host": h["hostname"], "detail": detail})

        tls = h.get("tls", {})
        if tls.get("valid") and tls.get("expiring_soon"):
            medium += 1
            findings.append({
                "severity": "Medium", "host": h["hostname"],
                "detail": f"TLS certificate expires in {tls['days_left']} day(s)",
            })

        headers = h.get("headers", {})
        for missing_header in headers.get("headers_missing", []):
            sev = HEADER_SEVERITY.get(missing_header, "Low")
            if sev == "High":
                high += 1
            elif sev == "Medium":
                medium += 1
            else:
                low += 1
            findings.append({
                "severity": sev, "host": h["hostname"],
                "detail": f"Missing header: {missing_header}",
            })

    severity_order = {"High": 0, "Medium": 1, "Low": 2}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 3))

    return {"high": high, "medium": medium, "low": low, "open_ports": open_ports_count, "findings": findings}
