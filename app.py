import ipaddress
import time

from flask import Flask, render_template, request, redirect, url_for, flash

from modules.subdomain_enum import enumerate_subdomains
from modules.dns_resolve import resolve_host, reverse_dns
from modules.port_scan import scan_host
from modules.tls_check import check_tls_cert
from modules.http_headers import check_headers
from modules.whois_lookup import lookup_whois
from modules.ip_intel import get_ip_intel
from modules.risk_summary import compute_risk_summary
from modules.banner_grab import grab_banner

app = Flask(__name__)
app.secret_key = "dev-secret-change-me"

# How many discovered subdomains to actually scan (keeps runtime reasonable)
MAX_SUBDOMAINS = 10


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target", "").strip().lower()
    confirmed = request.form.get("confirm")

    if not target:
        flash("Please enter a domain or IP address.")
        return redirect(url_for("index"))
    if not confirmed:
        flash("You must confirm you are authorized to scan this target before continuing.")
        return redirect(url_for("index"))

    start = time.time()

    if is_ip(target):
        report = build_ip_report(target)
    else:
        target = target.replace("http://", "").replace("https://", "").split("/")[0]
        report = build_domain_report(target)

    report["risk_summary"] = compute_risk_summary(report["hosts"])
    report["elapsed_seconds"] = round(time.time() - start, 1)
    return render_template("report.html", report=report)


def _host_checks(hostname, ip):
    ports = scan_host(ip)
    web_open = any(p["port"] in (80, 443, 8080, 8443) for p in ports)
    tls = check_tls_cert(hostname) if any(p["port"] == 443 for p in ports) else {"valid": False, "error": "Port 443 not open"}
    headers = check_headers(hostname) if web_open else {"error": "No web port open", "headers_present": [], "headers_missing": [], "server": None}

    server_banner = headers.get("server")
    for p in ports:
        if p["port"] in (80, 443, 8080, 8443):
            p["banner"] = server_banner
        else:
            p["banner"] = grab_banner(ip, p["port"])

    return ports, tls, headers


def build_ip_report(ip):
    ports, tls, headers = _host_checks(ip, ip)
    intel = get_ip_intel(ip)
    rdns = reverse_dns(ip)

    return {
        "mode": "ip",
        "target": ip,
        "reverse_dns": rdns,
        "intel": intel,
        "whois": None,
        "subdomain_error": None,
        "hosts": [{"hostname": ip, "ip": ip, "ports": ports, "tls": tls, "headers": headers}],
    }


def build_domain_report(domain):
    sub_result = enumerate_subdomains(domain, limit=MAX_SUBDOMAINS)
    subdomains = sub_result["subdomains"] or [domain]
    whois_info = lookup_whois(domain)

    hosts = []
    for sub in subdomains:
        ip = resolve_host(sub)
        if not ip:
            hosts.append({
                "hostname": sub, "ip": None, "ports": [],
                "tls": {"valid": False, "error": "Could not resolve"},
                "headers": {"error": "Could not resolve", "headers_present": [], "headers_missing": [], "server": None},
            })
            continue
        ports, tls, headers = _host_checks(sub, ip)
        hosts.append({"hostname": sub, "ip": ip, "ports": ports, "tls": tls, "headers": headers})

    main_ip = next((h["ip"] for h in hosts if h["ip"]), None)
    intel = get_ip_intel(main_ip)

    return {
        "mode": "domain",
        "target": domain,
        "reverse_dns": None,
        "intel": intel,
        "whois": whois_info,
        "subdomain_error": sub_result["error"],
        "hosts": hosts,
    }


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
