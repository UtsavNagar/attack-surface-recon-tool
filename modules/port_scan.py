"""
Lightweight TCP connect port scanner.
Pure Python (socket + threads) so it runs on Windows/Linux/Mac
without needing nmap installed.
"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "OracleDB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9200: "Elasticsearch", 27017: "MongoDB",
}

# Ports that are generally considered risky if exposed to the public internet
RISKY_PORTS = {21, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 27017}


def scan_port(host, port, timeout=0.8):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                return port
    except Exception:
        pass
    return None


def scan_host(host, ports=None, max_workers=40, timeout=0.8):
    """Scan a host and return a list of {port, service, risky} dicts for open ports."""
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, host, p, timeout): p for p in ports}
        for future in as_completed(futures):
            port = future.result()
            if port:
                open_ports.append(port)

    open_ports.sort()
    findings = []
    for p in open_ports:
        findings.append({
            "port": p,
            "service": COMMON_PORTS.get(p, "Unknown"),
            "risky": p in RISKY_PORTS,
        })
    return findings
