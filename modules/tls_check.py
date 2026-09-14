import ssl
import socket
from datetime import datetime


def check_tls_cert(hostname, port=443, timeout=5):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        not_after = cert.get("notAfter")
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry - datetime.utcnow()).days
        issuer = dict(x[0] for x in cert.get("issuer", []))

        return {
            "valid": True,
            "expires": expiry.strftime("%Y-%m-%d"),
            "days_left": days_left,
            "issuer": issuer.get("organizationName", "Unknown"),
            "expiring_soon": days_left < 30,
            "error": None,
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}
