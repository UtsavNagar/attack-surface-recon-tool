"""
Lightweight banner grabbing for common text-banner services (SSH, FTP, SMTP, etc).
This is what turns "port 22 open" into "port 22 open, running OpenSSH 8.2p1".
"""
import socket

TEXT_BANNER_PORTS = {21, 22, 23, 25, 110, 143, 3306}


def grab_banner(host, port, timeout=2):
    if port not in TEXT_BANNER_PORTS:
        return None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            banner = s.recv(256).decode(errors="ignore").strip()
            return banner if banner else None
    except Exception:
        return None
