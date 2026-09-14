import socket


def resolve_host(hostname, timeout=3):
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def reverse_dns(ip, timeout=3):
    try:
        socket.setdefaulttimeout(timeout)
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None
