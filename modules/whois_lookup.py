def lookup_whois(domain):
    try:
        import whois  # python-whois package
        w = whois.whois(domain)

        def fmt(v):
            if isinstance(v, list):
                return str(v[0]) if v else None
            return str(v) if v else None

        name_servers = w.name_servers
        if isinstance(name_servers, str):
            name_servers = [name_servers]
        elif not name_servers:
            name_servers = []

        return {
            "registrar": fmt(w.registrar),
            "creation_date": fmt(w.creation_date),
            "expiration_date": fmt(w.expiration_date),
            "name_servers": list(name_servers)[:4],
            "error": None,
        }
    except Exception as e:
        return {
            "registrar": None, "creation_date": None,
            "expiration_date": None, "name_servers": [], "error": str(e),
        }
