import requests


def get_ip_intel(ip, timeout=6):
    """Free geolocation/ASN lookup via ip-api.com (no API key required, rate limited)."""
    if not ip:
        return {"error": "No IP available to look up"}
    try:
        fields = "status,message,country,regionName,city,isp,org,as,lat,lon,query"
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields={fields}", timeout=timeout)
        data = resp.json()
        if data.get("status") == "success":
            return {
                "ip": data.get("query"),
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "asn": data.get("as"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "error": None,
            }
        return {"error": data.get("message", "Lookup failed")}
    except Exception as e:
        return {"error": str(e)}
