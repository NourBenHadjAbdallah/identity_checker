"""Tiny offline GeoIP table for the lab (no account, no download).
Replace lookup() with a GeoLite2 reader if you want real data."""
import ipaddress, math

# (network, city, lat, lon)  -- TEST-NET ranges are used as "foreign" demo locations
TABLE = [
    ("41.224.0.0/12", "Tunis (TN)", 36.8065, 10.1815),
    ("81.2.69.0/24", "London (UK)", 51.5142, -0.0931),
    ("203.0.113.0/24", "Tokyo (JP)", 35.6762, 139.6503),
    ("198.51.100.0/24", "New York (US)", 40.7128, -74.0060),
    ("192.0.2.0/24", "Sao Paulo (BR)", -23.5505, -46.6333),
]
CAMPUS = ("Campus (Tunis)", 36.8065, 10.1815)


def lookup(ip):
    """Return (name, lat, lon) or None when unknown."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net, name, lat, lon in TABLE:
        if a in ipaddress.ip_network(net):
            return (name, lat, lon)
    if a.is_private or a.is_loopback:
        return CAMPUS
    return None


def haversine_km(lat1, lon1, lat2, lon2):
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))
