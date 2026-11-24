"""Enrichment helpers: internal-IP check and a tiny simulated GeoIP table."""
import ipaddress

_INTERNAL = [ipaddress.ip_network(n) for n in
             ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")]

# Simulated GeoIP (prefix -> country). Replace with MaxMind GeoLite2 in production.
_GEO = {
    "203.0.113.": "IN", "198.51.100.": "BR", "185.220.": "RU",
    "45.155.": "NL", "91.92.": "BG", "194.165.": "SC", "8.8.": "US",
    "1.1.": "AU", "142.250.": "US", "151.101.": "US", "13.107.": "US",
}


def is_internal(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return any(addr in n for n in _INTERNAL)


def country_of(ip):
    if not ip:
        return None
    if is_internal(ip):
        return "INTERNAL"
    for prefix, cc in _GEO.items():
        if ip.startswith(prefix):
            return cc
    return "??"
