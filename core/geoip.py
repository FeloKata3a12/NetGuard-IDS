"""
NetGuard – GeoIP Resolver
Priority:
  1. Local GeoLite2-City.mmdb  (offline, fast, accurate)
  2. ip-api.com HTTP API        (free, no key needed, 45 req/min)
  3. Stub / private IP label    (always works)

Setup (option 1 – recommended):
  - Register free at https://www.maxmind.com/en/geolite2/signup
  - Download GeoLite2-City.mmdb
  - Place it at:  NetGuard/data/GeoLite2-City.mmdb
"""

import ipaddress
import threading
import time
from functools import lru_cache
from pathlib import Path

# ── DB path ───────────────────────────────────────────────────────────────────
_BASE = Path(__file__).parent.parent
DB_PATH = _BASE / "data" / "GeoLite2-City.mmdb"

# ── Private / reserved ranges ─────────────────────────────────────────────────
_PRIVATE = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE)
    except ValueError:
        return False

# ── Result structure ──────────────────────────────────────────────────────────
def _stub(ip: str) -> dict:
    if _is_private(ip):
        return {"ip": ip, "country": "Private", "country_code": "LAN",
                "city": "Local Network", "lat": 0.0, "lon": 0.0, "isp": "-", "source": "private"}
    return {"ip": ip, "country": "Unknown", "country_code": "??",
            "city": "Unknown", "lat": 0.0, "lon": 0.0, "isp": "-", "source": "unknown"}

# ── Local DB reader ───────────────────────────────────────────────────────────
_db_reader = None
_db_lock   = threading.Lock()

def _get_db_reader():
    global _db_reader
    if _db_reader is not None:
        return _db_reader
    with _db_lock:
        if _db_reader is None and DB_PATH.exists():
            try:
                import geoip2.database
                _db_reader = geoip2.database.Reader(str(DB_PATH))
            except Exception:
                _db_reader = None
    return _db_reader

def _lookup_local(ip: str) -> dict | None:
    reader = _get_db_reader()
    if reader is None:
        return None
    try:
        r = reader.city(ip)
        return {
            "ip":           ip,
            "country":      r.country.name or "Unknown",
            "country_code": r.country.iso_code or "??",
            "city":         r.city.name or "Unknown",
            "lat":          float(r.location.latitude  or 0),
            "lon":          float(r.location.longitude or 0),
            "isp":          "-",
            "source":       "local_db",
        }
    except Exception:
        return None

# ── HTTP fallback (ip-api.com) ────────────────────────────────────────────────
_http_cache : dict[str, tuple[dict, float]] = {}   # ip → (result, timestamp)
_HTTP_TTL   = 3600   # seconds
_http_lock  = threading.Lock()

def _lookup_http(ip: str) -> dict | None:
    # Check cache first
    with _http_lock:
        if ip in _http_cache:
            result, ts = _http_cache[ip]
            if time.time() - ts < _HTTP_TTL:
                return result

    try:
        import requests
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,city,lat,lon,isp"},
            timeout=3,
        )
        data = resp.json()
        if data.get("status") == "success":
            result = {
                "ip":           ip,
                "country":      data.get("country", "Unknown"),
                "country_code": data.get("countryCode", "??"),
                "city":         data.get("city", "Unknown"),
                "lat":          float(data.get("lat", 0)),
                "lon":          float(data.get("lon", 0)),
                "isp":          data.get("isp", "-"),
                "source":       "ip-api",
            }
            with _http_lock:
                _http_cache[ip] = (result, time.time())
            return result
    except Exception:
        pass
    return None

# ── Public API ────────────────────────────────────────────────────────────────
_cache : dict[str, dict] = {}
_cache_lock = threading.Lock()

def geolocate(ip: str) -> dict:
    """
    Return geo info dict for an IP address.
    Keys: ip, country, country_code, city, lat, lon, isp, source
    """
    if _is_private(ip):
        return _stub(ip)

    with _cache_lock:
        if ip in _cache:
            return _cache[ip]

    # Try local DB first (fast, offline)
    result = _lookup_local(ip)

    # Fall back to HTTP API
    if result is None:
        result = _lookup_http(ip)

    # Final fallback
    if result is None:
        result = _stub(ip)

    with _cache_lock:
        _cache[ip] = result

    return result


def geolocate_many(ips: list[str]) -> dict[str, dict]:
    """Batch geolocate a list of IPs. Returns {ip: geo_dict}."""
    return {ip: geolocate(ip) for ip in set(ips)}


def db_status() -> str:
    """Human-readable status of the geo DB."""
    if DB_PATH.exists():
        size_mb = DB_PATH.stat().st_size / 1_048_576
        return f"✅ Local DB loaded ({size_mb:.0f} MB)"
    return "⚠️ No local DB — using ip-api.com fallback (place GeoLite2-City.mmdb in data/)"
