import os


def env_str(key: str, default: str) -> str:
    return os.environ.get(key, default)


def env_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, str(default)))
    except ValueError:
        return default


def env_bool(key: str, default: bool) -> bool:
    """Parse boolean environment variable. Accepts: true/false, 1/0, yes/no (case insensitive)"""
    value = os.environ.get(key, "").lower().strip()
    if not value:
        return default
    return value in ("true", "1", "yes", "on")


# RIR Support Configuration
SUPPORT_RIPE = env_bool("SUPPORT_RIPE", True)
SUPPORT_ARIN = env_bool("SUPPORT_ARIN", True)
SUPPORT_APNIC = env_bool("SUPPORT_APNIC", True)

# RIPE NCC Endpoints
RIPE_WHOIS_SERVER = "whois.ripe.net"
RIPE_WHOIS_PORT = 43
RIPE_REST_BASE = "https://rest.db.ripe.net"
RIPE_RDAP_BASE = "https://rdap.db.ripe.net"

# ARIN Endpoints
ARIN_WHOIS_SERVER = "whois.arin.net"
ARIN_WHOIS_PORT = 43
ARIN_REST_BASE = "https://whois.arin.net/rest"
ARIN_RDAP_BASE = "https://rdap.arin.net/registry"

# APNIC Endpoints
APNIC_WHOIS_SERVER = "whois.apnic.net"
APNIC_WHOIS_PORT = 43
APNIC_REST_BASE = "https://registry-api.apnic.net/v1"
APNIC_RDAP_BASE = "https://rdap.apnic.net"

# General Configuration
HTTP_TIMEOUT_SECONDS = env_int("HTTP_TIMEOUT_SECONDS", 10)
WHOIS_CONNECT_TIMEOUT_SECONDS = env_int("WHOIS_CONNECT_TIMEOUT_SECONDS", 5)
WHOIS_READ_TIMEOUT_SECONDS = env_int("WHOIS_READ_TIMEOUT_SECONDS", 5)
CACHE_TTL_SECONDS = env_int("CACHE_TTL_SECONDS", 60)
CACHE_MAX_ITEMS = env_int("CACHE_MAX_ITEMS", 512)
USER_AGENT = env_str("USER_AGENT", "whois-mcp/1.0")
