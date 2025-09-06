import os

def env_str(key: str, default: str) -> str:
    return os.environ.get(key, default)


def env_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, str(default)))
    except ValueError:
        return default


WHOIS_SERVER = env_str("WHOIS_SERVER", "whois.ripe.net")
WHOIS_PORT = env_int("WHOIS_PORT", 43)
RIPE_REST = env_str("RIPE_REST", "https://rest.db.ripe.net")
RDAP_BASE = env_str("RDAP_BASE", "https://rdap.db.ripe.net")
HTTP_TIMEOUT_SECONDS = env_int("HTTP_TIMEOUT_SECONDS", 10)
WHOIS_CONNECT_TIMEOUT_SECONDS = env_int("WHOIS_CONNECT_TIMEOUT_SECONDS", 5)
WHOIS_READ_TIMEOUT_SECONDS = env_int("WHOIS_READ_TIMEOUT_SECONDS", 5)
CACHE_TTL_SECONDS = env_int("CACHE_TTL_SECONDS", 60)
CACHE_MAX_ITEMS = env_int("CACHE_MAX_ITEMS", 512)