import ipaddress
import os
from functools import lru_cache
from typing import Any


@lru_cache(maxsize=2)
def _reader(database_path: str):
    from geoip2.database import Reader

    return Reader(database_path)


def lookup_country(address: str, database_path: str | None = None) -> dict[str, Any]:
    path = database_path or os.getenv("CYBERGUARD_GEOIP_DB_PATH", "").strip()
    if not path:
        return {"status": "disabled", "country": None}
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return {"status": "invalid_address", "country": None}
    if not ip.is_global:
        return {"status": "non_public_address", "country": None}
    if not os.path.isfile(path):
        return {"status": "database_missing", "country": None}
    try:
        reader = _reader(path)
        country = reader.country(str(ip)).country.iso_code
        return {"status": "located" if country else "country_unknown", "country": country}
    except ImportError:
        return {"status": "unavailable", "country": None}
    except Exception as error:
        if error.__class__.__name__ == "AddressNotFoundError":
            return {"status": "country_unknown", "country": None}
        return {"status": "unavailable", "country": None}