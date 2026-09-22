from pathlib import Path
from modules.m17_geo_infra_intel.engine import analyze_geo_infrastructure, DEFAULT_DB_PATH, DB_VERSION

def chain(*ips):
    return {"chain": [{"hop_number": i+1, "ip": ip} for i, ip in enumerate(ips)]}

def test_known_ip_in_bundled_database():
    result = analyze_geo_infrastructure(chain("8.8.8.8"))
    hop = result["hop_intelligence"][0]
    assert result["database_available"] is True
    assert hop["status"] == "RESOLVED" and hop["country_code"] == "US"
    assert DB_VERSION in result["findings"][0]["evidence"]

def test_ip_not_in_database_is_unavailable_never_guessed():
    hop = analyze_geo_infrastructure(chain("203.0.113.5"))["hop_intelligence"][0]
    assert hop["status"] == "INTERNAL_OR_NON_ROUTABLE" or (hop["status"] == "GEOLOCATION_UNAVAILABLE" and hop["country_name"] is None)

def test_private_reserved_is_labeled_and_not_geolocated():
    result = analyze_geo_infrastructure(chain("10.1.2.3", "127.0.0.1"))
    assert all(h["status"] == "INTERNAL_OR_NON_ROUTABLE" for h in result["hop_intelligence"])

def test_missing_database_file_degrades_honestly(tmp_path):
    result = analyze_geo_infrastructure(chain("8.8.8.8"), str(tmp_path/"missing.mmdb"))
    assert result["database_available"] is False
    assert result["hop_intelligence"][0]["status"] == "GEOLOCATION_UNAVAILABLE"

def test_corrupt_database_file_degrades_honestly(tmp_path):
    db = tmp_path/"bad.mmdb"; db.write_bytes(b"not an mmdb")
    result = analyze_geo_infrastructure(chain("8.8.8.8"), str(db))
    assert result["database_available"] is False
    assert result["hop_intelligence"][0]["country_name"] is None

def test_ipv6_lookup_supported():
    hop = analyze_geo_infrastructure(chain("2001:4860:4860::8888"))["hop_intelligence"][0]
    assert hop["status"] == "RESOLVED"
    assert hop["country_code"]
