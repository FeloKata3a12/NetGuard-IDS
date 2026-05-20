#!/usr/bin/env python3
"""
NetGuard – GeoLite2 Database Downloader
Downloads GeoLite2-City.mmdb from MaxMind (free account required).

Usage:
    python download_geodb.py --key YOUR_LICENSE_KEY

Get a free license key at: https://www.maxmind.com/en/geolite2/signup
"""

import argparse
import hashlib
import tarfile
import urllib.request
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
DB_FILE  = DATA_DIR / "GeoLite2-City.mmdb"

URL_TEMPLATE = (
    "https://download.maxmind.com/app/geoip_download"
    "?edition_id=GeoLite2-City&license_key={key}&suffix=tar.gz"
)


def download(key: str):
    DATA_DIR.mkdir(exist_ok=True)
    url = URL_TEMPLATE.format(key=key)

    print(f"[*] Downloading GeoLite2-City database...")
    tmp = DATA_DIR / "geolite2.tar.gz"
    urllib.request.urlretrieve(url, tmp)
    print(f"[+] Downloaded: {tmp.stat().st_size / 1_048_576:.1f} MB")

    print("[*] Extracting...")
    with tarfile.open(tmp, "r:gz") as tar:
        for member in tar.getmembers():
            if member.name.endswith("GeoLite2-City.mmdb"):
                member.name = "GeoLite2-City.mmdb"
                tar.extract(member, DATA_DIR)
                break

    tmp.unlink()
    if DB_FILE.exists():
        print(f"[✓] Database saved to: {DB_FILE}")
        print(f"    Size: {DB_FILE.stat().st_size / 1_048_576:.1f} MB")
    else:
        print("[!] Extraction failed — check your license key.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download GeoLite2-City DB")
    parser.add_argument("--key", required=True, help="MaxMind license key")
    args = parser.parse_args()
    download(args.key)
