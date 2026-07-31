#!/usr/bin/env python3
"""Download the IPinfo Lite MMDB for offline, API-free IP geolocation."""

import os
import requests
import zipfile
import shutil
from pathlib import Path

def download_ipinfo_mmdb():
    data_dir = Path(__file__).parent.parent / "data"
    data_dir.mkdir(exist_ok=True)

    mmdb_path = data_dir / "ipinfo_lite.mmdb"

    if mmdb_path.exists():
        print(f"MMDB database already exists at {mmdb_path}")
        return str(mmdb_path)
    
    # A placeholder: the real URL comes from an IPinfo Lite plan dashboard.
    download_url = "https://ipinfo.io/data/free/country_asn.mmdb.gz"
    
    print("Downloading IPinfo Lite MMDB database...")
    print("Note: You may need to sign up for IPinfo Lite plan to get the download URL")
    print(f"Expected download URL: {download_url}")
    
    try:
        response = requests.get(download_url, stream=True)
        response.raise_for_status()

        compressed_path = data_dir / "ipinfo_lite.mmdb.gz"
        with open(compressed_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        import gzip
        with gzip.open(compressed_path, 'rb') as f_in:
            with open(mmdb_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

        compressed_path.unlink()
        
        print(f"Successfully downloaded and extracted MMDB database to {mmdb_path}")
        return str(mmdb_path)
        
    except requests.exceptions.RequestException as e:
        print(f"Error downloading MMDB database: {e}")
        print("\nManual download instructions:")
        print("1. Sign up for IPinfo Lite plan at https://ipinfo.io/")
        print("2. Download the MMDB database from your IPinfo dashboard")
        print("3. Place the file at: data/ipinfo_lite.mmdb")
        return None
    except Exception as e:
        print(f"Error processing MMDB database: {e}")
        return None

if __name__ == "__main__":
    result = download_ipinfo_mmdb()
    if result:
        print(f"MMDB database ready at: {result}")
    else:
        print("Failed to download MMDB database. Please download manually.") 