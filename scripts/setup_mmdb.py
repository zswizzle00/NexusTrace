#!/usr/bin/env python3
"""
Comprehensive MMDB database setup script for NexusTrace.
This script provides multiple options for setting up IP geolocation databases.
"""

import os
import requests
import zipfile
import shutil
import gzip
from pathlib import Path
import sys

def check_geoip2():
    """Check if geoip2 library is installed."""
    try:
        import geoip2
        print("✓ geoip2 library is installed")
        return True
    except ImportError:
        print("✗ geoip2 library is not installed")
        print("Install it with: pip install geoip2")
        return False

def create_data_directory():
    """Create data directory if it doesn't exist."""
    data_dir = Path(__file__).parent.parent / "data"
    data_dir.mkdir(exist_ok=True)
    return data_dir

def download_geolite2_city():
    """Download GeoLite2 City database (free alternative)."""
    data_dir = create_data_directory()
    mmdb_path = data_dir / "GeoLite2-City.mmdb"
    
    if mmdb_path.exists():
        print(f"✓ GeoLite2 City database already exists at {mmdb_path}")
        return str(mmdb_path)
    
    print("Downloading GeoLite2 City database...")
    print("Note: This requires a free MaxMind account and license key")
    print("1. Sign up at: https://www.maxmind.com/en/geolite2/signup")
    print("2. Generate a license key")
    print("3. Set the MAXMIND_LICENSE_KEY environment variable")
    
    license_key = os.getenv('MAXMIND_LICENSE_KEY')
    if not license_key:
        print("MAXMIND_LICENSE_KEY environment variable not set")
        print("Please set it with your MaxMind license key")
        return None
    
    try:
        # Download GeoLite2 City database
        url = f"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key={license_key}&suffix=tar.gz"
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        # Save the compressed file
        compressed_path = data_dir / "GeoLite2-City.tar.gz"
        with open(compressed_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        # Extract the tar.gz file
        import tarfile
        with tarfile.open(compressed_path, 'r:gz') as tar:
            # Find the .mmdb file in the archive
            mmdb_member = None
            for member in tar.getmembers():
                if member.name.endswith('.mmdb'):
                    mmdb_member = member
                    break
            
            if mmdb_member:
                with open(mmdb_path, 'wb') as f:
                    shutil.copyfileobj(tar.extractfile(mmdb_member), f)
        
        # Clean up compressed file
        compressed_path.unlink()
        
        print(f"✓ Successfully downloaded GeoLite2 City database to {mmdb_path}")
        return str(mmdb_path)
        
    except Exception as e:
        print(f"✗ Error downloading GeoLite2 City database: {e}")
        return None

def download_ipinfo_sample():
    """Download a sample IPinfo database or provide instructions."""
    data_dir = create_data_directory()
    mmdb_path = data_dir / "ipinfo_lite.mmdb"
    
    if mmdb_path.exists():
        print(f"✓ IPinfo Lite database already exists at {mmdb_path}")
        return str(mmdb_path)
    
    print("IPinfo Lite Database Setup:")
    print("1. Sign up for IPinfo Lite plan at: https://ipinfo.io/")
    print("2. Download the MMDB database from your IPinfo dashboard")
    print("3. Place the file at: data/ipinfo_lite.mmdb")
    print("4. The application will automatically detect and use it")
    
    return None

def create_sample_mmdb():
    """Create a minimal sample MMDB file for testing."""
    data_dir = create_data_directory()
    mmdb_path = data_dir / "sample.mmdb"
    
    if mmdb_path.exists():
        print(f"✓ Sample MMDB database already exists at {mmdb_path}")
        return str(mmdb_path)
    
    print("Creating a minimal sample MMDB database for testing...")
    print("Note: This is a placeholder file and won't provide real geolocation data")
    
    # Create a minimal MMDB file structure (this is just a placeholder)
    try:
        # Create a simple binary file that geoip2 can read (minimal valid MMDB)
        with open(mmdb_path, 'wb') as f:
            # Write a minimal MMDB header
            f.write(b'\xab\xcd\xefMaxMind.com')
            f.write(b'\x00' * 16)  # Metadata size placeholder
            f.write(b'\x00' * 4)   # Metadata offset placeholder
            
        print(f"✓ Created sample MMDB database at {mmdb_path}")
        print("Note: This is a placeholder file for testing the MMDB loading mechanism")
        return str(mmdb_path)
        
    except Exception as e:
        print(f"✗ Error creating sample MMDB: {e}")
        return None

def update_ip_service_config():
    """Update the IP service configuration to use available MMDB databases."""
    ip_service_path = Path(__file__).parent.parent / "app" / "services" / "ip_service.py"
    
    if not ip_service_path.exists():
        print("✗ IP service file not found")
        return False
    
    print("Updating IP service configuration...")
    
    # Read the current file
    with open(ip_service_path, 'r') as f:
        content = f.read()
    
    # Update the MMDB path configuration
    updated_content = content.replace(
        "mmdb_path = os.getenv('MMDB_PATH', os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'ipinfo_lite.mmdb'))",
        """mmdb_path = os.getenv('MMDB_PATH', os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'ipinfo_lite.mmdb'))
    # Try alternative MMDB databases if primary doesn't exist
    if not os.path.exists(mmdb_path):
        alternative_paths = [
            os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'GeoLite2-City.mmdb'),
            os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'sample.mmdb'),
        ]
        for alt_path in alternative_paths:
            if os.path.exists(alt_path):
                mmdb_path = alt_path
                logger.info(f"Using alternative MMDB database: {mmdb_path}")
                break"""
    )
    
    # Write the updated content
    with open(ip_service_path, 'w') as f:
        f.write(updated_content)
    
    print("✓ Updated IP service configuration")
    return True

def main():
    """Main setup function."""
    print("NexusTrace MMDB Database Setup")
    print("=" * 40)
    
    # Check requirements
    if not check_geoip2():
        print("\nPlease install geoip2 first:")
        print("pip install geoip2")
        sys.exit(1)
    
    print("\nAvailable MMDB database options:")
    print("1. GeoLite2 City (free, requires MaxMind account)")
    print("2. IPinfo Lite (requires IPinfo account)")
    print("3. Create sample database (for testing)")
    print("4. Skip MMDB setup (API-only mode)")
    
    choice = input("\nChoose an option (1-4): ").strip()
    
    mmdb_path = None
    
    if choice == "1":
        mmdb_path = download_geolite2_city()
    elif choice == "2":
        mmdb_path = download_ipinfo_sample()
    elif choice == "3":
        mmdb_path = create_sample_mmdb()
    elif choice == "4":
        print("Skipping MMDB setup. Application will use API-only mode.")
        return
    else:
        print("Invalid choice. Exiting.")
        return
    
    if mmdb_path:
        print(f"\n✓ MMDB database ready at: {mmdb_path}")
        update_ip_service_config()
        print("\nConfiguration complete!")
        print("The application will now use the MMDB database for faster IP lookups.")
    else:
        print("\nMMDB setup incomplete. The application will use API-only mode.")

if __name__ == "__main__":
    main() 