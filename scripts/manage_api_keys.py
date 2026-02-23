#!/usr/bin/env python3
"""CLI for managing NexusTrace enrichment API keys.

Usage:
    python scripts/manage_api_keys.py list
    python scripts/manage_api_keys.py create "My SIEM Tool"
    python scripts/manage_api_keys.py revoke <full-key>
"""
import json
import os
import secrets
import sys
from datetime import datetime, timezone

API_KEYS_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'api_keys.json')


def _load():
    if not os.path.exists(API_KEYS_FILE):
        return {'keys': {}}
    with open(API_KEYS_FILE) as f:
        return json.load(f)


def _save(data):
    os.makedirs(os.path.dirname(API_KEYS_FILE), exist_ok=True)
    with open(API_KEYS_FILE, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"Saved to {API_KEYS_FILE}")


def cmd_list():
    data = _load()
    keys = data.get('keys', {})
    if not keys:
        print("No API keys configured.")
        return
    print(f"{'KEY':<68}  {'NAME':<30}  {'CREATED':<20}  ACTIVE")
    print('-' * 130)
    for key, info in keys.items():
        print(f"{key:<68}  {info.get('name', ''):<30}  {info.get('created', ''):<20}  {info.get('active', False)}")


def cmd_create(name):
    data = _load()
    key = secrets.token_hex(32)
    data.setdefault('keys', {})[key] = {
        'name': name,
        'created': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'active': True,
    }
    _save(data)
    print(f"\nCreated API key for '{name}':")
    print(f"  {key}")
    print("\nStore this key securely — it will not be shown again.")


def cmd_revoke(key):
    data = _load()
    keys = data.get('keys', {})
    if key not in keys:
        print(f"Key not found: {key}")
        sys.exit(1)
    keys[key]['active'] = False
    _save(data)
    print(f"Revoked key: {key}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == 'list':
        cmd_list()
    elif command == 'create':
        if len(sys.argv) < 3:
            print("Usage: manage_api_keys.py create <name>")
            sys.exit(1)
        cmd_create(sys.argv[2])
    elif command == 'revoke':
        if len(sys.argv) < 3:
            print("Usage: manage_api_keys.py revoke <key>")
            sys.exit(1)
        cmd_revoke(sys.argv[2])
    else:
        print(f"Unknown command: {command!r}")
        print(__doc__)
        sys.exit(1)


if __name__ == '__main__':
    main()
