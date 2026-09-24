#!/usr/bin/env python3
"""Fetch YARA detection rules for NexusTrace.

The app ships with no rules. This is a deliberate operator action, the same shape as
scripts/setup_mmdb.py, because rules carry their own licences and shipping them would
make this project a rule distributor.

Default source: Neo23x0/signature-base, under Detection Rule License 1.1. Only the
yara/ directory is taken; vendor/ holds third-party files under other terms.
"""
import io
import os
import sys
import zipfile
from pathlib import Path

import requests

ARCHIVE_URL = 'https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip'
RULES_SUBPATH = 'signature-base-master/yara/'
DEST = Path(__file__).parent.parent / 'data' / 'yara'
TIMEOUT = 120

ATTRIBUTION = """
These rules are licensed under Detection Rule License (DRL) 1.1.

DRL 1.1 requires that messages based on matches with the rules retain identification of
the rule author. NexusTrace renders the `author` meta on every match for this reason; do
not remove it from the result card.

Source: https://github.com/Neo23x0/signature-base
"""


def main():
    print(f'Fetching {ARCHIVE_URL}')
    try:
        response = requests.get(ARCHIVE_URL, timeout=TIMEOUT)
        response.raise_for_status()
    except requests.RequestException as exc:
        print(f'FAILED: {exc}')
        return 1

    DEST.mkdir(parents=True, exist_ok=True)
    written = 0
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        for info in archive.infolist():
            if info.is_dir() or not info.filename.startswith(RULES_SUBPATH):
                continue
            if not info.filename.endswith(('.yar', '.yara')):
                continue
            name = os.path.basename(info.filename)
            if not name or os.path.sep in name or name.startswith('.'):
                continue                     # never let an archive choose a path
            (DEST / name).write_bytes(archive.read(info))
            written += 1

    print(f'Wrote {written} rule files to {DEST}')
    print(ATTRIBUTION)
    print('Restart NexusTrace: rules are compiled once at import.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
