"""Pins the 30-day retention sweep for the identity store.

scripts/purge_data.py keeps its own STORES tuple AND hand-written per-store logic, so
adding a store to the tuple alone gets its directory path-checked and nothing else. That
is exactly how this store shipped unpurged: records enumerating a named person's accounts
and their infostealer exposure would have accumulated forever while the commit message
claimed a 30-day window.

Runs the real script as a subprocess against a temp data directory. No network, and it
never touches the repo's own data/.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPT = os.path.join(REPO_ROOT, 'scripts', 'purge_data.py')

failures = []
cases = 0


def check(condition, message):
    global cases
    cases += 1
    if not condition:
        failures.append(message)
    return bool(condition)


def seed(directory, age_days):
    path = os.path.join(directory, f'{uuid.uuid4()}.json')
    with open(path, 'w') as handle:
        json.dump({'target': 'alice', 'mode': 'username', 'findings': []}, handle)
    stamp = time.time() - age_days * 86400
    os.utime(path, (stamp, stamp))
    return path


def test_aged_identity_records_are_purged_and_fresh_ones_kept():
    root = tempfile.mkdtemp(prefix='nt-purge-')
    try:
        store = os.path.join(root, 'identity')
        os.makedirs(store)
        old = seed(store, age_days=60)
        fresh = seed(store, age_days=1)

        proc = subprocess.run(
            [sys.executable, SCRIPT, '--data-dir', root, '--store', 'identity',
             '--max-age-days', '30', '--yes'],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=120)

        check(proc.returncode == 0,
              f'purge exited {proc.returncode}: {proc.stderr[:300]}')
        check(not os.path.exists(old),
              'a 60-day-old identity record survived a 30-day retention sweep')
        check(os.path.exists(fresh),
              'a 1-day-old identity record was deleted by a 30-day retention sweep')
        check('identity' in proc.stdout,
              f'the identity store was not reported at all: {proc.stdout[:300]!r}')
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_dry_run_deletes_nothing():
    """The default must be non-destructive: this script runs against real analyst data."""
    root = tempfile.mkdtemp(prefix='nt-purge-')
    try:
        store = os.path.join(root, 'identity')
        os.makedirs(store)
        old = seed(store, age_days=60)

        proc = subprocess.run(
            [sys.executable, SCRIPT, '--data-dir', root, '--store', 'identity',
             '--max-age-days', '30'],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=120)

        check(proc.returncode == 0, f'dry run exited {proc.returncode}')
        check(os.path.exists(old), 'a dry run deleted a file')
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main():
    test_aged_identity_records_are_purged_and_fresh_ones_kept()
    test_dry_run_deletes_nothing()

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {cases} cases')


if __name__ == '__main__':
    main()
