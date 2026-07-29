#!/usr/bin/env python3
"""NexusTrace - retention / purge tool for stored analyst data.

Trims real analyst data (scanned URLs, sender addresses, subjects, Received-chain
IPs) to a retention window:

    data/scans/<uuid>.json
    data/screenshots/<uuid>.png, data/screenshots/<uuid>-<stage>.png
    data/analyses/<uuid>.json

Usage:
    python3 scripts/purge_data.py                        # dry run, 30-day retention
    python3 scripts/purge_data.py --max-age-days 7
    python3 scripts/purge_data.py --store analyses
    python3 scripts/purge_data.py --max-age-days 90 --yes

Nothing is deleted without --yes; a bare run only reports what would go.

Age comes from file mtime - the same ordering ``list_scans()`` / ``list_analyses()``
use - never from a ``created_at`` field inside the JSON, so a malformed record can
neither make itself immortal nor make anything else deletable.

A scan's screenshots are always removed together with its record, so --store scans
still deletes the screenshots belonging to the records it purges. Screenshots with
no scan record ("orphaned") are reported, and are purged on age only when the
screenshots store is in scope.

An operator tool: deliberately not wired into the app, a cron, the Dockerfile, or
start.sh.
"""
import argparse
import os
import re
import stat
import sys
from collections import defaultdict, namedtuple
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_MAX_AGE_DAYS = 30
DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent / 'data'

STORES = ('scans', 'screenshots', 'analyses')

_UUID = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
RECORD_RE = re.compile(rf'^({_UUID})\.json$')
SHOT_RE = re.compile(rf'^({_UUID})(?:-([A-Za-z0-9_-]{{1,32}}))?\.png$')

Entry = namedtuple('Entry', 'path uuid size mtime')


def _fmt_bytes(n):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024 or unit == 'GB':
            return f'{n:.0f} {unit}' if unit == 'B' else f'{n:.1f} {unit}'
        n /= 1024.0


def _fmt_time(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def collect(directory, pattern):
    """List the store's recognised files. Anything else is returned as 'unexpected'
    and never touched - an unrecognised file is not assumed to be junk."""
    entries, unexpected = [], []
    if not directory.is_dir():
        return entries, unexpected
    with os.scandir(directory) as it:
        items = sorted(it, key=lambda e: e.name)
    for item in items:
        # lstat, never stat: a symlink is reported, not followed out of the store.
        st = item.stat(follow_symlinks=False)
        if not stat.S_ISREG(st.st_mode):
            unexpected.append((item.name, 'not a regular file'))
            continue
        match = pattern.match(item.name)
        if not match:
            unexpected.append((item.name, 'unrecognised name'))
            continue
        entries.append(Entry(Path(item.path), match.group(1), st.st_size, st.st_mtime))
    return entries, unexpected


def remove(path, store_dir):
    """Delete one file, re-checking the invariants immediately before unlinking:
    it must still be a plain file sitting directly in the store directory."""
    if path.parent != store_dir:
        raise RuntimeError(f'refusing to delete outside {store_dir}: {path}')
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode):
        raise RuntimeError(f'refusing to delete non-regular file: {path}')
    os.unlink(path)


def report_store(name, directory, doomed, retained, unexpected, notes, apply, list_all):
    print(f'\n{name}  {directory}')
    if not directory.is_dir():
        print('  directory not present')
        return
    verb = 'deleted' if apply else 'would delete'
    d_bytes = sum(e.size for e in doomed)
    r_bytes = sum(e.size for e in retained)
    print(f'  {verb:<13} {len(doomed):>5} files  {_fmt_bytes(d_bytes):>10}')
    print(f'  {"retained":<13} {len(retained):>5} files  {_fmt_bytes(r_bytes):>10}', end='')
    if retained:
        mtimes = [e.mtime for e in retained]
        print(f'  oldest {_fmt_time(min(mtimes))}  newest {_fmt_time(max(mtimes))}')
    else:
        print()
    for note in notes:
        print(f'  {note}')

    shown = doomed if list_all else doomed[:20]
    for entry in shown:
        print(f'    - {entry.path.name}  {_fmt_bytes(entry.size)}  {_fmt_time(entry.mtime)}')
    if len(doomed) > len(shown):
        print(f'    ... and {len(doomed) - len(shown)} more (use --list)')

    if unexpected:
        print(f'  unexpected entries (left alone): {len(unexpected)}')
        for filename, reason in unexpected:
            print(f'    ? {filename}  [{reason}]')


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--max-age-days', type=float, default=DEFAULT_MAX_AGE_DAYS,
                        help=f'retention window in days (default: {DEFAULT_MAX_AGE_DAYS})')
    parser.add_argument('--store', choices=STORES + ('all',), default='all',
                        help='restrict the purge to one store (default: all)')
    parser.add_argument('--data-dir', default=str(DEFAULT_DATA_DIR),
                        help=f'data directory to operate on (default: {DEFAULT_DATA_DIR})')
    parser.add_argument('--yes', '--apply', dest='apply', action='store_true',
                        help='actually delete; without this the run is a dry run')
    parser.add_argument('--list', dest='list_all', action='store_true',
                        help='list every affected file instead of the first 20 per store')
    args = parser.parse_args()

    if args.max_age_days < 0:
        parser.error('--max-age-days must not be negative')

    data_dir = Path(args.data_dir).expanduser().resolve()
    if not data_dir.is_dir():
        sys.exit(f'Data directory not found: {data_dir}')

    stores = set(STORES) if args.store == 'all' else {args.store}
    dirs = {}
    for name in STORES:
        path = (data_dir / name)
        resolved = path.resolve()
        # A store directory that symlinks outside the data directory is not ours to purge.
        if path.exists() and not str(resolved).startswith(str(data_dir) + os.sep):
            sys.exit(f'Refusing to operate on {name}: {path} resolves outside {data_dir}')
        dirs[name] = resolved

    cutoff = datetime.now(timezone.utc).timestamp() - args.max_age_days * 86400

    scans, scans_unexpected = collect(dirs['scans'], RECORD_RE)
    shots, shots_unexpected = collect(dirs['screenshots'], SHOT_RE)
    analyses, analyses_unexpected = collect(dirs['analyses'], RECORD_RE)

    shots_by_uuid = defaultdict(list)
    for entry in shots:
        shots_by_uuid[entry.uuid].append(entry)
    record_uuids = {entry.uuid for entry in scans}

    doomed_scans = [e for e in scans if e.mtime < cutoff] if 'scans' in stores else []
    doomed_scan_ids = {e.uuid for e in doomed_scans}
    retained_scans = [e for e in scans if e.uuid not in doomed_scan_ids]

    # Screenshots travel with their record; orphans are age-purged on their own.
    doomed_shots = [e for e in shots if e.uuid in doomed_scan_ids]
    orphans = [e for e in shots if e.uuid not in record_uuids]
    if 'screenshots' in stores:
        doomed_shots += [e for e in orphans if e.mtime < cutoff]
    doomed_shot_paths = {e.path for e in doomed_shots}
    retained_shots = [e for e in shots if e.path not in doomed_shot_paths]
    retained_orphans = [e for e in orphans if e.path not in doomed_shot_paths]

    doomed_analyses = [e for e in analyses if e.mtime < cutoff] if 'analyses' in stores else []
    doomed_analysis_ids = {e.uuid for e in doomed_analyses}
    retained_analyses = [e for e in analyses if e.uuid not in doomed_analysis_ids]

    mode = 'APPLY - files will be deleted' if args.apply else 'DRY RUN - nothing will be deleted'
    print(f'NexusTrace data purge  [{mode}]')
    print(f'  data directory : {data_dir}')
    print(f'  retention      : {args.max_age_days:g} days (cutoff {_fmt_time(cutoff)})')
    print(f'  stores         : {", ".join(sorted(stores))}')

    shot_notes = []
    if orphans and 'screenshots' in stores:
        shot_notes.append(f'orphaned (no scan record): {len(orphans)}, '
                          f'{len(retained_orphans)} still within retention')
    elif orphans:
        shot_notes.append(f'orphaned (no scan record): {len(orphans)} '
                          '(screenshots store not in scope, none age-purged)')
    if doomed_scan_ids and 'screenshots' not in stores:
        shot_notes.append('screenshots of purged scan records are removed with their record')

    report_store('scans      ', dirs['scans'], doomed_scans, retained_scans,
                 scans_unexpected, [], args.apply, args.list_all)
    report_store('screenshots', dirs['screenshots'], doomed_shots, retained_shots,
                 shots_unexpected, shot_notes, args.apply, args.list_all)
    report_store('analyses   ', dirs['analyses'], doomed_analyses, retained_analyses,
                 analyses_unexpected, [], args.apply, args.list_all)

    total = doomed_scans + doomed_shots + doomed_analyses
    total_bytes = sum(e.size for e in total)
    print()
    if not args.apply:
        print(f'Dry run: {len(total)} files ({_fmt_bytes(total_bytes)}) would be deleted. '
              'Re-run with --yes to apply.')
        return 0

    failures = 0
    freed = 0
    for entries, store_dir in ((doomed_scans, dirs['scans']),
                               (doomed_shots, dirs['screenshots']),
                               (doomed_analyses, dirs['analyses'])):
        for entry in entries:
            try:
                remove(entry.path, store_dir)
                freed += entry.size
            except Exception as exc:
                failures += 1
                print(f'FAILED to delete {entry.path}: {exc}', file=sys.stderr)
    print(f'Deleted {len(total) - failures} files ({_fmt_bytes(freed)}).')
    if failures:
        print(f'{failures} deletion(s) failed.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
