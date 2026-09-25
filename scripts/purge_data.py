#!/usr/bin/env python3
"""NexusTrace: retention / purge tool for stored analyst data.

Trims real analyst data (scanned URLs, sender addresses, subjects, Received-chain
IPs, queued abuse.ch submissions) to a retention window:

    data/scans/<uuid>.json
    data/screenshots/<uuid>.png, data/screenshots/<uuid>-<stage>.png
    data/analyses/<uuid>.json
    data/submissions/<uuid>.json
    data/quarantine/<sha256>-<submission-uuid>.bin        queued abuse.ch sample bytes
    data/activity/<YYYY-MM-DD>.jsonl                      per-request log, client IPs

Usage:
    python3 scripts/purge_data.py                        # dry run, 30-day retention
    python3 scripts/purge_data.py --max-age-days 7
    python3 scripts/purge_data.py --store analyses
    python3 scripts/purge_data.py --max-age-days 90 --yes

Nothing is deleted without --yes; a bare run only reports what would go.

Age comes from file mtime, never from a ``created_at`` field inside the JSON, so a
malformed record can neither make itself immortal nor make anything else deletable.

Screenshots and quarantined samples travel with the record that owns them, so --store
scans still deletes the screenshots of the records it purges. A file whose record is
gone ("orphaned") is reported, and age-purged only when its own store is in scope.
With the submissions store missing entirely nothing in quarantine can be attributed,
so nothing there is treated as orphaned.

Submissions are a live review queue, so they carry one rule on top of ageing: a
submission still awaiting an operator decision (``pending`` or ``approved``) is never
purged, and neither are its quarantined bytes, however old. Purging those would gut a
submission awaiting approval, or leave an approval that can no longer be honoured;
they are reported instead. ``sent``, ``rejected`` and ``failed`` age out normally. A
month-old failed send is not a live decision, and holding its sample indefinitely is a
liability, so the retry it forfeits is the intended trade.

``status`` is the only thing ever read out of a record, it can only keep a file and
never condemn one, and a record that will not parse counts as awaiting a decision, so
the "content cannot make anything deletable" invariant above still holds.

An operator tool: deliberately not wired into the app, a cron, the Dockerfile, or
start.sh.
"""
import argparse
import json
import os
import re
import stat
import sys
from collections import namedtuple
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_MAX_AGE_DAYS = 30
DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent / 'data'

# data/phone_reports.db is deliberately absent from this tuple. These stores are
# directories of per-record files aged by mtime; the FTC store is one SQLite file whose
# rows carry their own dates, so it prunes itself inside scripts/ingest_ftc_dnc.py with
# the same --max-age-days flag. Adding it here would delete the whole store on its first
# birthday rather than trimming it.
STORES = ('scans', 'screenshots', 'analyses', 'submissions', 'quarantine', 'activity',
          'identity')

_UUID = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
RECORD_RE = re.compile(rf'^({_UUID})\.json$')
SHOT_RE = re.compile(rf'^({_UUID})(?:-([A-Za-z0-9_-]{{1,32}}))?\.png$')
# The submission id, not the digest, is the capture group: it is what links a quarantined
# sample to its record, and collect() keeps only group 1. Its own pattern rather than a
# loosened shared one, so adding this store does not widen what the other stores accept.
SAMPLE_RE = re.compile(rf'^[0-9a-f]{{64}}-({_UUID})\.bin$')
# One JSONL file per UTC day, with the day as the capture group so it doubles as the entry
# key. Its own pattern for the same reason as SAMPLE_RE: loosening RECORD_RE to admit a
# date would widen what every other store accepts.
ACTIVITY_RE = re.compile(r'^(\d{4}-\d{2}-\d{2})\.jsonl$')

# A submission in any other state (or in no state this script recognises) is still
# waiting for an operator and is kept regardless of age.
DECIDED_STATUSES = frozenset({'sent', 'rejected', 'failed'})

# `key` is what links a file to the record that owns it: the record's own UUID for
# the four uuid-named stores, and the owning submission's UUID for quarantine.
Entry = namedtuple('Entry', 'path key size mtime')


def fmt_bytes(n):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024 or unit == 'GB':
            return f'{n:.0f} {unit}' if unit == 'B' else f'{n:.1f} {unit}'
        n /= 1024.0


def fmt_time(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def awaiting_decision(path):
    """True when this submission record still needs an operator.

    Fails safe in every direction: an unreadable record, an unparseable one, and one
    carrying an unrecognised status all count as awaiting a decision, so the failure mode
    is retention rather than deletion.
    """
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
        record = json.loads(text)
        status = str(record.get('status', '')).strip().lower()
    except (OSError, ValueError, AttributeError):
        return True
    return status not in DECIDED_STATUSES


def collect(directory, pattern):
    """List the store's recognised files. Anything else comes back as 'unexpected' and is
    never touched: an unrecognised file is not assumed to be junk."""
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
    print(f'  {verb:<13} {len(doomed):>5} files  {fmt_bytes(d_bytes):>10}')
    print(f'  {"retained":<13} {len(retained):>5} files  {fmt_bytes(r_bytes):>10}', end='')
    if retained:
        mtimes = [e.mtime for e in retained]
        print(f'  oldest {fmt_time(min(mtimes))}  newest {fmt_time(max(mtimes))}')
    else:
        print()
    for note in notes:
        print(f'  {note}')

    shown = doomed if list_all else doomed[:20]
    for entry in shown:
        print(f'    - {entry.path.name}  {fmt_bytes(entry.size)}  {fmt_time(entry.mtime)}')
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
    subs, subs_unexpected = collect(dirs['submissions'], RECORD_RE)
    samples, samples_unexpected = collect(dirs['quarantine'], SAMPLE_RE)
    activity, activity_unexpected = collect(dirs['activity'], ACTIVITY_RE)
    identity, identity_unexpected = collect(dirs['identity'], RECORD_RE)

    record_uuids = {entry.key for entry in scans}

    doomed_scans = [e for e in scans if e.mtime < cutoff] if 'scans' in stores else []
    doomed_scan_ids = {e.key for e in doomed_scans}
    retained_scans = [e for e in scans if e.key not in doomed_scan_ids]

    # Screenshots travel with their record; orphans are age-purged on their own.
    doomed_shots = [e for e in shots if e.key in doomed_scan_ids]
    orphans = [e for e in shots if e.key not in record_uuids]
    if 'screenshots' in stores:
        doomed_shots += [e for e in orphans if e.mtime < cutoff]
    doomed_shot_paths = {e.path for e in doomed_shots}
    retained_shots = [e for e in shots if e.path not in doomed_shot_paths]
    retained_orphans = [e for e in orphans if e.path not in doomed_shot_paths]

    # The request log has no owning record, so it ages purely on mtime. activity.py's
    # per-day cap bounds a single file, not the directory, so without this sweep the store
    # grows without limit.
    doomed_activity = [e for e in activity if e.mtime < cutoff] if 'activity' in stores else []
    doomed_activity_paths = {e.path for e in doomed_activity}
    retained_activity = [e for e in activity if e.path not in doomed_activity_paths]

    doomed_analyses = [e for e in analyses if e.mtime < cutoff] if 'analyses' in stores else []
    doomed_analysis_ids = {e.key for e in doomed_analyses}
    retained_analyses = [e for e in analyses if e.key not in doomed_analysis_ids]

    # No owning record and no companion store, so identity results age purely on mtime,
    # like the activity log.
    doomed_identity = ([e for e in identity if e.mtime < cutoff]
                       if 'identity' in stores else [])
    doomed_identity_ids = {e.key for e in doomed_identity}
    retained_identity = [e for e in identity if e.key not in doomed_identity_ids]

    submission_uuids = {e.key for e in subs}
    undecided = {e.key for e in subs if awaiting_decision(e.path)}

    doomed_subs = ([e for e in subs if e.mtime < cutoff and e.key not in undecided]
                   if 'submissions' in stores else [])
    held_subs = [e for e in subs if e.mtime < cutoff and e.key in undecided]
    doomed_sub_ids = {e.key for e in doomed_subs}
    retained_subs = [e for e in subs if e.key not in doomed_sub_ids]

    # A quarantine directory with no submissions store to read against is
    # unattributable, so nothing in it is treated as orphaned.
    submissions_present = dirs['submissions'].is_dir()
    sample_orphans = ([e for e in samples if e.key not in submission_uuids]
                      if submissions_present else [])
    nominated = [e for e in samples if e.key in doomed_sub_ids]
    if 'quarantine' in stores:
        nominated += [e for e in samples
                      if e.mtime < cutoff and e.key in submission_uuids]
        nominated += [e for e in sample_orphans if e.mtime < cutoff]

    # The single choke point for the awaiting-decision rule: bytes a submission still
    # needs are never deleted, no matter which branch above nominated them.
    doomed_samples, doomed_sample_paths = [], set()
    for entry in nominated:
        if entry.key in undecided or entry.path in doomed_sample_paths:
            continue
        doomed_sample_paths.add(entry.path)
        doomed_samples.append(entry)
    held_samples = [e for e in samples if e.key in undecided]
    retained_samples = [e for e in samples if e.path not in doomed_sample_paths]
    retained_sample_orphans = [e for e in sample_orphans
                               if e.path not in doomed_sample_paths]

    mode = 'APPLY: files will be deleted' if args.apply else 'DRY RUN: nothing will be deleted'
    print(f'NexusTrace data purge  [{mode}]')
    print(f'  data directory : {data_dir}')
    print(f'  retention      : {args.max_age_days:g} days (cutoff {fmt_time(cutoff)})')
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

    sub_notes = []
    if held_subs:
        names = ', '.join(e.path.name for e in held_subs[:5])
        sub_notes.append(f'past retention but awaiting a decision (kept): '
                         f'{len(held_subs)}: {names}'
                         + (' ...' if len(held_subs) > 5 else ''))
    if doomed_sub_ids and 'quarantine' not in stores:
        sub_notes.append('quarantined samples of purged submissions are removed with '
                         'their record')

    sample_notes = []
    if samples and not submissions_present:
        sample_notes.append('submissions store absent, so nothing here can be attributed, '
                            'so nothing is treated as orphaned')
    if held_samples:
        sample_notes.append('held for a submission awaiting a decision (never purged): '
                            f'{len(held_samples)}')
    if sample_orphans and 'quarantine' in stores:
        sample_notes.append(f'orphaned (no submission record): {len(sample_orphans)}, '
                            f'{len(retained_sample_orphans)} still within retention')
    elif sample_orphans:
        sample_notes.append(f'orphaned (no submission record): {len(sample_orphans)} '
                            '(quarantine store not in scope, none age-purged)')

    report_store('scans      ', dirs['scans'], doomed_scans, retained_scans,
                 scans_unexpected, [], args.apply, args.list_all)
    report_store('screenshots', dirs['screenshots'], doomed_shots, retained_shots,
                 shots_unexpected, shot_notes, args.apply, args.list_all)
    report_store('analyses   ', dirs['analyses'], doomed_analyses, retained_analyses,
                 analyses_unexpected, [], args.apply, args.list_all)
    report_store('submissions', dirs['submissions'], doomed_subs, retained_subs,
                 subs_unexpected, sub_notes, args.apply, args.list_all)
    report_store('quarantine ', dirs['quarantine'], doomed_samples, retained_samples,
                 samples_unexpected, sample_notes, args.apply, args.list_all)
    report_store('activity   ', dirs['activity'], doomed_activity, retained_activity,
                 activity_unexpected, [], args.apply, args.list_all)
    report_store('identity   ', dirs['identity'], doomed_identity, retained_identity,
                 identity_unexpected, [], args.apply, args.list_all)

    total = (doomed_scans + doomed_shots + doomed_analyses + doomed_subs + doomed_samples
             + doomed_activity + doomed_identity)
    total_bytes = sum(e.size for e in total)
    print()
    if not args.apply:
        print(f'Dry run: {len(total)} files ({fmt_bytes(total_bytes)}) would be deleted. '
              'Re-run with --yes to apply.')
        return 0

    failures = 0
    freed = 0
    for entries, store_dir in ((doomed_scans, dirs['scans']),
                               (doomed_shots, dirs['screenshots']),
                               (doomed_analyses, dirs['analyses']),
                               (doomed_subs, dirs['submissions']),
                               (doomed_samples, dirs['quarantine']),
                               (doomed_activity, dirs['activity']),
                               (doomed_identity, dirs['identity'])):
        for entry in entries:
            try:
                remove(entry.path, store_dir)
                freed += entry.size
            except Exception as exc:
                failures += 1
                print(f'FAILED to delete {entry.path}: {exc}', file=sys.stderr)
    print(f'Deleted {len(total) - failures} files ({fmt_bytes(freed)}).')
    if failures:
        print(f'{failures} deletion(s) failed.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
