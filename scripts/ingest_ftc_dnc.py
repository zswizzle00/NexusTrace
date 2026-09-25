#!/usr/bin/env python3
"""Ingest FTC Do Not Call complaint files into the local report store.

The FTC publishes a CSV of consumer complaints every business day, in the US public
domain with no restriction on caching or redistribution. Ingested locally it gives
unlimited reported-call history with better provenance than SkipCalls, and the lookup
then contacts nobody: no third party learns which number is being investigated.

Dry run is the default, matching scripts/purge_data.py. --yes is what writes.

    uv run python scripts/ingest_ftc_dnc.py                      # yesterday, dry run
    uv run python scripts/ingest_ftc_dnc.py --yes                # yesterday, apply
    uv run python scripts/ingest_ftc_dnc.py --backfill-days 365 --yes
    uv run python scripts/ingest_ftc_dnc.py --force-day 2026-09-22 --yes
    uv run python scripts/ingest_ftc_dnc.py --prune-only --yes
"""
import argparse
import csv
import io
import logging
import os
import sys
import time
from datetime import date, datetime, timedelta, timezone

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.utils.phone_reports import DB_PATH, connect, normalise, store_stats  # noqa: E402

logger = logging.getLogger('ingest_ftc_dnc')

URL = 'https://www.ftc.gov/sites/default/files/DNC_Complaint_Numbers_{day}.csv'

# ftc.gov returns 403 to a default requests User-Agent and 200 to a browser-like one.
# Verified 2026-09-24, and again at design time. This is the single most likely cause of
# a silent ingest failure, so it lives in the code rather than being rediscovered.
HEADERS = {
    'User-Agent': ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
                   '(KHTML, like Gecko) Chrome/120.0 Safari/537.36'),
    'Accept': 'text/csv,*/*',
}

TIMEOUT = 60
REQUEST_INTERVAL = 1.0      # a backfill is ~250 requests against a public service
DEFAULT_MAX_AGE_DAYS = 365  # named to match purge_data.py, so an operator meets one flag

# Placeholders that appear instead of a caller number. Stored, they would become a
# "most reported number" that is really an artefact of the reporting form.
SENTINELS = frozenset({'0000000000', '5555555555', '1111111111', '9999999999',
                       '1234567890', '0123456789'})


def fetch_day(day, transport=None):
    """`(rows, published)`. A 404 means the FTC did not publish that day, which is the
    normal outcome for weekends and holidays and is NOT an error."""
    response = (transport or requests.get)(URL.format(day=day), headers=HEADERS,
                                           timeout=TIMEOUT)
    if response.status_code == 404:
        return [], False
    response.raise_for_status()
    return parse_csv(response.text), True


def parse_csv(text):
    """Usable rows only. Roughly 4% of rows carry no caller number at all, and a further
    handful carry fragments of 3 to 9 digits; both are dropped rather than stored as a
    near-match that would never be looked up."""
    rows = []
    for row in csv.DictReader(io.StringIO(text)):
        phone = normalise(row.get('Company_Phone_Number'))
        if phone is None or phone in SENTINELS:
            continue
        created = (row.get('Created_Date') or '').strip()
        if not created:
            continue
        rows.append((
            phone,
            created[:10],
            (row.get('Violation_Date') or '').strip()[:10] or None,
            (row.get('Consumer_State') or '').strip() or None,
            (row.get('Subject') or '').strip() or None,
            1 if (row.get('Recorded_Message_Or_Robocall') or '').strip().upper() == 'Y' else 0,
        ))
    return rows


def already_done(connection, day):
    return connection.execute('SELECT 1 FROM ingested_days WHERE day = ?',
                              (day,)).fetchone() is not None


def record_day(connection, day, count):
    connection.execute(
        'INSERT OR REPLACE INTO ingested_days (day, rows, ingested_at) VALUES (?, ?, ?)',
        (day, count, datetime.now(timezone.utc).isoformat(timespec='seconds')))


def ingest_day(connection, day, apply_changes, force=False, transport=None):
    """`(count, published, skipped)`."""
    if not force and already_done(connection, day):
        return 0, False, True
    try:
        rows, published = fetch_day(day, transport=transport)
    except requests.RequestException as exc:
        logger.error('%s: fetch failed: %s', day, exc)
        return 0, False, True

    if apply_changes:
        if force:
            connection.execute('DELETE FROM reports WHERE created_date = ?', (day,))
        connection.executemany(
            'INSERT INTO reports (phone, created_date, violation_date, consumer_state,'
            ' subject, robocall) VALUES (?, ?, ?, ?, ?, ?)', rows)
        record_day(connection, day, len(rows))
        connection.commit()
    return len(rows), published, False


def prune(connection, max_age_days, apply_changes):
    """Delete rows past the retention window and forget their ledger entries, so the
    store is self-bounding rather than growing without limit."""
    cutoff = (date.today() - timedelta(days=max_age_days)).isoformat()
    doomed = connection.execute('SELECT COUNT(*) FROM reports WHERE created_date < ?',
                                (cutoff,)).fetchone()[0]
    if apply_changes and doomed:
        connection.execute('DELETE FROM reports WHERE created_date < ?', (cutoff,))
        connection.execute('DELETE FROM ingested_days WHERE day < ?', (cutoff,))
        connection.commit()
    return doomed, cutoff


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--yes', action='store_true',
                        help='apply changes; without it this is a dry run')
    parser.add_argument('--backfill-days', type=int, default=1,
                        help='how many days back to ingest (default 1)')
    parser.add_argument('--force-day', metavar='YYYY-MM-DD',
                        help='re-fetch one day regardless of the ledger')
    parser.add_argument('--prune-only', action='store_true')
    parser.add_argument('--max-age-days', type=int, default=DEFAULT_MAX_AGE_DAYS)
    parser.add_argument('--db', default=DB_PATH)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    connection = connect(args.db, write=True)

    if not args.yes:
        print('DRY RUN. Nothing will be written. Pass --yes to apply.\n')

    total = skipped = unpublished = 0
    if not args.prune_only:
        days = ([args.force_day] if args.force_day
                else [(date.today() - timedelta(days=n)).isoformat()
                      for n in range(1, args.backfill_days + 1)])
        for index, day in enumerate(days):
            if index:
                time.sleep(REQUEST_INTERVAL)
            count, published, was_skipped = ingest_day(
                connection, day, args.yes, force=bool(args.force_day))
            if was_skipped:
                skipped += 1
            elif not published:
                unpublished += 1
                if args.yes:
                    record_day(connection, day, 0)
                    connection.commit()
                print(f'  {day}  not published (weekend or holiday)')
            else:
                total += count
                print(f'  {day}  {count} usable rows')

    doomed, cutoff = prune(connection, args.max_age_days, args.yes)
    stats = store_stats(args.db) or {}
    connection.close()

    print(f'\ningested {total} rows, {skipped} day(s) already done, '
          f'{unpublished} non-publishing day(s)')
    print(f'pruned {doomed} row(s) older than {cutoff}')
    if stats:
        print(f'store now holds {stats["reports"]} reports across {stats["days"]} day(s), '
              f'{stats["window_start"]} to {stats["window_end"]}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
