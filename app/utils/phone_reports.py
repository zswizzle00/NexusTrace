"""Local store of FTC Do Not Call complaints.

Pure leaf module: no Flask import, so `app/tests/test_phone_reports.py` runs it against
a temp file with no server.

**The web app never writes here.** Only `scripts/ingest_ftc_dnc.py` creates or populates
the database; the app opens it read-only and treats its absence as "no data", exactly as
a missing API key makes a provider card never render. Three things follow, and all three
are the reason for the rule:

- A missing database is unambiguous, rather than a half-initialised schema.
- Cloud Run, whose filesystem is per-instance tmpfs, degrades cleanly with no special
  casing.
- The app process needs no write access, so the systemd unit keeps a narrow
  `ReadWritePaths`.

Why this exists at all: SkipCalls is the phone surface's only reputation source and it
self-reported `last_updated: 2026-08-02` while missing 33 of 80 sampled numbers carrying
2026 FCC complaints. The FTC file is federal, public domain, published every business
day, and carries fields SkipCalls structurally cannot: dates, pitch subject, a robocall
flag and consumer state.
"""
import logging
import os
import sqlite3

logger = logging.getLogger(__name__)

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_PATH = os.environ.get('NEXUSTRACE_PHONE_DB') or os.path.join(_BASE, 'data', 'phone_reports.db')

MAX_SUBJECTS = 3

SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    phone           TEXT NOT NULL,
    created_date    TEXT NOT NULL,
    violation_date  TEXT,
    consumer_state  TEXT,
    subject         TEXT,
    robocall        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_reports_phone ON reports(phone);
CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_date);

-- What makes the ingest idempotent and resumable. The initial backfill is ~250 business
-- days; without this ledger an interrupted run would either duplicate rows or restart
-- from the beginning. A non-publishing day is recorded here with rows = 0, which is
-- what stops a backfill re-fetching every weekend on every run.
CREATE TABLE IF NOT EXISTS ingested_days (
    day          TEXT PRIMARY KEY,
    rows         INTEGER NOT NULL,
    ingested_at  TEXT NOT NULL
);
"""


def connect(path=None, write=False):
    """A connection, or None when the database is absent and we are not creating it."""
    target = path or DB_PATH
    if not write and not os.path.exists(target):
        return None
    if write:
        os.makedirs(os.path.dirname(target) or '.', exist_ok=True)
        connection = sqlite3.connect(target)
        connection.executescript(SCHEMA)
        return connection
    # Read-only, so a bug in the app cannot corrupt a store the ingest owns.
    try:
        return sqlite3.connect(f'file:{target}?mode=ro', uri=True)
    except sqlite3.Error as exc:
        logger.warning('Could not open the phone report store read-only: %s', exc)
        return None


def normalise(raw):
    """Digits only, NANP-normalised, or None when there is no usable number.

    The lookup key has to be stable regardless of the format an analyst typed, and the
    FTC file itself is inconsistent: most rows are bare 10-digit strings but some carry
    a leading country code. A number that is not 10 digits after stripping the NANP `1`
    is not usable as a key and is dropped rather than stored as a near-match.
    """
    digits = ''.join(c for c in str(raw or '') if c.isdigit())
    if len(digits) == 11 and digits.startswith('1'):
        digits = digits[1:]
    return digits if len(digits) == 10 else None


def reported_activity(national_number, path=None):
    """Complaint history for one number.

    Returns None **only when the database is absent**, which the template renders as no
    card at all. A number with no complaints returns a dict with `count: 0`, because the
    page has to be able to say that absence proves nothing, and it cannot say that if
    the card does not render. "We have no data" and "we have data and this number is not
    in it" are different claims.
    """
    key = normalise(national_number)
    if key is None:
        return None
    connection = connect(path)
    if connection is None:
        return None
    try:
        cursor = connection.execute(
            'SELECT COUNT(*), MIN(created_date), MAX(created_date),'
            '       SUM(robocall), COUNT(DISTINCT consumer_state)'
            '  FROM reports WHERE phone = ?', (key,))
        count, first_seen, last_seen, robocalls, states = cursor.fetchone()

        subjects = connection.execute(
            'SELECT subject, COUNT(*) AS n FROM reports'
            ' WHERE phone = ? AND subject IS NOT NULL AND subject != ""'
            ' GROUP BY subject ORDER BY n DESC LIMIT ?', (key, MAX_SUBJECTS)).fetchall()

        # The covered window comes from the ledger, not from the matched rows, so the
        # page can state the period actually covered rather than implying currency.
        window = connection.execute(
            'SELECT MIN(day), MAX(day) FROM ingested_days WHERE rows > 0').fetchone()
    except sqlite3.Error as exc:
        logger.warning('Phone report lookup failed: %s', exc)
        return None
    finally:
        connection.close()

    return {
        'count': count or 0,
        'first_seen': first_seen,
        'last_seen': last_seen,
        'robocall_count': robocalls or 0,
        'top_subjects': [(subject, n) for subject, n in subjects],
        'state_count': states or 0,
        'window_start': window[0] if window else None,
        'window_end': window[1] if window else None,
    }


def store_stats(path=None):
    """Row count and covered window, for the operator scripts and a freshness panel."""
    connection = connect(path)
    if connection is None:
        return None
    try:
        rows = connection.execute('SELECT COUNT(*) FROM reports').fetchone()[0]
        days, first, last = connection.execute(
            'SELECT COUNT(*), MIN(day), MAX(day) FROM ingested_days WHERE rows > 0'
        ).fetchone()
    except sqlite3.Error as exc:
        logger.warning('Phone report stats failed: %s', exc)
        return None
    finally:
        connection.close()
    return {'reports': rows, 'days': days, 'window_start': first, 'window_end': last}
