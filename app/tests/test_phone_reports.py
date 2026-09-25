"""The local FTC Do Not Call report store and its ingest.

Offline: every case builds its own database in a temp directory and injects a transport.
Nothing here fetches from ftc.gov.

The distinction this file exists to protect is three-way, and the three states must
never collapse into each other:

  reported_activity() -> None          the store has never been ingested
  reported_activity() -> count == 0    the store was checked, this number is not in it
  reported_activity() -> count  > 0    complaints name this number

Only the third is a finding. The first two look identical to a careless template and
mean completely different things, which is why the card renders all three differently.
"""
import os
import sys
import tempfile
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.utils import phone_reports
from scripts import ingest_ftc_dnc

failures = []
cases = 0

REPORTED_ROWS = ('8304319830,2026-09-20 01:00:00,,,Texas,830,Debt relief,Y\n',
                 '8304319830,2026-09-21 01:00:00,,,Ohio,830,Debt relief,Y\n')

HEADER = ('Company_Phone_Number,Created_Date,Violation_Date,Consumer_City,'
          'Consumer_State,Consumer_Area_Code,Subject,Recorded_Message_Or_Robocall\n')


def check(condition, message):
    global cases
    cases += 1
    if not condition:
        failures.append(message)
    return bool(condition)


def csv_for(rows):
    return HEADER + ''.join(rows)


class FakeResponse:
    def __init__(self, text='', status_code=200):
        self.text = text
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise AssertionError(f'raise_for_status called on {self.status_code}')


def transport_for(*responses):
    state = {'n': 0}

    def send(*_a, **_k):
        item = responses[min(state['n'], len(responses) - 1)]
        state['n'] += 1
        return item

    send.calls = state
    return send


# ------------------------------------------------------------------ normalise

def test_normalise_produces_a_stable_key():
    """The lookup key must not depend on the format an analyst typed, and the FTC file
    itself is inconsistent: mostly bare 10-digit strings, some with a country code."""
    for raw, want in (('8009423767', '8009423767'),
                      ('18009423767', '8009423767'),
                      ('800-942-3767', '8009423767'),
                      ('(800) 942 3767', '8009423767'),
                      ('', None), (None, None), ('abc', None),
                      ('12345', None), ('123456789012', None)):
        got = phone_reports.normalise(raw)
        check(got == want, f'normalise({raw!r}) -> {got!r}, expected {want!r}')


# ------------------------------------------------------------- the three states

def test_an_absent_store_is_none_not_zero():
    """None means "we have no data". Returning a zero-count record would make the page
    say "no complaints name this number", which is a claim we cannot support."""
    with tempfile.TemporaryDirectory() as box:
        missing = os.path.join(box, 'nope.db')
        check(phone_reports.reported_activity('8009423767', path=missing) is None,
              'an absent store did not return None')


def test_a_checked_but_unlisted_number_is_zero_not_none():
    """count == 0 means "we checked and it is not here", which the card must render,
    because the page has to say that absence proves nothing and it cannot say that if
    the card is missing."""
    with tempfile.TemporaryDirectory() as box:
        path = os.path.join(box, 'p.db')
        connection = phone_reports.connect(path, write=True)
        ingest_ftc_dnc.ingest_day(connection, '2026-09-22', True,
                                  transport=transport_for(FakeResponse(csv_for([
                                      '5551234567,2026-09-21 00:00:00,,,Texas,555,Other,Y\n']))))
        connection.close()
        result = phone_reports.reported_activity('2125559999', path=path)
        check(result is not None, 'a populated store returned None for an unlisted number')
        check(result and result['count'] == 0, f'expected count 0, got {result}')
        check(result and result['window_start'] == '2026-09-22',
              'the covered window was not reported for an unlisted number')


def test_a_reported_number_carries_its_detail():
    with tempfile.TemporaryDirectory() as box:
        path = os.path.join(box, 'p.db')
        connection = phone_reports.connect(path, write=True)
        ingest_ftc_dnc.ingest_day(connection, '2026-09-22', True,
                                  transport=transport_for(FakeResponse(csv_for([
                                      '8304319830,2026-09-20 01:00:00,,,Texas,830,Debt,Y\n',
                                      '8304319830,2026-09-21 01:00:00,,,Ohio,830,Debt,Y\n',
                                      '8304319830,2026-09-21 02:00:00,,,Ohio,830,Other,N\n']))))
        connection.close()
        r = phone_reports.reported_activity('830-431-9830', path=path)
        check(r['count'] == 3, f'count wrong: {r["count"]}')
        check(r['robocall_count'] == 2, f'robocall_count wrong: {r["robocall_count"]}')
        check(r['state_count'] == 2, f'state_count wrong: {r["state_count"]}')
        check(r['first_seen'] == '2026-09-20' and r['last_seen'] == '2026-09-21',
              f'date range wrong: {r["first_seen"]}..{r["last_seen"]}')
        check(r['top_subjects'] and r['top_subjects'][0] == ('Debt', 2),
              f'top_subjects wrong: {r["top_subjects"]}')


# ------------------------------------------------------------------- ingest

def test_rows_without_a_usable_number_are_dropped():
    """About 4% of rows carry no caller number and a handful carry 3-to-9-digit
    fragments. Stored, a fragment becomes a row that can never be looked up."""
    rows = ingest_ftc_dnc.parse_csv(csv_for([
        ',2026-09-21 00:00:00,,,Texas,555,Other,Y\n',          # no number
        '911,2026-09-21 00:00:00,,,Texas,555,Other,Y\n',       # fragment
        '5555555555,2026-09-21 00:00:00,,,Texas,555,Other,Y\n',  # sentinel
        '8009423767,,,,Texas,800,Other,Y\n',                   # no created date
        '8009423767,2026-09-21 00:00:00,,,Texas,800,Other,Y\n',  # the only good row
    ]))
    check(len(rows) == 1, f'expected 1 usable row, got {len(rows)}: {rows}')
    check(rows and rows[0][0] == '8009423767', f'wrong row survived: {rows}')


def test_a_404_is_a_non_publishing_day_not_a_failure():
    """The FTC publishes on business days only, so a 404 is the normal weekend outcome.
    Recording it is what stops a backfill re-fetching every weekend on every run."""
    with tempfile.TemporaryDirectory() as box:
        path = os.path.join(box, 'p.db')
        connection = phone_reports.connect(path, write=True)
        count, published, skipped = ingest_ftc_dnc.ingest_day(
            connection, '2026-09-20', True, transport=transport_for(FakeResponse(status_code=404)))
        check(published is False, 'a 404 was reported as published')
        check(skipped is False, 'a 404 was treated as an error rather than an answer')
        check(count == 0, f'a 404 produced {count} rows')
        connection.close()


def test_a_day_is_ingested_once():
    """Without the ledger an interrupted backfill would either duplicate every row or
    restart from the beginning."""
    with tempfile.TemporaryDirectory() as box:
        path = os.path.join(box, 'p.db')
        connection = phone_reports.connect(path, write=True)
        body = FakeResponse(csv_for(['8009423767,2026-09-21 00:00:00,,,Texas,800,Other,Y\n']))
        send = transport_for(body)
        ingest_ftc_dnc.ingest_day(connection, '2026-09-22', True, transport=send)
        count, _published, skipped = ingest_ftc_dnc.ingest_day(
            connection, '2026-09-22', True, transport=send)
        check(skipped is True, 'a day already in the ledger was re-fetched')
        check(count == 0, f'the repeat ingest inserted {count} rows')
        total = connection.execute('SELECT COUNT(*) FROM reports').fetchone()[0]
        check(total == 1, f'the row was duplicated: {total} rows')
        connection.close()


def test_force_day_replaces_rather_than_duplicates():
    with tempfile.TemporaryDirectory() as box:
        path = os.path.join(box, 'p.db')
        connection = phone_reports.connect(path, write=True)
        body = FakeResponse(csv_for(['8009423767,2026-09-22 00:00:00,,,Texas,800,Other,Y\n']))
        ingest_ftc_dnc.ingest_day(connection, '2026-09-22', True, transport=transport_for(body))
        ingest_ftc_dnc.ingest_day(connection, '2026-09-22', True, force=True,
                                  transport=transport_for(body))
        total = connection.execute('SELECT COUNT(*) FROM reports').fetchone()[0]
        check(total == 1, f'--force-day duplicated rows: {total}')
        connection.close()


def test_prune_bounds_the_store():
    with tempfile.TemporaryDirectory() as box:
        path = os.path.join(box, 'p.db')
        connection = phone_reports.connect(path, write=True)
        connection.execute("INSERT INTO reports VALUES ('8009423767','2000-01-01',NULL,NULL,NULL,0,'2000-01-01')")
        connection.execute("INSERT INTO ingested_days VALUES ('2000-01-01',1,'x')")
        connection.commit()
        doomed, _cutoff = ingest_ftc_dnc.prune(connection, 365, True)
        check(doomed == 1, f'prune reported {doomed} doomed rows, expected 1')
        left = connection.execute('SELECT COUNT(*) FROM reports').fetchone()[0]
        check(left == 0, f'{left} row(s) survived the retention window')
        days = connection.execute('SELECT COUNT(*) FROM ingested_days').fetchone()[0]
        check(days == 0, 'the ledger entry outlived its rows, so the day can never re-ingest')
        connection.close()


# A file holds every complaint since the previous file, measured against ftc.gov on
# 2026-09-25: the Wednesday file carried only Tuesday, the Monday file carried Friday,
# Saturday and Sunday. No row's created_date equals its own file's day. Fixtures where
# they are equal are what let the created_date-keyed version pass.
MONDAY_FILE = ('8009423767,2026-09-18 09:00:00,,,Texas,800,Other,Y\n',
               '8009423767,2026-09-19 09:00:00,,,Texas,800,Other,Y\n',
               '8009423767,2026-09-20 09:00:00,,,Texas,800,Other,Y\n')
TUESDAY_FILE = ('8009423767,2026-09-21 09:00:00,,,Ohio,800,Other,N\n',
                '8009423767,2026-09-21 10:00:00,,,Ohio,800,Other,N\n')


def _store_with_two_real_shaped_files(box):
    path = os.path.join(box, 'p.db')
    connection = phone_reports.connect(path, write=True)
    ingest_ftc_dnc.ingest_day(connection, '2026-09-21', True,
                              transport=transport_for(FakeResponse(csv_for(MONDAY_FILE))))
    ingest_ftc_dnc.ingest_day(connection, '2026-09-22', True,
                              transport=transport_for(FakeResponse(csv_for(TUESDAY_FILE))))
    return connection


def _rows_by_file(connection):
    return dict(connection.execute(
        'SELECT file_day, COUNT(*) FROM reports GROUP BY file_day').fetchall())


def test_force_day_touches_only_its_own_file():
    """Keyed on created_date, re-fetching Monday deleted Tuesday's rows (created on
    Monday) and duplicated Monday's own (created Friday to Sunday), inflating the count
    an analyst sees."""
    with tempfile.TemporaryDirectory() as box:
        connection = _store_with_two_real_shaped_files(box)
        for day, body in (('2026-09-21', MONDAY_FILE), ('2026-09-22', TUESDAY_FILE)):
            ingest_ftc_dnc.ingest_day(connection, day, True, force=True,
                                      transport=transport_for(FakeResponse(csv_for(body))))
            by_file = _rows_by_file(connection)
            check(by_file == {'2026-09-21': 3, '2026-09-22': 2},
                  f'--force-day {day} disturbed other files or duplicated: {by_file}')
        connection.close()


def test_prune_keeps_the_oldest_file_inside_the_window():
    """Keyed on created_date, a backfill's oldest file was pruned the moment it landed,
    because every row in it predates its own file day, while its ledger entry survived
    claiming rows the store no longer held."""
    with tempfile.TemporaryDirectory() as box:
        connection = _store_with_two_real_shaped_files(box)
        age = (date.today() - date(2026, 9, 21)).days
        doomed, cutoff = ingest_ftc_dnc.prune(connection, age, True)
        check(cutoff == '2026-09-21', f'fixture is wrong: cutoff {cutoff}')
        check(doomed == 0, f'prune doomed {doomed} rows from a file inside the window')
        check(_rows_by_file(connection) == {'2026-09-21': 3, '2026-09-22': 2},
              'a file inside the retention window lost rows')

        doomed, _cutoff = ingest_ftc_dnc.prune(connection, age - 1, True)
        check(doomed == 3, f'expected the Monday file\'s 3 rows doomed, got {doomed}')
        check(_rows_by_file(connection) == {'2026-09-22': 2},
              f'rows and file did not age out together: {_rows_by_file(connection)}')
        ledger = [d for (d,) in connection.execute('SELECT day FROM ingested_days')]
        check(ledger == ['2026-09-22'], f'the ledger disagrees with the rows: {ledger}')
        connection.close()


def test_prune_forgets_old_non_publishing_days():
    """A weekend has a ledger entry and no rows, so a prune that only acts when rows
    are doomed would keep every old weekend forever."""
    with tempfile.TemporaryDirectory() as box:
        connection = phone_reports.connect(os.path.join(box, 'p.db'), write=True)
        ingest_ftc_dnc.record_day(connection, '2000-01-01', 0)
        connection.commit()
        doomed, _cutoff = ingest_ftc_dnc.prune(connection, 365, True)
        days = connection.execute('SELECT COUNT(*) FROM ingested_days').fetchone()[0]
        check(doomed == 0 and days == 0, f'an old weekend outlived the window: {days}')
        connection.close()


def test_a_legacy_store_is_refused_for_writing_but_still_read():
    """A store built before file_day cannot be migrated exactly. Writing to it must be
    refused, and the app must keep serving lookups from it until it is rebuilt."""
    import sqlite3
    with tempfile.TemporaryDirectory() as box:
        path = os.path.join(box, 'p.db')
        legacy = sqlite3.connect(path)
        legacy.executescript(
            'CREATE TABLE reports (phone TEXT NOT NULL, created_date TEXT NOT NULL,'
            ' violation_date TEXT, consumer_state TEXT, subject TEXT,'
            ' robocall INTEGER NOT NULL DEFAULT 0);'
            'CREATE TABLE ingested_days (day TEXT PRIMARY KEY, rows INTEGER NOT NULL,'
            ' ingested_at TEXT NOT NULL);'
            "INSERT INTO reports VALUES ('8009423767','2026-09-21',NULL,'Ohio',NULL,1);"
            "INSERT INTO ingested_days VALUES ('2026-09-22',1,'x');")
        legacy.commit()
        legacy.close()
        try:
            phone_reports.connect(path, write=True)
            failures.append('a legacy store was opened for writing')
        except phone_reports.LegacyStoreError:
            check(True, 'legacy store refused')
        result = phone_reports.reported_activity('8009423767', path=path)
        check(result is not None and result['count'] == 1,
              f'a legacy store stopped serving lookups: {result}')


def test_the_app_opens_the_store_read_only():
    """Only the ingest writes. A bug in a request must not be able to corrupt a store
    the operator owns."""
    with tempfile.TemporaryDirectory() as box:
        path = os.path.join(box, 'p.db')
        phone_reports.connect(path, write=True).close()
        connection = phone_reports.connect(path)
        try:
            connection.execute("INSERT INTO reports VALUES ('1','2','3','4','5',0,'6')")
            failures.append('the app-side connection accepted a write')
        except Exception:
            pass
        check(True, 'read-only connection rejects writes')
        connection.close()



# ------------------------------------------------------------------ rendering

def _ftc_card(body):
    """Just the FTC card. Scoping matters: the SkipCalls card above it is titled
    "Reported spam", so a page-wide search for "Reported" matches whatever the FTC card
    says. An unscoped version of the assertion below passed on a zero-count page."""
    start = body.find('FTC complaints')
    if start == -1:
        return ''
    end = body.find('</div>', body.find('Local data covering', start))
    return body[start:end if end != -1 else len(body)]


def _render(number, rows=()):
    """Render the page against a store this test builds, never the developer's own.

    `phone_reports.DB_PATH` is read at import, so it is patched rather than set through
    the environment. Without this the rendering cases would pass only on a machine that
    happens to have run the ingest, which is worse than having no test: it would go
    green locally and fail on a fresh checkout.

    `live=False` keeps LocalCallingGuide and SkipCalls off the wire; the FTC lookup is
    local and runs regardless.
    """
    import tempfile
    from app import create_app
    from app.services import phone_service

    with tempfile.TemporaryDirectory() as box:
        path = os.path.join(box, 'p.db')
        connection = phone_reports.connect(path, write=True)
        if rows:
            ingest_ftc_dnc.ingest_day(connection, '2026-09-22', True,
                                      transport=transport_for(FakeResponse(csv_for(rows))))
        else:
            ingest_ftc_dnc.record_day(connection, '2026-09-22', 0)
            connection.commit()
        connection.close()

        original = phone_reports.DB_PATH
        phone_reports.DB_PATH = path
        try:
            app = create_app()
            report = phone_service.build_report(number, live=False)
            report['reports'] = phone_reports.reported_activity(
                (report.get('offline') or {}).get('national_number') or number)
            with app.test_request_context('/'):
                return app.jinja_env.get_template('phone_analysis.html').render(
                    report=report, submitted=number)
        finally:
            phone_reports.DB_PATH = original


def test_a_zero_count_card_never_reads_as_exoneration():
    """The card has to render for an unlisted number, because the page has to say that
    absence proves nothing. Rendering it without that caveat would be worse than not
    rendering it at all."""
    card = _ftc_card(_render('+12125559999'))
    if not check(card, 'the FTC card did not render for a number with no complaints'):
        return
    check('No FTC complaints name this number' in card, 'the empty state is missing')
    check('not a clean result' in card, 'the empty card has no caveat and reads as clean')
    check('voluntary' in card, 'the caveat does not say why absence proves nothing')
    check('Reported' not in card, 'the empty card claimed a complaint count')


def test_a_reported_number_shows_a_count_and_never_a_verdict():
    card = _ftc_card(_render('+18304319830', rows=REPORTED_ROWS))
    if not check(card, 'the FTC card did not render for a reported number'):
        return
    check('Reported' in card, 'the count is missing')
    check('does not verify' in card,
          'the card omits the FTC caveat about unverified complaints')
    for verdict in ('malicious', 'suspicious', 'Malicious', 'Suspicious', 'score'):
        check(verdict not in card,
              f'the FTC card rendered a verdict word: {verdict!r}. It reports a count.')


def test_the_card_states_the_window_it_covers():
    """From the ingest ledger, not the matched rows, so an analyst can see whether the
    store is current rather than assuming it. A stale store is the exact failure this
    feature exists to fix."""
    card = _ftc_card(_render('+18304319830', rows=REPORTED_ROWS))
    check('Local data covering' in card, 'the covered window is not stated')


def main():
    test_normalise_produces_a_stable_key()
    test_an_absent_store_is_none_not_zero()
    test_a_checked_but_unlisted_number_is_zero_not_none()
    test_a_reported_number_carries_its_detail()
    test_rows_without_a_usable_number_are_dropped()
    test_a_404_is_a_non_publishing_day_not_a_failure()
    test_a_day_is_ingested_once()
    test_force_day_replaces_rather_than_duplicates()
    test_prune_bounds_the_store()
    test_force_day_touches_only_its_own_file()
    test_prune_keeps_the_oldest_file_inside_the_window()
    test_prune_forgets_old_non_publishing_days()
    test_a_legacy_store_is_refused_for_writing_but_still_read()
    test_the_app_opens_the_store_read_only()
    test_a_zero_count_card_never_reads_as_exoneration()
    test_a_reported_number_shows_a_count_and_never_a_verdict()
    test_the_card_states_the_window_it_covers()

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {cases} cases')


if __name__ == '__main__':
    main()
