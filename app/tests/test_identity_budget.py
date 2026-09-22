"""Pins the deadline and the concurrency cap in app/services/identity_service.py.

No vendor engine and no network: a fake worker script stands in, so a case can sleep
deliberately. The assertions are on OUTCOMES, per tasks/lessons.md (2026-07-28,
"Verification that checks the wrong signal"): that the child process is gone, that a
partial result came back, and that the unfinished engine is marked timed out. Asserting
that a deadline variable was set would pass while the process kept running.
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.services import identity_service

failures = []
cases = 0


def check(condition, message):
    global cases
    cases += 1
    if not condition:
        failures.append(message)
    return bool(condition)


SLOW_WORKER = '''
import json, sys, time
time.sleep(30)
json.dump({"target": "x", "mode": "username", "engines": {}}, sys.stdout)
'''

FAST_WORKER = '''
import json, sys
json.dump({"target": "alice", "mode": "username", "engines": {
    "sherlock": {"status": "ok", "findings": [
        {"site_name": "GitHub", "status": "CLAIMED", "url_user": "https://github.com/alice"}]},
    "user-scanner": {"status": "ok", "findings": [
        {"site_name": "GitHub", "status": "TAKEN", "url": "https://github.com/alice",
         "category": "dev"}]}}}, sys.stdout)
'''

CRASHING_WORKER = '''
import sys
sys.stderr.write("boom")
sys.exit(3)
'''


def _worker(source):
    handle = tempfile.NamedTemporaryFile('w', suffix='.py', delete=False)
    handle.write(source)
    handle.close()
    return [sys.executable, handle.name]


def test_slow_worker_is_killed_and_reported_as_timed_out():
    """`worker_pid` has no value to a reader of the finished record and is not part of
    what gets persisted, so the pid is captured here by wrapping Popen rather than by
    reading it back off the result."""
    argv = _worker(SLOW_WORKER)
    pids = []
    original_popen = identity_service.subprocess.Popen

    def capturing_popen(*args, **kwargs):
        proc = original_popen(*args, **kwargs)
        pids.append(proc.pid)
        return proc

    identity_service.subprocess.Popen = capturing_popen
    try:
        started = time.monotonic()
        result = identity_service.run_identity_scan(
            'alice', budget=3, worker_argv=argv, breach_lookup=lambda *a, **k: None)
        elapsed = time.monotonic() - started
    finally:
        identity_service.subprocess.Popen = original_popen

    check(elapsed < 15, f'the budget was not enforced: took {elapsed:.1f}s for a 3s budget')
    check(result.get('timed_out') is True,
          f'timed_out={result.get("timed_out")!r}, expected True')
    check('worker_pid' not in result,
          'worker_pid was persisted into the stored record')

    # The outcome that matters: no orphan left behind.
    if check(pids, 'the worker pid was never captured'):
        pid = pids[0]
        alive = True
        for _ in range(20):
            try:
                os.kill(pid, 0)
            except OSError:
                alive = False
                break
            time.sleep(0.1)
        check(not alive, f'the worker process {pid} survived the deadline')


def test_fast_worker_produces_merged_findings():
    argv = _worker(FAST_WORKER)
    result = identity_service.run_identity_scan(
        'alice', budget=30, worker_argv=argv, breach_lookup=lambda *a, **k: None)

    check(result.get('timed_out') is False, 'a fast worker was reported as timed out')
    rows = result.get('findings') or []
    check(len(rows) == 1, f'the two engines were not merged: {len(rows)} rows')
    if rows:
        check(sorted(rows[0]['engines']) == ['sherlock', 'user-scanner'],
              f'corroboration lost: {rows[0]["engines"]!r}')
    check(result['summary']['corroborated'] == 1,
          f'summary corroborated={result["summary"]["corroborated"]!r}, expected 1')


def test_crashing_worker_is_an_error_not_an_exception():
    argv = _worker(CRASHING_WORKER)
    try:
        result = identity_service.run_identity_scan(
            'alice', budget=10, worker_argv=argv, breach_lookup=lambda *a, **k: None)
    except Exception as exc:  # noqa: BLE001 - reported below
        failures.append(f'a crashing worker raised {exc!r} instead of returning a result')
        return
    check(result.get('error'), 'a crashing worker produced no error marker')
    check(result.get('findings') == [], 'a crashing worker produced findings')


def test_hudson_runs_in_the_parent_and_survives_a_dead_worker():
    """Hudson Rock is a single fast request under our own limiter and has nothing to do
    with the engines, so a killed worker must still yield breach data."""
    argv = _worker(SLOW_WORKER)
    result = identity_service.run_identity_scan(
        'alice', budget=3, worker_argv=argv,
        breach_lookup=lambda *a, **k: {'exposed': True, 'count': 1, 'infections': [],
                                       'source': 'Hudson Rock'})
    check(result.get('timed_out') is True, 'expected the slow worker to time out')
    check((result.get('breach') or {}).get('exposed') is True,
          'breach data was lost when the worker was killed')


def test_concurrency_cap_rejects_the_third_scan():
    argv = _worker(SLOW_WORKER)
    errors = []
    busy = []

    def attempt():
        try:
            identity_service.run_identity_scan(
                'alice', budget=4, worker_argv=argv, breach_lookup=lambda *a, **k: None)
        except identity_service.ScannerBusy:
            busy.append(1)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=attempt) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    check(not errors, f'unexpected exceptions from concurrent scans: {errors}')
    check(busy, 'the third concurrent scan was not rejected; the cap does not hold')


# A worker whose OWN child inherits the stdout pipe and outlives it. This is the
# realistic vendor shape, because both engines use thread and process pools. The
# grandchild's pid is written to a path the test supplies, so the test can confirm
# afterward that the grandchild is actually dead, not just that the call returned in
# time: elapsed time alone does not catch a group-kill that silently degrades to
# killing only the direct child, since the drain grace period bounds the wait either
# way.
GRANDCHILD_WORKER = '''
import subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
# The grandchild inherits this process's stdout, so killing only the direct child leaves
# the pipe open and an unbounded read blocks until the grandchild exits.
with open({pidfile!r}, "w") as handle:
    handle.write(str(child.pid))
time.sleep(0.5)
'''


def test_a_surviving_grandchild_cannot_breach_the_budget():
    """The deadline has to hold against the realistic vendor shape, not just against
    a single sleeping process. Before the process group was killed, a grandchild
    sleeping 20 seconds breached a 2 second budget by 18 and pinned the calling
    thread for the whole time."""
    pidfile = tempfile.NamedTemporaryFile('w', suffix='.pid', delete=False).name
    argv = _worker(GRANDCHILD_WORKER.format(pidfile=pidfile))
    started = time.monotonic()
    result = identity_service.run_identity_scan(
        'alice', budget=3, worker_argv=argv, breach_lookup=lambda *a, **k: None)
    elapsed = time.monotonic() - started

    check(elapsed < 12,
          f'a surviving grandchild held the call for {elapsed:.1f}s against a 3s '
          f'budget; the deadline does not hold')
    check(result.get('timed_out') is True,
          f'timed_out={result.get("timed_out")!r}, expected True')

    # The outcome that actually matters: the grandchild, not just the direct child,
    # is gone. Elapsed time alone would pass even if the group kill silently fell
    # back to killing only the worker, because the bounded drain still lets the call
    # return on schedule while the grandchild keeps running in the background.
    for _ in range(20):
        if os.path.exists(pidfile):
            break
        time.sleep(0.1)
    if check(os.path.exists(pidfile), 'the grandchild never reported its pid'):
        with open(pidfile) as handle:
            grandchild_pid = int(handle.read().strip())
        alive = True
        for _ in range(20):
            try:
                os.kill(grandchild_pid, 0)
            except OSError:
                alive = False
                break
            time.sleep(0.1)
        check(not alive,
              f'the grandchild {grandchild_pid} survived the deadline; only the '
              f'direct child was killed')


def main():
    test_slow_worker_is_killed_and_reported_as_timed_out()
    test_fast_worker_produces_merged_findings()
    test_crashing_worker_is_an_error_not_an_exception()
    test_hudson_runs_in_the_parent_and_survives_a_dead_worker()
    test_concurrency_cap_rejects_the_third_scan()
    test_a_surviving_grandchild_cannot_breach_the_budget()

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {cases} cases')


if __name__ == '__main__':
    main()
