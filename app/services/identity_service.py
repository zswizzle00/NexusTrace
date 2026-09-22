"""Spawns the identity worker, enforces the deadline and the concurrency cap, and
assembles the record.

**The budget is 70 seconds** because two ceilings sit above it. Cloudflare gives up at
roughly 100 seconds and serves a 524, and the Dockerfile runs gunicorn with
--timeout 120. Under --worker-class gthread a timeout kills the WHOLE worker, taking
every other in-flight request with it, so the margin protects other users rather than
this one.

**The cap is 2 concurrent scans** because each one is well over a thousand outbound
requests. Without a cap, a handful of browser tabs would saturate all 8 gunicorn threads
and fire tens of thousands of requests from one origin IP.

Hudson Rock runs HERE, not in the worker. It is one fast request under our own rate
limiter with nothing to do with the vendor engines, and keeping it in the parent means a
killed worker still yields breach data.

The worker is killed by process group, not by PID, because both vendor engines use
thread and process pools: `proc.kill()` reaches only the direct child, and a surviving
grandchild that inherited the stdout pipe leaves the following read blocked until it
exits on its own, which defeats the budget. `start_new_session=True` and `os.killpg`
are POSIX only; that is acceptable because this app runs on Linux containers and macOS
development, and this worker is spawned only by this service.
"""

import json
import logging
import os
import signal
import subprocess
import sys
import threading

from ..utils.identity_findings import (merge, normalize_sherlock,
                                       normalize_user_scanner, summarize)
from . import hudson

logger = logging.getLogger(__name__)

BUDGET_SECONDS = 70
MAX_CONCURRENT = 2

# After the group is killed, how long to wait for whatever it already wrote. The
# second read has to be bounded: an unbounded one is exactly what let a surviving
# grandchild hold the request thread past the budget.
DRAIN_SECONDS = 5

_slots = threading.BoundedSemaphore(MAX_CONCURRENT)

WORKER_ARGV = [sys.executable, '-m', 'app.tools.identity_worker']


class ScannerBusy(RuntimeError):
    """Raised when both scan slots are taken. The route turns this into a flash message,
    not a 500 and not a queue: an analyst would rather be told to retry than wait behind
    two minute-long scans."""


def _findings_from(payload):
    findings = []
    engines = (payload or {}).get('engines') or {}

    sherlock = engines.get('sherlock') or {}
    for entry in sherlock.get('findings') or ():
        findings.append(normalize_sherlock(entry.get('site_name'), entry))

    scanner = engines.get('user-scanner') or {}
    for entry in scanner.get('findings') or ():
        findings.append(normalize_user_scanner(entry))

    return findings, {name: (engines.get(name) or {}).get('status', 'error')
                      for name in ('sherlock', 'user-scanner')}


def _kill_worker_group(proc):
    """SIGKILL the worker's whole process group, not just the worker.

    proc.kill() reaches the direct child only. Both vendor engines use thread and
    process pools, so a grandchild can outlive it while still holding the stdout
    pipe, and the read that follows then blocks until that grandchild exits.
    Measured before this existed: a grandchild sleeping 20 seconds defeated a 2
    second budget by 18, which turns the deadline into a suggestion and pins a
    gunicorn thread for the duration.

    The process group id is `proc.pid` itself, not a value looked up with
    `os.getpgid(proc.pid)`. Looking it up races against the realistic case: the
    worker is typically the SHORT-LIVED one (it spawns the pool and returns), so by
    the time the budget expires the worker has usually already exited and been
    reaped, and `os.getpgid` on that pid then raises ProcessLookupError even though
    the group, and the grandchild inside it, are still very much alive. Because the
    worker is spawned with `start_new_session=True`, POSIX guarantees its process
    group id equals its own pid at creation, and that id stays valid for `killpg`
    for as long as any member of the group remains, regardless of whether the
    worker itself is still one of them.
    """
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except Exception:
        # No such group left to signal. The direct child is still worth killing,
        # and a failure here must not mask the timeout being reported.
        try:
            proc.kill()
        except Exception:
            pass


def _drain(proc, grace=DRAIN_SECONDS):
    """Whatever the worker already wrote, without waiting on a pipe nobody will close.

    The process group is dead by the time this runs, so anything still holding these
    descriptors is not ours to wait for. Bounded, then abandoned.
    """
    try:
        return proc.communicate(timeout=grace)
    except subprocess.TimeoutExpired:
        for stream in (proc.stdout, proc.stderr):
            try:
                if stream is not None:
                    stream.close()
            except Exception:
                pass
        return '', ''


def run_identity_scan(target, mode='username', *, budget=None, worker_argv=None,
                      breach_lookup=None):
    """One scan. Never raises except ScannerBusy.

    `worker_argv` and `breach_lookup` are injection points for the tests, which use a
    fake worker script so a case can sleep deliberately without running a vendor engine.
    `breach_lookup` is named to avoid shadowing the module-level `hudson` import.
    """
    budget = BUDGET_SECONDS if budget is None else budget
    argv = list(worker_argv or WORKER_ARGV)
    if not worker_argv:
        argv += ['--target', target, '--mode', mode]

    if not _slots.acquire(blocking=False):
        raise ScannerBusy('two identity scans are already running')

    record = {'target': target, 'mode': mode, 'timed_out': False, 'error': None,
              'findings': [], 'engines': {}, 'breach': None}
    try:
        # stdin is closed on purpose. user-scanner carries three blocking input() calls;
        # they are only reachable from its CLI, which the worker never touches, but with
        # no stdin a stray prompt raises EOFError in the child instead of hanging here.
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, start_new_session=True)
        try:
            out, err = proc.communicate(timeout=budget)
        except subprocess.TimeoutExpired:
            _kill_worker_group(proc)
            out, err = _drain(proc)
            record['timed_out'] = True
            # No target here, on purpose: this reaches logs/app.log, which no retention
            # sweep covers and which the delete route's promise to remove a record does
            # not touch. The record itself, not this log line, carries the target.
            logger.warning('identity worker exceeded the %ss budget', budget)

        if err:
            logger.debug('identity worker stderr: %s', err[:2000])

        if out:
            try:
                payload = json.loads(out)
            except ValueError:
                payload = None
                record['error'] = 'the scanner returned unreadable output'
        else:
            payload = None
            if not record['timed_out']:
                record['error'] = 'the scanner produced no output'

        if payload:
            findings, engine_status = _findings_from(payload)
            record['findings'] = merge(findings)
            record['engines'] = engine_status
    except Exception:
        # No target here either, same reason as the timeout warning above.
        logger.exception('identity scan failed')
        record['error'] = record['error'] or 'the scan could not be run'
    finally:
        _slots.release()

    # Outside the slot: one cheap request that must not hold a scan slot, and that still
    # runs when the worker was killed.
    try:
        call = breach_lookup if breach_lookup is not None else hudson.lookup
        record['breach'] = call(target, is_email=(mode == 'email'))
    except Exception:
        logger.debug('Hudson Rock lookup failed', exc_info=True)
        record['breach'] = None

    record['summary'] = summarize(record['findings'])
    return record
