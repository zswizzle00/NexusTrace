"""Runs the two identity engines in a throwaway subprocess and emits JSON on stdout.

**Why a subprocess.** sherlock() blocks on an internal futures pool and cannot be
interrupted. Run in-process, an overrunning scan would leave hundreds of sockets and a
live thread pool inside the single gunicorn worker with no way to reclaim them. A
subprocess can be killed when the deadline passes, which is what makes the budget real
rather than aspirational.

It also contains two vendor hazards. user-scanner's orchestrators print to stdout, which
would otherwise pollute the application log, and user-scanner carries three blocking
input() prompts. Those prompts are only reachable from its CLI, which this module never
touches, but the parent spawns this worker with stdin closed so that even if one were
reached it raises EOFError here instead of hanging a request thread forever.

**Never import user_scanner.__main__ or anything under user_scanner.utils.** That is
where the prompts live, along with a self-updater that shells out to pip and would
mutate the running container's site-packages.

This module emits RAW per-engine findings. Normalization and merging happen in the
parent, in app/utils/identity_findings.py, so that logic stays pure and testable without
spawning anything.
"""

import argparse
import contextlib
import json
import os
import sys


def sherlock_site_data():
    """Sherlock's site list, loaded from the file bundled in the wheel.

    SitesInformation() with no argument sets data_file_path to MANIFEST_URL and performs
    requests.get(url, timeout=30) before a single username is checked. That would spend
    up to 30 of the scan's 70-second budget, fail hard whenever GitHub is unreachable,
    and never work in a container with restricted egress. The bundled copy is resolved
    from the installed package so it cannot drift from the pinned version.

    honor_exclusions defaults to True and triggers a SECOND, independent network call
    (a false-positive exclusion list, timeout=10) that the manifest fix above does not
    touch. It fails soft (a caught exception and a printed warning) rather than raising,
    so it would not crash the worker, but it is still an outbound request this offline
    load must not make. Disabled explicitly for the same reason as the manifest path.
    """
    import sherlock_project
    from sherlock_project.sites import SitesInformation

    bundled = os.path.join(os.path.dirname(sherlock_project.__file__),
                           'resources', 'data.json')
    sites = SitesInformation(data_file_path=bundled, honor_exclusions=False)
    return {site.name: site.information for site in sites}


def _selftest_mode():
    return os.environ.get('NEXUSTRACE_IDENTITY_SELFTEST') or ''


def run_sherlock(target, mode='username', engine=None, timeout=8):
    """Sherlock's results for one username, as a raw findings list.

    Sherlock is username-only, so e-mail mode reports not_applicable rather than an
    error: "this engine does not do e-mail" and "this engine failed" are different
    claims and the page renders them differently.
    """
    if mode != 'username':
        return {'status': 'not_applicable', 'findings': []}

    selftest = _selftest_mode()
    if selftest == 'prompt':
        return _errored(lambda: input('pretend prompt'))
    if selftest == 'fdnoise':
        return _errored(lambda: os.write(1, b'GARBAGE') and None)
    if selftest:
        return _errored(lambda: (_ for _ in ()).throw(RuntimeError('selftest')))

    def call():
        from sherlock_project.notify import QueryNotify

        class Quiet(QueryNotify):
            """No-op notifier. The base class prints; this one is why the engine can run
            without writing to the stream that carries our JSON."""

            def start(self, message=None):
                return None

            def update(self, result):
                return None

            def finish(self, message=None):
                return None

        run = engine
        if run is None:
            from sherlock_project.sherlock import sherlock as run

        raw = run(target, sherlock_site_data(), Quiet(), timeout=timeout)
        findings = []
        for site_name, entry in (raw or {}).items():
            status = getattr(entry.get('status'), 'status', entry.get('status'))
            findings.append({
                'site_name': site_name,
                'status': getattr(status, 'name', str(status)),
                'url_user': entry.get('url_user'),
            })
        return findings

    return _errored(call)


def run_user_scanner(target, mode='username', engine=None, timeout=8):
    """user-scanner's results for one target, as a raw findings list."""
    selftest = _selftest_mode()
    if selftest:
        return _errored(lambda: (_ for _ in ()).throw(RuntimeError('selftest')))

    def call():
        from user_scanner.core.helpers import ScanConfig

        # allow_loud=False is the default and is deliberate: with it the orchestrators
        # SKIP loud sites instead of prompting, and the prompt path is the one that
        # would otherwise block.
        config = ScanConfig(allow_loud=False, timeout=timeout)

        run = engine
        if run is None:
            if mode == 'email':
                from user_scanner.core.email_orchestrator import run_email_full_batch as run
            else:
                from user_scanner.core.orchestrator import run_user_full as run

        results = run(target, config) or []
        return [_user_scanner_entry(item) for item in results]

    return _errored(call)


def _user_scanner_entry(item):
    """One vendor Result as the raw dict the parent's normalizer reads.

    Module level so a test can drive it with a real vendor object rather than a fake
    dict. Faking the dict is what let the status-label mismatch ship.
    """
    to_dict = getattr(item, 'to_dict', None)
    data = to_dict() if callable(to_dict) else dict(item or {})
    # Read the enum off the OBJECT, not out of to_dict(). The vendor's to_dict()
    # replaces status with a display label that also differs between modes
    # ('Found' vs 'Registered'), and mapping a label against enum names silently
    # turns every result into `unknown`.
    status = getattr(item, 'status', data.get('status'))
    data['status'] = getattr(status, 'name', str(status))
    return data


def _errored(call):
    """Run `call` and wrap any failure as an engine error entry.

    Every failure path converges here on purpose. The parent's contract is that it reads
    one JSON document and never has to distinguish a crash from a partial result by
    parsing stderr, so an exception in either engine must become data, not a traceback.

    SystemExit is caught deliberately and KeyboardInterrupt is not. A vendor calling
    sys.exit() must not take the other engine's results with it, but an interrupt
    should still stop the process.
    """
    try:
        return {'status': 'ok', 'findings': call()}
    except (Exception, SystemExit) as exc:  # noqa: BLE001 - including EOFError from a stray prompt
        print(f'engine failed: {exc!r}', file=sys.stderr)
        return {'status': 'error', 'findings': [], 'error': str(exc)[:200]}


@contextlib.contextmanager
def _stdout_to_stderr():
    """Point file descriptor 1 at stderr for the duration of the block.

    Reassigning sys.stdout only redirects Python-level writes. Redirecting the
    descriptor also catches a C extension writing to fd 1 directly, and a vendor that
    captured the real stdout before we swapped it. stdout carries exactly one JSON
    document, so a stray byte on it is a parse failure in the parent rather than a
    visible error here.
    """
    saved_fd = os.dup(1)
    saved_stdout = sys.stdout
    try:
        saved_stdout.flush()
        os.dup2(2, 1)
        sys.stdout = sys.stderr
        yield
    finally:
        try:
            sys.stderr.flush()
        except Exception:
            pass
        os.dup2(saved_fd, 1)
        os.close(saved_fd)
        sys.stdout = saved_stdout


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', required=True)
    parser.add_argument('--mode', choices=('username', 'email'), default='username')
    parser.add_argument('--timeout', type=int, default=8)
    args = parser.parse_args(argv)

    with _stdout_to_stderr():
        payload = {
            'target': args.target,
            'mode': args.mode,
            'engines': {
                'sherlock': run_sherlock(args.target, args.mode, timeout=args.timeout),
                'user-scanner': run_user_scanner(args.target, args.mode,
                                                 timeout=args.timeout),
            },
        }

    json.dump(payload, sys.stdout)
    sys.stdout.flush()
    return 0


if __name__ == '__main__':
    sys.exit(main())
