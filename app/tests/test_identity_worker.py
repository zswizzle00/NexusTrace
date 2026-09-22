"""Pins app/tools/identity_worker.py without running either vendor engine.

The engines are replaced by fakes. What is under test here is the worker's CONTRACT:
that it always emits one parseable JSON document on stdout, that a crashing engine
becomes an error entry rather than a traceback, and that Sherlock's site list loads
from the bundled file rather than over the network.

That last one has teeth. SitesInformation() called with no argument performs
requests.get(MANIFEST_URL, timeout=30) before checking a single username, which would
spend up to 30 of the scan's 70-second budget and fail hard whenever GitHub is
unreachable. The case asserts no HTTP call happens.
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.tools import identity_worker

failures = []
cases = 0


def check(condition, message):
    global cases
    cases += 1
    if not condition:
        failures.append(message)
    return bool(condition)


def test_sherlock_site_data_loads_offline():
    """No network. Patches requests.get inside the vendor module so any attempt to fetch
    the manifest fails the test loudly rather than silently costing 30 seconds."""
    import sherlock_project.sites as vendor_sites

    calls = []
    original = vendor_sites.requests.get

    def forbidden(*args, **kwargs):
        calls.append(args[0] if args else kwargs.get('url'))
        raise AssertionError('the worker fetched the site list over the network')

    vendor_sites.requests.get = forbidden
    try:
        data = identity_worker.sherlock_site_data()
    except Exception as exc:  # noqa: BLE001 - reported as a failure below
        failures.append(f'sherlock_site_data() raised {exc!r}')
        data = {}
    finally:
        vendor_sites.requests.get = original

    check(not calls, f'sherlock_site_data() made HTTP calls: {calls}')
    check(len(data) > 300,
          f'sherlock_site_data() returned {len(data)} sites, expected the bundled list')


def test_run_sherlock_wraps_engine_failure():
    def boom(*args, **kwargs):
        raise RuntimeError('engine exploded')

    result = identity_worker.run_sherlock('alice', engine=boom)
    check(result['status'] == 'error',
          f'a crashing engine produced status={result["status"]!r}, expected error')
    check(result['findings'] == [], 'a crashing engine produced findings')


def test_run_sherlock_is_not_applicable_for_email_mode():
    """Sherlock is username-only. E-mail mode must report not_applicable rather than an
    error, so the page can say 'this engine does not do e-mail' instead of implying a
    failure."""
    result = identity_worker.run_sherlock('a@b.test', mode='email')
    check(result['status'] == 'not_applicable',
          f'e-mail mode gave status={result["status"]!r}, expected not_applicable')


def test_run_user_scanner_wraps_engine_failure():
    def boom(*args, **kwargs):
        raise RuntimeError('engine exploded')

    result = identity_worker.run_user_scanner('alice', mode='username', engine=boom)
    check(result['status'] == 'error',
          f'a crashing engine produced status={result["status"]!r}, expected error')


def test_subprocess_emits_json_even_when_everything_fails():
    """The contract the parent depends on: ONE JSON document on stdout, always. The
    parent must never have to tell a crash from a partial result by parsing stderr.

    NEXUSTRACE_IDENTITY_SELFTEST makes both engines raise immediately, so this spawns a
    real subprocess without touching the network.
    """
    env = dict(os.environ, NEXUSTRACE_IDENTITY_SELFTEST='1')
    proc = subprocess.run(
        [sys.executable, '-m', 'app.tools.identity_worker',
         '--target', 'alice', '--mode', 'username'],
        cwd=REPO_ROOT, env=env, stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=60)

    try:
        payload = json.loads(proc.stdout)
    except Exception as exc:  # noqa: BLE001 - reported below
        failures.append(f'worker stdout was not JSON: {exc!r}; stdout={proc.stdout[:200]!r}')
        return

    check(payload.get('target') == 'alice', f'target={payload.get("target")!r}')
    check(payload.get('mode') == 'username', f'mode={payload.get("mode")!r}')
    engines = payload.get('engines') or {}
    for name in ('sherlock', 'user-scanner'):
        check(name in engines, f'{name} missing from the worker payload')
        check(engines.get(name, {}).get('status') == 'error',
              f'{name} status={engines.get(name, {}).get("status")!r}, expected error')


def test_subprocess_closes_stdin_safely():
    """user-scanner has three blocking input() calls. They are only reachable from its
    CLI, but the worker is spawned with stdin closed so that even if one were reached it
    raises EOFError in the child instead of hanging a gunicorn thread forever."""
    env = dict(os.environ, NEXUSTRACE_IDENTITY_SELFTEST='prompt')
    proc = subprocess.run(
        [sys.executable, '-m', 'app.tools.identity_worker',
         '--target', 'alice', '--mode', 'username'],
        cwd=REPO_ROOT, env=env, stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=60)
    check(proc.returncode is not None, 'the worker did not terminate')
    try:
        payload = json.loads(proc.stdout)
    except Exception:
        failures.append('a prompting engine did not yield a JSON document')
        return
    check(payload['engines']['sherlock']['status'] == 'error',
          'an EOFError from a prompt was not reported as an engine error')


def test_raw_fd_writes_cannot_corrupt_stdout():
    """The descriptor-level guarantee, asserted as an outcome.

    A Python-level `sys.stdout` swap would let this test fail: the selftest mode
    writes to file descriptor 1 directly, exactly as a C extension would.
    """
    env = dict(os.environ, NEXUSTRACE_IDENTITY_SELFTEST='fdnoise')
    proc = subprocess.run(
        [sys.executable, '-m', 'app.tools.identity_worker',
         '--target', 'alice', '--mode', 'username'],
        cwd=REPO_ROOT, env=env, stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=60)

    check('GARBAGE' not in proc.stdout,
          f'raw fd-1 output reached stdout: {proc.stdout[:120]!r}')
    try:
        payload = json.loads(proc.stdout)
    except Exception as exc:  # noqa: BLE001 - reported below
        failures.append(f'stdout was not parseable JSON: {exc!r}; '
                        f'stdout={proc.stdout[:160]!r}')
        return
    check(payload.get('target') == 'alice', 'the payload survived the fd noise')
    check('GARBAGE' in proc.stderr,
          'the fd-1 noise did not end up on stderr where it belongs')


def test_user_scanner_status_survives_as_an_enum_name():
    """Built from a real vendor Result, not a fake dict.

    The vendor's to_dict() emits a display label ('Found', and 'Registered' in e-mail
    mode), while the normalizer maps enum names. Every test that fakes this shape passes
    while the real path yields `unknown` for every result, which is how this shipped
    unnoticed.
    """
    try:
        from user_scanner.core.result import Result, Status
    except Exception as exc:  # noqa: BLE001
        failures.append(f'could not import the vendor Result: {exc!r}')
        return

    from app.utils.identity_findings import normalize_user_scanner

    expected = {'TAKEN': 'found', 'AVAILABLE': 'not_found',
               'ERROR': 'unknown', 'SKIPPED': 'not_applicable'}

    for is_email in (False, True):
        for name, want in expected.items():
            item = Result(status=getattr(Status, name), site_name='X',
                          url='https://x.test/a', is_email=is_email)
            emitted = identity_worker._user_scanner_entry(item)
            got = normalize_user_scanner(emitted)['status']
            mode = 'email' if is_email else 'username'
            check(got == want,
                  f'{name} in {mode} mode normalised to {got!r}, expected {want!r} '
                  f'(worker emitted status={emitted.get("status")!r})')


def main():
    test_sherlock_site_data_loads_offline()
    test_run_sherlock_wraps_engine_failure()
    test_run_sherlock_is_not_applicable_for_email_mode()
    test_run_user_scanner_wraps_engine_failure()
    test_subprocess_emits_json_even_when_everything_fails()
    test_subprocess_closes_stdin_safely()
    test_raw_fd_writes_cannot_corrupt_stdout()
    test_user_scanner_status_survives_as_an_enum_name()

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {cases} cases')


if __name__ == '__main__':
    main()
