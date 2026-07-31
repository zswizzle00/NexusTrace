"""Holds app/utils/disclosure.py against the service layer.

The point is that the third-party list shown to analysts cannot rot. It AST-walks every
string constant in `app/services/*.py`, pulls the hostnames out, and fails when one is
neither claimed by a Party in the registry nor waived in `NOT_A_DESTINATION` - so adding
a provider to a service breaks this test until the acceptable-use notice mentions it.

Docstrings are skipped (they carry illustrative hosts like `http://10.0.0.5:8080/`) and
comments never reach the AST at all, so only strings the code can actually use count. A
provider reached through a library that builds its own URLs - Shodan, via the `shodan`
package - has no literal to find and must be listed by hand; that gap is stated in
disclosure.py and cannot be closed from here.

Pure: no server, no network, no filesystem writes.
"""
import ast
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from app.utils import disclosure  # noqa: E402

SERVICES = Path(disclosure.__file__).resolve().parent.parent / 'services'

# Deliberately broad: a bare `zen.spamhaus.org` in a tuple has no scheme, so
# matching only on `https?://` would miss every DNS-based provider.
HOST_RE = re.compile(
    r'\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+'
    r'(?:com|net|org|io|ch|sh|run|gov|edu|info|co|me|us|ai|dev|cloud|app|xyz)\b')

CASES = 0
FAILURES = []


def ok(condition, label, detail=''):
    global CASES
    CASES += 1
    if not condition:
        FAILURES.append(f'{label}: {detail}' if detail else label)


def _docstring_ids(tree):
    ids = set()
    for node in ast.walk(tree):
        body = getattr(node, 'body', None)
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                 ast.AsyncFunctionDef)) or not body:
            continue
        first = body[0]
        if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)):
            ids.add(id(first.value))
    return ids


def hosts_in_services():
    """{host: {source file, ...}} over every non-docstring string constant."""
    found = {}
    for path in sorted(SERVICES.glob('*.py')):
        tree = ast.parse(path.read_text(encoding='utf-8'))
        skip = _docstring_ids(tree)
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and id(node) not in skip):
                for host in HOST_RE.findall(node.value.lower()):
                    found.setdefault(host, set()).add(path.name)
    return found


def test_registry_shape():
    print('\nRegistry shape:')
    keys = [p.key for p in disclosure.PARTIES]
    ok(len(keys) == len(set(keys)), 'party keys are unique',
       f'duplicates: {[k for k in keys if keys.count(k) > 1]}')
    for party in disclosure.PARTIES:
        ok(party.when in (disclosure.ALWAYS, disclosure.ON_CLICK),
           f'{party.key} has a known `when`', party.when)
        ok(bool(party.name) and bool(party.sends), f'{party.key} is described')
    for name, surface in disclosure.SURFACES.items():
        unknown = [k for k in surface.parties if k not in keys]
        ok(not unknown, f'{name} references only known parties', unknown)
        ok(bool(surface.retained), f'{name} says what is retained')
        ok(bool(surface.sends), f'{name} says what is transmitted')
        # These are rendered escaped. An apostrophe or ampersand here comes out as
        # an entity mid-sentence, which is how the copy last broke.
        for field in ('sends', 'retained'):
            text = getattr(surface, field)
            ok(not (set(text) & set('<>&\'"')),
               f'{name}.{field} needs no markup escaping', text)
    print(f'  PASS  {len(keys)} parties, {len(disclosure.SURFACES)} surfaces, '
          f'no unknown references')


def test_service_hosts_are_disclosed():
    print('\nCoverage against app/services/*.py:')
    claimed = {}
    for party in disclosure.PARTIES:
        for host in party.hosts:
            claimed[host] = party.key
    found = hosts_in_services()
    ok(bool(found), 'the extractor found hosts at all', 'regex or path is wrong')

    undisclosed = sorted(h for h in found
                         if h not in claimed and h not in disclosure.NOT_A_DESTINATION)
    ok(not undisclosed, 'every host in the service layer is classified',
       '; '.join(f'{h} (in {", ".join(sorted(found[h]))})' for h in undisclosed))

    stale = sorted(h for h in disclosure.NOT_A_DESTINATION if h not in found)
    ok(not stale, 'no stale NOT_A_DESTINATION waivers', stale)

    for host, reason in disclosure.NOT_A_DESTINATION.items():
        ok(bool(reason), f'{host} waiver states a reason')

    print(f'  PASS  {len(found)} hosts found, {len(found) - len(undisclosed)} '
          f'classified, {len(disclosure.NOT_A_DESTINATION)} waived')


def test_known_providers_present():
    """Spot-check the providers the deployment actually depends on. Guards against
    a registry that passes coverage because someone deleted parties."""
    print('\nNamed providers:')
    expected = ('AbuseIPDB', 'IPinfo', 'IP2Location', 'IP2WHOIS', 'AlienVault OTX',
                'abuse.ch', 'ProxyCheck.io', 'Cisco Talos', 'PhishTank',
                'HackerTarget', 'VirusTotal', 'Shodan', 'Team Cymru', 'Spamhaus')
    names = {p.name for p in disclosure.PARTIES}
    for want in expected:
        ok(any(want in name for name in names), f'{want} is in the registry')
    print(f'  PASS  {len(expected)} known providers present')


def test_surface_rendering():
    print('\nPer-surface template data:')
    for name in ('url_scan', 'email', 'file'):
        data = disclosure.for_template(name)
        ok(bool(data['always']), f'{name} discloses at least one destination')
        ok(bool(data['retained']), f'{name} states what is retained')
        # Names go through Jinja's autoescape; anything in this set would render as
        # an entity and read as noise in the middle of a sentence.
        offenders = [n for n in data['always'] + data['on_click']
                     if set(n) & set('<>&\'"')]
        ok(not offenders, f'{name} names need no markup escaping', offenders)
        print(f'  {name:9s} always={len(data["always"])} '
              f'on_click={len(data["on_click"])} retention='
              f'{"yes" if data["retention"] else "n/a"}')

    ok('VirusTotal' in disclosure.for_template('file')['always'],
       'the file surface discloses VirusTotal')
    ok('Spamhaus' in disclosure.for_template('email')['always'],
       'the e-mail surface discloses Spamhaus')
    ok('Team Cymru' in disclosure.for_template('url_scan')['always'],
       'the URL surface discloses Team Cymru')
    ok('VirusTotal' not in disclosure.for_template('url_scan')['always'],
       'the URL surface does not claim a provider it never calls')

    raised = False
    try:
        disclosure.for_template('nope')
    except ValueError:
        raised = True
    ok(raised, 'an unknown surface raises rather than rendering an empty notice')
    print('  PASS  three surfaces render, unknown surface raises')


def main():
    test_registry_shape()
    test_service_hosts_are_disclosed()
    test_known_providers_present()
    test_surface_rendering()
    if FAILURES:
        print('\nFAIL:')
        for line in FAILURES:
            print('  ' + line)
        sys.exit(1)
    print(f'\nPASS: {CASES} cases')


if __name__ == '__main__':
    main()
