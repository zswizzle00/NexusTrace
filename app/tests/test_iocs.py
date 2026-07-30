"""Pins app/utils/iocs.py - IOC extraction and defanging. Pure, no network."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.utils.iocs import defang, extract_iocs, refang

# (raw, expected_defanged)
DEFANG_CASES = [
    ('http://evil.com', 'hxxp://evil[.]com'),
    ('https://evil.com/a', 'hxxps://evil[.]com/a'),
    ('evil.com', 'evil[.]com'),
    ('8.8.8.8', '8[.]8[.]8[.]8'),
    # Idempotent: defanging defanged input changes nothing.
    ('hxxp://evil[.]com', 'hxxp://evil[.]com'),
    ('evil[dot]com', 'evil[.]com'),
]

# (defanged, expected_live)
REFANG_CASES = [
    ('hxxp://evil[.]com', 'http://evil.com'),
    ('hxxps://evil[.]com', 'https://evil.com'),
    ('evil[dot]com', 'evil.com'),
    ('evil(.)com', 'evil.com'),
    ('http://evil.com', 'http://evil.com'),
]

# (text, must_contain, must_not_contain)
EXTRACT_CASES = [
    (
        'Visit http://bad.test/login now',
        [('url', 'hxxp://bad[.]test/login'), ('domain', 'bad[.]test')],
        [],
    ),
    (
        'C2 at 203.0.113.42 and mirror at evil.example',
        [('ipv4', '203[.]0[.]113[.]42'), ('domain', 'evil[.]example')],
        [],
    ),
    (
        'See index.html and report.pdf for details',
        [],
        [('domain', 'index[.]html'), ('domain', 'report[.]pdf')],
    ),
    (
        'Version 1.2.3.4.5 released; build 10.0.19041.1',
        [],
        [('ipv4', '1[.]2[.]3[.]4'), ('ipv4', '10[.]0[.]19041[.]1')],
    ),
    (
        'Not an ip: 999.999.999.999',
        [],
        [('ipv4', '999[.]999[.]999[.]999')],
    ),
    (
        'Already defanged: hxxp://bad[.]test/x',
        [('url', 'hxxp://bad[.]test/x')],
        [],
    ),
    (
        'Trailing punctuation http://bad.test/x. Done',
        [('url', 'hxxp://bad[.]test/x')],
        [],
    ),
    (
        'e.g. this is prose, i.e. not an indicator',
        [],
        [('domain', 'e[.]g'), ('domain', 'i[.]e')],
    ),
]


def main():
    failures = []

    for raw, expected in DEFANG_CASES:
        got = defang(raw)
        if got != expected:
            failures.append(f'defang({raw!r}) -> {got!r}, expected {expected!r}')

    for raw, expected in REFANG_CASES:
        got = refang(raw)
        if got != expected:
            failures.append(f'refang({raw!r}) -> {got!r}, expected {expected!r}')

    for text, must_contain, must_not in EXTRACT_CASES:
        found = {(item['type'], item['value']) for item in extract_iocs(text)}
        for pair in must_contain:
            if pair not in found:
                failures.append(f'extract_iocs({text!r}) missing {pair!r}; got {sorted(found)}')
        for pair in must_not:
            if pair in found:
                failures.append(f'extract_iocs({text!r}) wrongly produced {pair!r}')

    many = ' '.join(f'host{i}.test' for i in range(500))
    if len(extract_iocs(many, limit=10)) > 10:
        failures.append('extract_iocs ignored its limit')

    # No type may starve the others: a link-heavy page used to spend the whole
    # budget on URLs and drop the contacted C2 domain and address entirely.
    links = [f'https://cdn{i}.example/asset{i}.js' for i in range(250)]
    contacted = ['c2-server.test', '203.0.113.99']

    # links-first is the worst case for fairness (every URL seen before any other
    # type); contacted-first is the order scan_service actually builds.
    for label, corpus in (
        ('links-first', '\n'.join(links + contacted)),
        ('contacted-first', '\n'.join(contacted + links)),
    ):
        heavy = extract_iocs(corpus)
        if len(heavy) > 200:
            failures.append(f'{label} corpus exceeded the limit: {len(heavy)} items')
        kinds = {item['type'] for item in heavy}
        for required in ('url', 'domain', 'ipv4'):
            if required not in kinds:
                failures.append(
                    f'{label} corpus produced no {required} IOCs; got {sorted(kinds)}'
                )
        values = {item['value'] for item in heavy}
        if '203[.]0[.]113[.]99' not in values:
            failures.append(f'{label} corpus dropped the contacted IPv4')
        if label == 'contacted-first' and 'c2-server[.]test' not in values:
            failures.append(f'{label} corpus dropped the contacted domain')

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {len(DEFANG_CASES)} defang + {len(REFANG_CASES)} refang + '
          f'{len(EXTRACT_CASES)} extract + 1 limit + 2 fair-share cases')


if __name__ == '__main__':
    main()
