"""Pins POST /api/ip/check_ips - the bulk IP analyzer.

Uses the Flask test client, so no server, network, or browser is needed: every provider
function is stubbed at its defining module (app.services.ip_service), which is also where
the enrichment routes' function-local imports resolve.

The invariants under test, in the order they were broken:
  - a tokenless POST is rejected and a token-bearing one is accepted (CSRF)
  - a row is never dropped: an unqueryable or unanswered IP still appears, with `error`
  - no source is a hard dependency, so a keyless environment returns rows, not a 400
  - a private / link-local IP is reported, never shipped to a provider
  - a headerless CSV/XLSX keeps its first address
  - an empty or non-UTF-8 upload is a 400 with no pandas or codec internals
"""
import csv
import io
import os
import re
import sys
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pandas as pd

from app import create_app
from app.routes.enrichment_routes import _detect_type
from app.routes.ip_routes import MAX_BATCH_IPS

failures = []
checks = 0

CSV_MIME = 'text/csv'
IP_SERVICE = 'app.services.ip_service'


def check(label, condition, detail=''):
    global checks
    checks += 1
    if not condition:
        failures.append(f'{label}{": " + detail if detail else ""}')


def csrf_token(client):
    """Scraped from base.html's <meta name="csrf-token">, exactly as the page's own JS
    reads it."""
    page = client.get('/').get_data(as_text=True)
    match = re.search(r'name="csrf-token" content="([^"]+)"', page)
    if not match:
        raise RuntimeError('no CSRF token in the rendered home page')
    return match.group(1)


def post_file(client, token, filename, payload):
    headers = {'X-CSRFToken': token} if token else {}
    return client.post(
        '/api/ip/check_ips',
        data={'file': (io.BytesIO(payload), filename)},
        content_type='multipart/form-data',
        headers=headers,
        follow_redirects=False,
    )


def rows_of(response):
    return list(csv.DictReader(io.StringIO(response.get_data(as_text=True))))


VPN_OK = {
    'security': {'vpn': True, 'proxy': False, 'tor': False, 'relay': False},
    'location': {'city': 'Mountain View', 'region': 'California', 'country': 'United States',
                 'continent': 'North America', 'latitude': '37.4', 'longitude': '-122.0'},
    'network': {'network': '8.8.8.0/24', 'autonomous_system_number': 'AS15169',
                'autonomous_system_organization': 'GOOGLE'},
}
ABUSE_OK = {
    'abuse_confidence_score': 42, 'total_reports': 7, 'distinct_users': 3,
    'last_reported': '2026-07-01T00:00:00+00:00', 'usage_type': 'Data Center',
    'isp': 'Google LLC', 'domain': 'google.com', 'is_whitelisted': False,
}
IPINFO_OK = {'hostname': 'dns.google', 'org': 'AS15169 Google LLC', 'city': 'Mountain View',
             'region': 'California', 'country': 'US'}
WHOIS_OK = {'domain': 'google.com', 'registrar': {'name': 'MarkMonitor'}, 'status': 'clientTransferProhibited',
            'create_date': '1997-09-15', 'expire_date': '2028-09-14'}


def stub_sources(vpn=None, abuse=None, ipinfo=None, whois=None):
    """Patch at the defining module so both the routes and the services see the stub."""
    return mock.patch.multiple(
        IP_SERVICE,
        get_vpn_data=mock.Mock(return_value=vpn),
        check_abuseipdb=mock.Mock(return_value=abuse),
        get_ipinfo_data=mock.Mock(return_value=ipinfo),
    ), mock.patch('app.services.domain_service.get_whois_info', return_value=whois)


def with_stubs(client, filename, payload, token, **sources):
    sources_patch, whois_patch = stub_sources(**sources)
    with sources_patch, whois_patch:
        return post_file(client, token, filename, payload)


def test_csrf(client):
    tokenless = post_file(client, None, 'ips.csv', b'ip\n8.8.8.8\n')
    check('tokenless POST is rejected (303 to home)',
          tokenless.status_code == 303 and tokenless.headers.get('Location', '').endswith('/'),
          f'{tokenless.status_code} {tokenless.headers.get("Location")!r}')
    check('tokenless POST returns no CSV',
          CSV_MIME not in tokenless.headers.get('Content-Type', ''),
          tokenless.headers.get('Content-Type', ''))

    token = csrf_token(client)
    accepted = with_stubs(client, 'ips.csv', b'ip\n8.8.8.8\n', token,
                          vpn=VPN_OK, abuse=ABUSE_OK, ipinfo=IPINFO_OK, whois=WHOIS_OK)
    check('POST carrying the meta token is accepted',
          accepted.status_code == 200, str(accepted.status_code))
    check('accepted POST returns text/csv',
          CSV_MIME in accepted.headers.get('Content-Type', ''),
          accepted.headers.get('Content-Type', ''))


def test_column_shape(client, token):
    r = with_stubs(client, 'ips.csv', b'ip\n8.8.8.8\n', token,
                   vpn=VPN_OK, abuse=ABUSE_OK, ipinfo=IPINFO_OK, whois=WHOIS_OK)
    header = r.get_data(as_text=True).splitlines()[0]
    expected = (
        'ip,vpn,proxy,tor,relay,city,region,country,continent,latitude,longitude,'
        'network,asn,asn_org,abuse_score,abuse_total_reports,abuse_distinct_users,'
        'abuse_last_reported,abuse_usage_type,abuse_isp,abuse_domain,abuse_whitelisted,'
        'ipinfo_hostname,ipinfo_org,ipinfo_city,ipinfo_region,ipinfo_country,'
        'whois_domain,whois_registrar,whois_status,whois_create_date,whois_expire_date,error'
    )
    check('the 32 original columns keep their names and order, with error appended',
          header == expected, f'got {header!r}')

    row = rows_of(r)[0]
    check('a fully enriched row has an empty error', row['error'] == '', repr(row['error']))
    # abuse_score must be "42", not "42.0": a null in the same column used to make pandas
    # infer float64 for the whole column.
    for column, value in [('vpn', 'True'), ('country', 'United States'), ('asn', 'AS15169'),
                          ('abuse_score', '42'), ('abuse_total_reports', '7'),
                          ('ipinfo_hostname', 'dns.google'), ('whois_registrar', 'MarkMonitor')]:
        check(f'{column} is carried through from its source', row[column] == value, repr(row[column]))


def test_no_keys_configured(client, token):
    """The real state of this environment: every provider returns None. Rows must still
    come back - a 400 threw away the whole upload."""
    r = with_stubs(client, 'ips.txt', b'8.8.8.8\n1.1.1.1\n', token)
    check('a keyless environment returns 200, not 400', r.status_code == 200, str(r.status_code))
    rows = rows_of(r)
    check('one row per uploaded IP', len(rows) == 2, str(len(rows)))
    check('rows keep input order', [row['ip'] for row in rows] == ['8.8.8.8', '1.1.1.1'],
          str([row['ip'] for row in rows]))
    for row in rows:
        check(f'{row["ip"]} names every silent source',
              row['error'] == 'no data returned by any source: vpnapi, abuseipdb, ipinfo',
              repr(row['error']))
        check(f'{row["ip"]} has empty data columns', row['country'] == '' and row['abuse_score'] == '')
    return r


def test_partial_sources(client, token):
    """VPNapi used to gate the whole row, silently making VPNAPI_KEY mandatory."""
    r = with_stubs(client, 'ips.csv', b'ip\n8.8.8.8\n', token,
                   vpn=None, abuse=ABUSE_OK, ipinfo=IPINFO_OK, whois=WHOIS_OK)
    row = rows_of(r)[0]
    check('a row survives VPNapi returning nothing', row['ip'] == '8.8.8.8')
    check('AbuseIPDB data is kept when VPNapi is silent', row['abuse_score'] == '42', repr(row['abuse_score']))
    check('a mixed int/null column is not coerced to float', '.0' not in row['abuse_total_reports'],
          repr(row['abuse_total_reports']))
    check('IPinfo data is kept when VPNapi is silent', row['ipinfo_org'] == 'AS15169 Google LLC')
    check('WHOIS data is kept when VPNapi is silent', row['whois_domain'] == 'google.com')
    check('VPNapi-only columns are empty, not fabricated', row['vpn'] == '' and row['asn'] == '')
    check('error names only the silent source', row['error'] == 'no data from: vpnapi', repr(row['error']))

    errored = with_stubs(client, 'ips.csv', b'ip\n8.8.8.8\n', token,
                         vpn={'error': 'quota exceeded'}, abuse=ABUSE_OK, ipinfo=None)
    row = rows_of(errored)[0]
    check("a VPNapi error payload counts as silence, not as data",
          row['error'] == 'no data from: vpnapi, ipinfo', repr(row['error']))
    check('an errored VPNapi leaves its columns empty', row['vpn'] == '')

    raising = mock.patch(f'{IP_SERVICE}.check_abuseipdb', side_effect=RuntimeError('boom'))
    sources_patch, whois_patch = stub_sources(vpn=VPN_OK, ipinfo=None)
    with sources_patch, whois_patch, raising:
        r = post_file(client, token, 'ips.csv', b'ip\n8.8.8.8\n')
    row = rows_of(r)[0]
    check('a source that raises degrades to a silent source',
          row['error'] == 'no data from: abuseipdb, ipinfo', repr(row['error']))
    check('a raising source does not lose the row or the sources that answered',
          row['ip'] == '8.8.8.8' and row['city'] == 'Mountain View', repr(row))

    sources_patch, whois_patch = stub_sources(vpn=['not', 'an', 'object'], abuse=ABUSE_OK,
                                              ipinfo=IPINFO_OK, whois='not an object')
    with sources_patch, whois_patch:
        r = post_file(client, token, 'ips.csv', b'ip\n8.8.8.8\n')
    row = rows_of(r)[0]
    check('a non-object provider payload is treated as silence, not a crash',
          row['ip'] == '8.8.8.8' and row['error'] == 'no data from: vpnapi'
          and row['whois_registrar'] == '', repr(row))

    whois_raises = mock.patch('app.services.domain_service.get_whois_info',
                              side_effect=RuntimeError('whois down'))
    sources_patch, _ = stub_sources(vpn=VPN_OK, abuse=ABUSE_OK, ipinfo=IPINFO_OK)
    with sources_patch, whois_raises:
        r = post_file(client, token, 'ips.csv', b'ip\n8.8.8.8\n')
    row = rows_of(r)[0]
    check('a raising WHOIS lookup does not lose the row or flag the queried sources',
          row['ip'] == '8.8.8.8' and row['error'] == '' and row['whois_domain'] == '',
          repr(row['error']))


def test_non_global_ips(client, token):
    """Never queried, never dropped - dropping them would be the same silent loss."""
    upload = b'ip\n192.168.1.1\n10.0.0.1\n127.0.0.1\n169.254.169.254\nfe80::1\n::1\n8.8.8.8\n'
    sources_patch, whois_patch = stub_sources(vpn=VPN_OK, abuse=ABUSE_OK, ipinfo=IPINFO_OK, whois=WHOIS_OK)
    with sources_patch, whois_patch:
        r = post_file(client, token, 'ips.csv', upload)
        vpn_mock = sys.modules[IP_SERVICE].get_vpn_data
        queried = [call.args[0] for call in vpn_mock.call_args_list]

    rows = rows_of(r)
    check('every uploaded address is reported', len(rows) == 7, str(len(rows)))
    for row in rows[:6]:
        check(f'{row["ip"]} is reported as not queried',
              row['error'] == 'not queried: not a globally routable address', repr(row['error']))
        check(f'{row["ip"]} carries no provider data', row['country'] == '' and row['abuse_score'] == '')
    check('only the global address reached a provider', queried == ['8.8.8.8'], str(queried))
    check('the global address in the same batch is still enriched',
          rows[6]['ip'] == '8.8.8.8' and rows[6]['error'] == '', repr(rows[6]))


def test_headers_and_formats(client, token):
    cases = [
        ('headered .csv', 'ips.csv', b'ip\n8.8.8.8\n1.1.1.1\n9.9.9.9\n'),
        ('headerless .csv', 'ips.csv', b'8.8.8.8\n1.1.1.1\n9.9.9.9\n'),
        ('headerless .csv with CRLF', 'ips.csv', b'8.8.8.8\r\n1.1.1.1\r\n9.9.9.9\r\n'),
        ('uppercase .CSV', 'ips.CSV', b'8.8.8.8\n1.1.1.1\n9.9.9.9\n'),
        ('mixed-case .Csv', 'ips.Csv', b'ip\n8.8.8.8\n1.1.1.1\n9.9.9.9\n'),
        ('.txt', 'ips.txt', b'8.8.8.8\n1.1.1.1\n9.9.9.9\n'),
        ('.TXT', 'ips.TXT', b'8.8.8.8\n1.1.1.1\n9.9.9.9\n'),
        ('multi-column headered .csv', 'ips.csv', b'ip,note\n8.8.8.8,a\n1.1.1.1,b\n9.9.9.9,c\n'),
        ('multi-column headerless .csv', 'ips.csv', b'8.8.8.8,a\n1.1.1.1,b\n9.9.9.9,c\n'),
    ]
    for label, filename, payload in cases:
        r = with_stubs(client, filename, payload, token)
        ips = [row['ip'] for row in rows_of(r)]
        check(f'{label} keeps all three addresses in order',
              ips == ['8.8.8.8', '1.1.1.1', '9.9.9.9'], str(ips))

    single = with_stubs(client, 'one.csv', b'8.8.8.8\n', token)
    check('a single-IP headerless .csv is not swallowed',
          single.status_code == 200 and [row['ip'] for row in rows_of(single)] == ['8.8.8.8'],
          f'{single.status_code} {single.get_data(as_text=True)[:120]!r}')

    excel = io.BytesIO()
    pd.DataFrame({'ip': ['8.8.8.8', '1.1.1.1', '9.9.9.9']}).to_excel(excel, index=False)
    r = with_stubs(client, 'ips.xlsx', excel.getvalue(), token)
    check('headered .xlsx keeps all three addresses',
          [row['ip'] for row in rows_of(r)] == ['8.8.8.8', '1.1.1.1', '9.9.9.9'],
          str([row['ip'] for row in rows_of(r)]))

    excel = io.BytesIO()
    pd.DataFrame([['8.8.8.8'], ['1.1.1.1'], ['9.9.9.9']]).to_excel(excel, index=False, header=False)
    r = with_stubs(client, 'ips.XLSX', excel.getvalue(), token)
    check('headerless uppercase .XLSX keeps its first address',
          [row['ip'] for row in rows_of(r)] == ['8.8.8.8', '1.1.1.1', '9.9.9.9'],
          str([row['ip'] for row in rows_of(r)]))


def test_dedup_and_ipv6(client, token):
    upload = (b'ip\n8.8.8.8\n8.8.8.8\n 8.8.8.8 \n'
              b'2001:db8::1\n2001:0db8:0000:0000:0000:0000:0000:0001\n2001:DB8::1\n'
              b'2606:4700:4700::1111\n')
    sources_patch, whois_patch = stub_sources()
    with sources_patch, whois_patch:
        r = post_file(client, token, 'ips.csv', upload)
    ips = [row['ip'] for row in rows_of(r)]
    check('duplicates and IPv6 spelling variants collapse to normalized addresses',
          ips == ['8.8.8.8', '2001:db8::1', '2606:4700:4700::1111'], str(ips))


def test_bad_uploads(client, token):
    cases = [
        ('empty .csv', 'empty.csv', b'', 'The file is empty.'),
        ('empty .txt', 'empty.txt', b'', 'The file is empty.'),
        ('whitespace-only .csv', 'blank.csv', b'\n\n\n', None),
        ('UTF-16 .csv', 'utf16.csv', '8.8.8.8\n1.1.1.1\n'.encode('utf-16'), None),
        ('unsupported extension', 'ips.json', b'["8.8.8.8"]', None),
        ('no IPs at all', 'words.csv', b'host\nexample.com\nnot-an-ip\n', None),
        ('not a real xlsx', 'fake.xlsx', b'this is not a zip archive', None),
    ]
    # Naming UTF-8 is advice; quoting the codec error, pandas' wording, or a traceback is a leak.
    leaks = ("codec can't decode", 'No columns', 'Traceback', 'pandas', 'BadZipFile',
             'position 0', 'read_csv', 'read_excel', 'you must specify an engine')
    for label, filename, payload, expected in cases:
        r = with_stubs(client, filename, payload, token)
        body = r.get_json(silent=True) or {}
        message = body.get('error', '')
        check(f'{label} -> 400', r.status_code == 400,
              f'{r.status_code} {r.get_data(as_text=True)[:160]!r}')
        check(f'{label} returns an actionable message', bool(message) and message[-1] in '.!',
              repr(message))
        check(f'{label} leaks no internals',
              not any(leak.lower() in message.lower() for leak in leaks), repr(message))
        if expected:
            check(f'{label} message is {expected!r}', message == expected, repr(message))

    r = post_file(client, token, '', b'ip\n8.8.8.8\n')
    check('a missing filename -> 400', r.status_code == 400, str(r.status_code))
    r = client.post('/api/ip/check_ips', data={}, content_type='multipart/form-data',
                    headers={'X-CSRFToken': token})
    check('a missing file part -> 400', r.status_code == 400, str(r.status_code))


def test_cap(client, token):
    check('the cap is 200', MAX_BATCH_IPS == 200, str(MAX_BATCH_IPS))

    over = b'ip\n' + b''.join(f'1.0.{n // 256}.{n % 256}\n'.encode() for n in range(MAX_BATCH_IPS + 5))
    r = with_stubs(client, 'many.csv', over, token)
    message = (r.get_json(silent=True) or {}).get('error', '')
    check('over-cap upload -> 400', r.status_code == 400, str(r.status_code))
    check('the rejection states the limit', str(MAX_BATCH_IPS) in message, repr(message))
    check('the rejection states the real reason',
          'per second' in message and 'timeout' in message, repr(message))

    # The cap counts what will be looked up, so a long file of duplicates is not rejected.
    duplicates = b'ip\n' + b'8.8.8.8\n' * (MAX_BATCH_IPS * 3)
    r = with_stubs(client, 'dupes.csv', duplicates, token)
    check('a file whose unique count is under the cap is accepted',
          r.status_code == 200 and len(rows_of(r)) == 1,
          f'{r.status_code} {r.get_data(as_text=True)[:160]!r}')


def test_detect_type_guard():
    for value in [123, True, None, 3.5, ['8.8.8.8'], {'ip': '8.8.8.8'}]:
        try:
            got = repr(_detect_type(value))
        except ValueError:
            got = None
        except Exception as exc:
            got = f'raised {exc!r}'
        check(f'_detect_type({value!r}) raises ValueError instead of coercing to an IP',
              got is None, f'got {got}')
    check('_detect_type still classifies strings',
          _detect_type('8.8.8.8') == ('ip', '8.8.8.8')
          and _detect_type('example.com') == ('domain', 'example.com')
          and _detect_type('https://example.com/a') == ('url', 'https://example.com/a'))


def main():
    app = create_app()
    client = app.test_client()

    test_csrf(client)
    token = csrf_token(client)
    test_column_shape(client, token)
    keyless = test_no_keys_configured(client, token)
    test_partial_sources(client, token)
    error_case = with_stubs(client, 'mixed.csv',
                            b'ip\n8.8.8.8\n192.168.1.1\n169.254.169.254\n', token,
                            vpn=VPN_OK, abuse=ABUSE_OK, ipinfo=IPINFO_OK, whois=WHOIS_OK)
    test_non_global_ips(client, token)
    test_headers_and_formats(client, token)
    test_dedup_and_ipv6(client, token)
    test_bad_uploads(client, token)
    test_cap(client, token)
    test_detect_type_guard()

    if os.getenv('SHOW_CSV'):
        print('--- keyless multi-source CSV ---')
        print(keyless.get_data(as_text=True))
        print('--- error-column CSV ---')
        print(error_case.get_data(as_text=True))

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {checks} checks')


if __name__ == '__main__':
    main()
