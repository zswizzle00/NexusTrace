"""GreyNoise, RDAP and Wayback: three keyless sources.

Keyless matters. Every other source on the IP and domain surfaces is skipped when its
key is unset, so a deployment that has configured nothing gets nothing. These three
always answer, which makes their failure modes more visible rather than less.

Two properties are load-bearing and each is pinned below:

1. A GreyNoise 404 is the "not observed" ANSWER, not an error. It is the common case
   and it is useful information.
2. A transient failure must never be memoized. web.archive.org's CDX latency was
   measured swinging between 2.2s and 10.0s for the same request seconds apart, and a
   cached timeout would turn one slow window into an hour of "no archive history",
   which reads as a finding rather than an absence.

No network: every case injects a transport.
"""
import os
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.services import domain_service, ip_service

failures = []
cases = 0


def check(condition, message):
    global cases
    cases += 1
    if not condition:
        failures.append(message)
    return bool(condition)


class FakeResponse:
    def __init__(self, payload, status_code=200, url='https://rdap.verisign.com/x', history=()):
        self._payload = payload
        self.status_code = status_code
        self.url = url
        self.history = list(history)

    def json(self):
        return self._payload


def transport_for(*responses):
    """A transport that returns each response in turn and counts its calls."""
    state = {'n': 0}

    def send(*_args, **_kwargs):
        index = min(state['n'], len(responses) - 1)
        state['n'] += 1
        item = responses[index]
        if isinstance(item, Exception):
            raise item
        return item

    send.calls = state
    return send


def fresh(name):
    """A domain/IP nobody else in this file used, so the lru_cache never hides a call."""
    return f'{name}-{time.time_ns()}.test'


def settle():
    """Let the 2-per-second limiters refill between cases."""
    time.sleep(0.6)


# --------------------------------------------------------------------- GreyNoise

def test_a_404_is_the_not_observed_answer():
    """THE case. GreyNoise returns 404 with a JSON body for any address it has never
    seen scanning. Treating that as an error discards the most valuable thing it says."""
    body = {'ip': '8.8.8.8', 'noise': False, 'riot': False,
            'message': 'IP not observed scanning the internet.'}
    result = ip_service.map_greynoise_response(body, status_code=404)
    check(result is not None, 'a 404 was mapped to nothing at all')
    check(result['observed'] is False, 'a 404 did not map to observed=False')
    check('not observed' in (result['message'] or '').lower(),
          f'the 404 message was lost: {result["message"]!r}')


def test_a_known_scanner_keeps_its_actor_name():
    body = {'ip': '71.6.135.131', 'noise': True, 'riot': False, 'classification': 'benign',
            'name': 'Shodan.io', 'last_seen': '2026-09-24', 'message': 'Success'}
    result = ip_service.map_greynoise_response(body)
    check(result['observed'] is True, 'a scanning address mapped to observed=False')
    check(result['classification'] == 'benign',
          f'classification lost: {result["classification"]!r}')
    check(result['actor'] == 'Shodan.io', f'actor name lost: {result["actor"]!r}')


def test_unknown_is_not_rendered_as_an_actor_name():
    """GreyNoise uses the literal string 'unknown' as its placeholder for an
    unattributed scanner. Passing it through invents an operator called "unknown"."""
    body = {'noise': True, 'riot': False, 'classification': 'suspicious', 'name': 'unknown'}
    check(ip_service.map_greynoise_response(body)['actor'] is None,
          'the placeholder "unknown" was rendered as an actor name')


def test_an_unrecognised_classification_is_dropped():
    """The card colours by classification, so an unexpected value must not reach it."""
    body = {'noise': True, 'classification': 'totally-new-value', 'name': 'x'}
    check(ip_service.map_greynoise_response(body)['classification'] is None,
          'an unrecognised classification was passed through to the template')


def test_greynoise_junk_input_returns_none():
    for junk in (None, [], 'a string', 42):
        check(ip_service.map_greynoise_response(junk) is None,
              f'{junk!r} did not map to None')


# --------------------------------------------------------------------- RDAP

def test_rdap_extracts_registration_and_age():
    """Domain age is why this source exists: it makes the strongest single phishing
    signal keyless, where IP2WHOIS needs a key and is skipped without one."""
    payload = {
        'events': [{'eventAction': 'registration', 'eventDate': '2007-10-09T18:20:50Z'},
                   {'eventAction': 'expiration', 'eventDate': '2027-10-09T18:20:50Z'}],
        'status': ['client delete prohibited'],
        'entities': [{'vcardArray': ['vcard', [['version', {}, 'text', '4.0'],
                                               ['fn', {}, 'text', 'MarkMonitor Inc.']]]}],
    }
    result = domain_service.map_rdap_response(payload)
    check(result['registered'] == '2007-10-09T18:20:50Z', 'registration date lost')
    check(result['registrar'] == 'MarkMonitor Inc.',
          f'registrar not pulled from the jCard: {result["registrar"]!r}')
    check(result['age_days'] and result['age_days'] > 6000,
          f'age_days looks wrong for a 2007 domain: {result["age_days"]}')
    check(result['status'] == ['client delete prohibited'], 'status codes lost')


def test_rdap_handles_a_record_with_nothing_useful():
    check(domain_service.map_rdap_response({'objectClassName': 'domain'}) is None,
          'a record with no events and no entities should map to None')
    check(domain_service.map_rdap_response('not a dict') is None,
          'a non-dict payload should map to None')


def test_rdap_refuses_a_redirect_off_https():
    """rdap.org bootstraps to a registry chosen by a third party, so the final host is
    not known ahead of time. Following it off HTTPS would be a downgrade."""
    response = FakeResponse({'events': []}, url='http://insecure.example/domain/x')
    check(domain_service.get_rdap_info(fresh('downgrade'), transport=transport_for(response)) is None,
          'a redirect to plain HTTP was accepted')
    settle()


def test_rdap_refuses_an_over_long_redirect_chain():
    response = FakeResponse({'events': []}, history=[object()] * 9)
    check(domain_service.get_rdap_info(fresh('chain'), transport=transport_for(response)) is None,
          'an over-long redirect chain was accepted')
    settle()


# --------------------------------------------------------------------- Wayback

def test_wayback_skips_the_header_row():
    """The CDX API returns its column names as row 0. Counting it as a capture would
    report history for a domain that has none."""
    check(domain_service.map_wayback_response([['timestamp']])['archived'] is False,
          'a header-only response was read as an archived capture')
    result = domain_service.map_wayback_response([['timestamp'], ['20080514210148']])
    check(result['archived'] is True, 'a real capture was not detected')
    check(result['first_seen'] == '2008-05-14',
          f'timestamp not formatted as a date: {result["first_seen"]!r}')


def test_wayback_junk_input_is_not_an_archive():
    for junk in (None, [], 'string', [[]], [['timestamp'], ['not-a-number']]):
        result = domain_service.map_wayback_response(junk)
        check(result['archived'] is False, f'{junk!r} was read as archived')


# ------------------------------------------------- caching, the shared property

def test_a_transient_failure_is_never_memoized():
    """A cached timeout turns one slow window into an hour of "no data". For Wayback
    that is worse than useless: "nothing archived" reads as a finding, so a stall would
    manufacture a signal."""
    for label, call, good in (
        ('rdap', domain_service.get_rdap_info,
         FakeResponse({'events': [{'eventAction': 'registration',
                                   'eventDate': '2020-01-01T00:00:00Z'}]})),
        ('wayback', domain_service.get_wayback_history,
         FakeResponse([['timestamp'], ['20080514210148']])),
        ('greynoise', ip_service.get_greynoise_data,
         FakeResponse({'noise': True, 'classification': 'benign', 'name': 'Shodan.io'})),
    ):
        target = fresh(label)
        send = transport_for(requests.Timeout('simulated stall'), good)
        first = call(target, transport=send)
        settle()
        second = call(target, transport=send)
        check(first is None, f'{label}: a timeout did not surface as None')
        check(second is not None,
              f'{label}: the retry returned nothing, so the failure was memoized')
        check(send.calls['n'] == 2,
              f'{label}: transport called {send.calls["n"]} times, expected 2')
        settle()


def test_a_success_is_memoized():
    target = fresh('cached')
    send = transport_for(FakeResponse({'events': [{'eventAction': 'registration',
                                                   'eventDate': '2020-01-01T00:00:00Z'}]}))
    first = domain_service.get_rdap_info(target, transport=send)
    second = domain_service.get_rdap_info(target, transport=send)
    check(first is not None and first == second, 'the two calls disagreed')
    check(send.calls['n'] == 1,
          f'a success was not cached: transport called {send.calls["n"]} times')
    settle()



# ------------------------------------------------------------------- rendering

def _render(**overrides):
    """The rendered page with whitespace collapsed.

    Flattening is not cosmetic. The templates wrap their prose, so a contiguous-string
    assertion against raw HTML can miss a caveat that is present but split across two
    lines. That is merely annoying for an `in` assertion and dangerous for a `not in`
    one: `check('no archive history' not in body)` would pass silently the moment the
    template reflowed, while the card said exactly the wrong thing.
    """
    from app import create_app
    app = create_app()
    context = dict(indicator='x', error=None, card_count=1, alienvault=None,
                   domain_info=None, url_analysis=None, whois_info=None, abuseipdb=None,
                   tf_env=None, uh_env=None, greynoise=None, registration=None,
                   archive=None, internetdb=None, stopforumspam=None, ripestat=None)
    context.update(overrides)
    with app.test_request_context('/'):
        return ' '.join(
            app.jinja_env.get_template('analyze_result.html').render(**context).split())


def test_a_failed_archive_lookup_never_reads_as_no_history():
    """The one that matters. "Nothing archived" is a signal; "we could not check" is
    not. CDX latency swings between 2s and 10s for identical requests, so a timeout is
    routine, and rendering it as an absence would manufacture a finding on every slow
    request."""
    body = _render(registration={'registered': '2001-10-02T00:00:00Z', 'age_days': 9123,
                                 'registrar': 'MarkMonitor', 'expires': None, 'status': []},
                   archive=None)
    check('could not be checked' in body,
          'a failed archive lookup did not say so')
    check('no archive history' not in body,
          'a FAILED archive lookup rendered as "no archive history", inventing a signal')


def test_a_genuinely_unarchived_domain_says_so():
    body = _render(registration={'registered': '2026-09-20T00:00:00Z', 'age_days': 4,
                                 'registrar': 'NameSilo', 'expires': None, 'status': []},
                   archive={'archived': False, 'first_seen': None})
    check('no archive history' in body, 'a genuinely unarchived domain did not say so')
    check('registered recently' in body, 'a 4-day-old domain was not flagged as recent')


def test_greynoise_renders_without_any_other_ip_source():
    """It is the only keyless IP source, so on a deployment with no keys it is the only
    thing that can answer. If it were left out of the card-grid condition, a lookup that
    found something would render as if it had found nothing."""
    body = _render(greynoise={'observed': True, 'noise': True, 'riot': False,
                              'classification': 'benign', 'actor': 'Shodan.io',
                              'last_seen': '2026-09-24', 'link': None, 'message': 'Success'})
    check('GreyNoise' in body, 'the GreyNoise card did not render on its own')
    check('Shodan.io' in body, 'the actor name did not reach the page')


def test_not_observed_does_not_read_as_clean():
    """GreyNoise not seeing an address means it is not mass-scanning. Targeted traffic
    looks the same, so the copy must not imply the address was cleared."""
    body = _render(greynoise={'observed': False, 'noise': False, 'riot': False,
                              'classification': None, 'actor': None, 'last_seen': None,
                              'link': None, 'message': 'IP not observed scanning the internet.'})
    check('not a clean result' in body,
          'the not-observed card is missing its caveat and reads as an all-clear')



# ------------------------------------------- Shodan InternetDB and StopForumSpam

def test_internetdb_maps_the_fields_that_matter():
    payload = {'ip': '185.220.101.1', 'ports': [443, 80, 9001], 'hostnames': ['exit.example'],
               'tags': ['tor', 'self-signed'], 'vulns': ['CVE-2021-44228'],
               'cpes': ['cpe:/a:f5:nginx']}
    result = ip_service.map_internetdb_response(payload)
    check(result['ports'] == [80, 443, 9001], f'ports not sorted: {result["ports"]}')
    check(result['tags'] == ['tor', 'self-signed'], 'tags lost')
    check(result['vulns'] == ['CVE-2021-44228'], 'CVE list lost')
    check(result['port_count'] == 3, 'port_count wrong')


def test_internetdb_maps_an_empty_record_to_nothing():
    """Shodan returns a well-formed record with every list empty for an address it has
    indexed but learned nothing about. A card saying "ports: none, tags: none" is noise."""
    empty = {'ip': '1.2.3.4', 'ports': [], 'hostnames': [], 'tags': [], 'vulns': [], 'cpes': []}
    check(ip_service.map_internetdb_response(empty) is None,
          'an all-empty InternetDB record produced a card')
    check(ip_service.map_internetdb_response('junk') is None, 'junk did not map to None')


def test_internetdb_caps_its_lists():
    """The record is rendered and may be stored. A host with 900 open ports must not
    produce a 900-entry row."""
    payload = {'ports': list(range(1, 900)), 'hostnames': [f'h{i}.test' for i in range(80)],
               'vulns': [f'CVE-2024-{i:05d}' for i in range(200)], 'tags': [], 'cpes': []}
    result = ip_service.map_internetdb_response(payload)
    check(len(result['ports']) <= ip_service.MAX_PORTS, 'port list not capped')
    check(len(result['hostnames']) <= ip_service.MAX_HOSTNAMES, 'hostname list not capped')
    check(len(result['vulns']) <= ip_service.MAX_VULNS, 'CVE list not capped')
    check(result['port_count'] == 899,
          'the true count was lost when the list was capped, so the card cannot say '
          '"and N more"')


def test_stopforumspam_keeps_the_tor_exit_flag():
    """The reason this source is here. NexusTrace has no other independent Tor signal."""
    payload = {'success': 1, 'ip': {'value': '185.220.101.1', 'appears': 1, 'frequency': 91,
                                    'lastseen': '2026-09-19 20:09:07', 'torexit': 1,
                                    'asn': 60729, 'country': 'de', 'confidence': 95.29}}
    result = ip_service.map_stopforumspam_response(payload)
    check(result['tor_exit'] is True, 'the Tor exit flag was lost')
    check(result['frequency'] == 91, 'the report count was lost')
    check(result['country'] == 'DE', f'country not upper-cased: {result["country"]!r}')
    check(result['confidence'] == 95.3, f'confidence not rounded: {result["confidence"]}')


def test_stopforumspam_says_nothing_about_a_clean_address():
    """appears 0 and no Tor flag is not a finding, so it must not render a card that
    invites an analyst to read one."""
    payload = {'success': 1, 'ip': {'value': '8.8.8.8', 'frequency': 0, 'appears': 0,
                                    'asn': 15169, 'country': 'us'}}
    check(ip_service.map_stopforumspam_response(payload) is None,
          'a clean address produced a StopForumSpam card')
    check(ip_service.map_stopforumspam_response({'success': 0}) is None,
          'an unsuccessful response produced a card')


def test_a_tor_exit_renders_both_signals():
    body = _render(internetdb={'ports': [9001], 'port_count': 1, 'hostnames': [],
                               'hostname_count': 0, 'vulns': [], 'vuln_count': 0,
                               'tags': ['tor'], 'cpes': []},
                   stopforumspam={'appears': True, 'frequency': 91,
                                  'last_seen': '2026-09-19 20:09:07', 'tor_exit': True,
                                  'country': 'DE', 'asn': 60729, 'confidence': 95.3})
    check('Known Tor exit node' in body, 'the Tor exit flag did not reach the page')
    check('narrower than' in body,
          'the forum-spam card is missing its scope caveat, so the count over-reads')


def test_internetdb_cves_are_leads_not_findings():
    """Shodan matches CVEs against a detected software VERSION. A backported patch keeps
    the version string, so presenting these as confirmed findings would be wrong."""
    body = _render(internetdb={'ports': [443], 'port_count': 1, 'hostnames': [],
                               'hostname_count': 0, 'vulns': ['CVE-2021-44228'],
                               'vuln_count': 1, 'tags': [], 'cpes': []})
    check('CVE-2021-44228' in body, 'the CVE did not render')
    check('leads to check' in body, 'the CVE caveat about version matching is missing')



def test_ripestat_extracts_the_abuse_contact():
    """The question nothing else in this app answers: who do I report this to."""
    payload = {'data': {'abuse_contacts': ['abuse@artikel10.org'],
                        'authoritative_rir': 'ripe'}}
    result = ip_service.map_ripestat_abuse(payload)
    check(result['contacts'] == ['abuse@artikel10.org'], 'the contact was lost')
    check(result['rir'] == 'RIPE', f'rir not upper-cased: {result["rir"]!r}')


def test_ripestat_with_no_contact_renders_nothing():
    """RIPE returns a well-formed response with an empty list for an address whose
    holder registered no abuse mailbox. An empty card would be noise."""
    for payload in ({'data': {'abuse_contacts': []}}, {'data': {}}, {}, 'junk',
                    {'data': {'abuse_contacts': ['not-an-address']}}):
        check(ip_service.map_ripestat_abuse(payload) is None,
              f'{payload!r} produced an abuse-contact card')


def test_the_abuse_contact_is_not_presented_as_evidence():
    """A reputable host and a bulletproof one both register an abuse mailbox, so the
    presence of a contact must not read as a finding about the address."""
    body = _render(ripestat={'contacts': ['abuse@example.net'], 'rir': 'RIPE'})
    flat = body
    check('abuse@example.net' in body, 'the contact did not reach the page')
    check('says nothing about the address' in flat,
          'the abuse-contact card is missing its caveat')
    card = flat.split('Abuse Contact')[-1][:900]
    for verdict in ('malicious', 'suspicious', 'Malicious', 'Suspicious'):
        check(verdict not in card,
              f'the abuse-contact card rendered a verdict word: {verdict!r}')


def main():
    test_a_404_is_the_not_observed_answer()
    test_a_known_scanner_keeps_its_actor_name()
    test_unknown_is_not_rendered_as_an_actor_name()
    test_an_unrecognised_classification_is_dropped()
    test_greynoise_junk_input_returns_none()
    test_rdap_extracts_registration_and_age()
    test_rdap_handles_a_record_with_nothing_useful()
    test_rdap_refuses_a_redirect_off_https()
    test_rdap_refuses_an_over_long_redirect_chain()
    test_wayback_skips_the_header_row()
    test_wayback_junk_input_is_not_an_archive()
    test_a_transient_failure_is_never_memoized()
    test_a_success_is_memoized()
    test_a_failed_archive_lookup_never_reads_as_no_history()
    test_a_genuinely_unarchived_domain_says_so()
    test_greynoise_renders_without_any_other_ip_source()
    test_not_observed_does_not_read_as_clean()
    test_internetdb_maps_the_fields_that_matter()
    test_internetdb_maps_an_empty_record_to_nothing()
    test_internetdb_caps_its_lists()
    test_stopforumspam_keeps_the_tor_exit_flag()
    test_stopforumspam_says_nothing_about_a_clean_address()
    test_a_tor_exit_renders_both_signals()
    test_internetdb_cves_are_leads_not_findings()
    test_ripestat_extracts_the_abuse_contact()
    test_ripestat_with_no_contact_renders_nothing()
    test_the_abuse_contact_is_not_presented_as_evidence()

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {cases} cases')


if __name__ == '__main__':
    main()
