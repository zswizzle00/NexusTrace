"""Tests for app/utils/location_summary.py and the Location and Network card it feeds."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.utils.location_summary import reporting_sources, summarize

failures = []
cases = 0


def case(condition, message):
    global cases
    cases += 1
    if not condition:
        failures.append(message)


IPINFO = {'ip': '192.0.2.10', 'country': 'United States', 'country_code': 'US',
          'asn': 'AS64500', 'as_name': 'Example Net', 'as_domain': 'example.net',
          'hostname': 'host.example.net'}
IP2LOCATION = {'ip': '192.0.2.10', 'country_name': 'United States of America', 'country_code': 'US',
               'region_name': 'California', 'city_name': 'San Jose', 'latitude': 37.3382,
               'longitude': -121.8863, 'time_zone': '-08:00', 'asn': '64500', 'isp': 'Example Net'}
VPNAPI = {'location': {'country': 'United States', 'country_code': 'US', 'city': 'Dallas',
                       'latitude': 32.78, 'longitude': -96.80, 'time_zone': 'America/Chicago'},
          'network': {'autonomous_system_number': 'AS64500',
                      'autonomous_system_organization': 'Example Net', 'network': '192.0.2.0/24'},
          'security': {'vpn': False}}
PROXYCHECK = {'proxycheck': {'country': 'United States', 'isocode': 'US', 'city': 'San Jose',
                             'latitude': 37.34, 'longitude': -121.89, 'asn': 'AS64500',
                             'provider': 'Example Net', 'organisation': 'Upstream Transit',
                             'range': '192.0.2.0/24'}}
SHODAN = {'summary': {'country_name': 'United States', 'city': 'San Jose', 'isp': 'Example Net',
                      'org': 'Example Net'}, 'raw': {}, 'tables': {}}
ABUSEIPDB = {'summary': {'countryName': 'United States of America', 'isp': 'Example Net',
                         'domain': 'example.net', 'usageType': 'Data Center/Web Hosting/Transit'}}


def rows_by_label(**sources):
    return {row['label']: row for row in summarize(**sources)}


def test_one_answer_per_fact():
    rows = rows_by_label(ipinfo=IPINFO, ip2location=IP2LOCATION, vpnapi=VPNAPI,
                         proxycheck=PROXYCHECK, shodan=SHODAN, abuseipdb=ABUSEIPDB)
    country = rows['Country']
    case(country['agree'] and len(country['values']) == 1,
         f'country names for the same ISO code were not merged: {country}')
    case(set(country['values'][0]['sources']) == {'IPinfo', 'IP2Location', 'VPNapi', 'ProxyCheck',
                                                    'Shodan', 'AbuseIPDB'},
         'a provider that gave only a country name did not borrow the code')
    case(rows['ASN']['agree'] and rows['ASN']['values'][0]['value'] == 'AS64500',
         f'ASN forms (64500, AS64500) were not normalized: {rows["ASN"]}')
    case(rows['ISP']['agree'], 'identical ISPs were reported as a disagreement')


def test_disagreements_stay_visible():
    rows = rows_by_label(ipinfo=IPINFO, ip2location=IP2LOCATION, vpnapi=VPNAPI,
                         proxycheck=PROXYCHECK, shodan=SHODAN)
    city = rows['City']
    case(not city['agree'], 'two different cities were merged')
    case(city['values'][0]['value'] == 'San Jose' and city['values'][0]['sources'] ==
         ['IP2Location', 'ProxyCheck', 'Shodan'],
         f'the majority city is not listed first with its sources: {city["values"]}')
    case(any(v['value'] == 'Dallas' and v['sources'] == ['VPNapi'] for v in city['values']),
         'the minority city was dropped')
    coordinates = rows['Coordinates']
    case(len(coordinates['values']) == 2,
         f'coordinates within rounding were not grouped: {coordinates["values"]}')
    case(not rows['Organization']['agree'], 'differing organizations were merged')


def test_nothing_in_nothing_out():
    case(summarize() == [], 'no providers produced rows')
    case(summarize(ipinfo={}, proxycheck={'proxycheck': {}}) == [], 'empty payloads produced rows')
    case(reporting_sources(ipinfo=IPINFO) == ['IPinfo'], 'reporting sources are wrong')


def test_the_card_renders():
    os.environ.setdefault('SECRET_KEY', 'test-only')
    from app import create_app
    app = create_app()
    with app.test_request_context('/'):
        html = app.jinja_env.get_template('analyze_result.html').render(
            indicator='192.0.2.10', indicator_type='ip', card_count=6, ipinfo=IPINFO,
            ip2location=IP2LOCATION, vpnapi=VPNAPI, proxycheck=PROXYCHECK, shodan=SHODAN,
            abuseipdb=dict(ABUSEIPDB, raw={}, tables={'reports': []}))
        only_one = app.jinja_env.get_template('analyze_result.html').render(
            indicator='192.0.2.10', indicator_type='ip', card_count=1, ip2location=IP2LOCATION)
    case('Location and Network' in only_one, 'the card failed with IP2Location alone')
    case('Location and Network' in html, 'the Location and Network card did not render')
    case('sources differ' in html, 'a disagreement was not flagged on the card')
    title = 'class="nt-card__title">{}<'.format
    case(title('IPInfo') not in html and title('IP2Location') not in html,
         'IPinfo or IP2Location still has a card of its own')
    case('host.example.net' in html, 'an IPinfo-only detail (hostname) was lost')
    case(html.index(title('AbuseIPDB')) < html.index(title('Location and Network'))
         < html.index(title('Shodan')),
         'cards are not in reputation, location, infrastructure order')


TESTS = [test_one_answer_per_fact, test_disagreements_stay_visible, test_nothing_in_nothing_out,
         test_the_card_renders]


def main():
    for test in TESTS:
        try:
            test()
        except Exception as exc:  # noqa: BLE001 - an escaping exception IS a failure
            import traceback
            failures.append(f'{test.__name__} raised {exc!r}\n'
                            + ''.join(traceback.format_tb(exc.__traceback__)))
    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {cases} location summary cases')


if __name__ == '__main__':
    main()
