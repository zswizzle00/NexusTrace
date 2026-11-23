"""One view of where an IP is and who runs it, across every provider that answered.

IPinfo, IP2Location, VPNapi, ProxyCheck, Shodan and AbuseIPDB each report country, city,
ISP, ASN and so on, and the result page used to repeat those rows in every card. This
folds them into one list of facts. Each fact keeps every distinct value with the
providers that gave it, so a disagreement (two cities, two time zones) stays visible
instead of being resolved silently.

Pure functions over the provider payloads the result template already receives; no I/O.
"""
import re

SOURCES = ('IPinfo', 'IP2Location', 'VPNapi', 'ProxyCheck', 'Shodan', 'AbuseIPDB')


def _get(data, *path):
    for key in path:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def _first(data, *keys):
    for key in keys:
        value = _get(data, *key.split('.'))
        if value not in (None, '', [], {}):
            return value
    return None


def _asn(value):
    if value in (None, ''):
        return None
    digits = re.sub(r'\D', '', str(value).split()[0] if str(value).strip() else '')
    return f'AS{digits}' if digits else str(value)


def _coordinates(lat, lon):
    # One decimal (about 10 km): IP geolocation is no more precise than that, and finer
    # rounding splits providers that agree on the place into separate answers.
    try:
        return f'{float(lat):.1f}, {float(lon):.1f}'
    except (TypeError, ValueError):
        return None


def _ipinfo_coordinates(loc):
    if isinstance(loc, str) and ',' in loc:
        return _coordinates(*loc.split(',', 1))
    return None


def _proxycheck(payload):
    """ProxyCheck nests its answer under the queried address or under 'proxycheck'."""
    if not isinstance(payload, dict):
        return {}
    inner = payload.get('proxycheck')
    return inner if isinstance(inner, dict) else payload


def _sources(ipinfo, ip2location, vpnapi, proxycheck, shodan, abuseipdb):
    pc = _proxycheck(proxycheck)
    sh = _get(shodan, 'summary') or {}
    ab = _get(abuseipdb, 'summary') or {}
    return {
        'IPinfo': {
            'country': (ipinfo or {}).get('country'), 'country_code': (ipinfo or {}).get('country_code'),
            'region': (ipinfo or {}).get('region'), 'city': (ipinfo or {}).get('city'),
            'postal': (ipinfo or {}).get('postal'), 'timezone': (ipinfo or {}).get('timezone'),
            'coordinates': _ipinfo_coordinates((ipinfo or {}).get('loc')),
            'isp': _first(ipinfo, 'as_name'), 'organization': _first(ipinfo, 'org'),
            'asn': _asn(_first(ipinfo, 'asn')), 'domain': _first(ipinfo, 'as_domain'),
        },
        'IP2Location': {
            'country': _first(ip2location, 'country_name'), 'country_code': _first(ip2location, 'country_code'),
            'region': _first(ip2location, 'region_name', 'region'), 'city': _first(ip2location, 'city_name', 'city'),
            'postal': _first(ip2location, 'zip_code', 'zipcode'), 'timezone': _first(ip2location, 'time_zone', 'timezone'),
            'coordinates': _coordinates(_first(ip2location, 'latitude'), _first(ip2location, 'longitude')),
            'isp': _first(ip2location, 'isp', 'as'), 'asn': _asn(_first(ip2location, 'asn')),
            'domain': _first(ip2location, 'domain'), 'usage': _first(ip2location, 'usage_type'),
        },
        'VPNapi': {
            'country': _first(vpnapi, 'location.country'), 'country_code': _first(vpnapi, 'location.country_code'),
            'region': _first(vpnapi, 'location.region'), 'city': _first(vpnapi, 'location.city'),
            'timezone': _first(vpnapi, 'location.time_zone'),
            'coordinates': _coordinates(_first(vpnapi, 'location.latitude'), _first(vpnapi, 'location.longitude')),
            'isp': _first(vpnapi, 'network.autonomous_system_organization'),
            'asn': _asn(_first(vpnapi, 'network.autonomous_system_number')),
            'network': _first(vpnapi, 'network.network'),
        },
        'ProxyCheck': {
            'country': _first(pc, 'country'), 'country_code': _first(pc, 'isocode'),
            'region': _first(pc, 'region'), 'city': _first(pc, 'city'),
            'postal': _first(pc, 'postcode'), 'timezone': _first(pc, 'timezone'),
            'coordinates': _coordinates(_first(pc, 'latitude'), _first(pc, 'longitude')),
            'isp': _first(pc, 'provider', 'isp'), 'organization': _first(pc, 'organisation'),
            'asn': _asn(_first(pc, 'asn')), 'network': _first(pc, 'range'),
        },
        'Shodan': {
            'country': _first(sh, 'country', 'country_name'), 'country_code': _first(sh, 'country_code'),
            'city': _first(sh, 'city'),
            'isp': _first(sh, 'isp'), 'organization': _first(sh, 'org', 'organization'),
            'asn': _asn(_first(sh, 'asn')),
        },
        'AbuseIPDB': {
            'country': _first(ab, 'countryName', 'country_name', 'country'),
            'country_code': _first(ab, 'countryCode', 'country_code'),
            'isp': _first(ab, 'isp'), 'domain': _first(ab, 'domain'),
            'usage': _first(ab, 'usageType', 'usage_type'),
        },
    }


FIELDS = (
    ('country', 'Country'),
    ('region', 'Region'),
    ('city', 'City'),
    ('postal', 'Postal code'),
    ('coordinates', 'Coordinates'),
    ('timezone', 'Time zone'),
    ('isp', 'ISP'),
    ('organization', 'Organization'),
    ('asn', 'ASN'),
    ('network', 'Network'),
    ('domain', 'Domain'),
    ('usage', 'Usage type'),
)


def _normal(value):
    return re.sub(r'[\s.,]+', ' ', str(value)).strip().casefold()


def _key(field, value, record, country_codes):
    # Countries are grouped by ISO code, so "United States" and "United States of
    # America" count as the same answer. A provider that gives only a name borrows the
    # code another provider gave for that same name.
    if field == 'country':
        code = record.get('country_code') or country_codes.get(_normal(value))
        if code:
            return 'code:' + str(code).upper()
    return _normal(value)


def summarize(ipinfo=None, ip2location=None, vpnapi=None, proxycheck=None, shodan=None,
              abuseipdb=None):
    """[{'label', 'values': [{'value', 'sources': [...]}], 'agree'}] for each fact at
    least one provider reported, in FIELDS order. Values are ordered by how many
    providers gave them, then by provider order."""
    records = _sources(ipinfo, ip2location, vpnapi, proxycheck, shodan, abuseipdb)
    country_codes = {_normal(r['country']): r['country_code'] for r in records.values()
                     if r.get('country') and r.get('country_code')}
    rows = []
    for field, label in FIELDS:
        groups = {}
        for source in SOURCES:
            record = records[source]
            value = record.get(field)
            if value in (None, ''):
                continue
            group = groups.setdefault(_key(field, value, record, country_codes),
                                      {'value': str(value), 'sources': []})
            group['sources'].append(source)
        if groups:
            values = sorted(groups.values(), key=lambda g: -len(g['sources']))
            rows.append({'label': label, 'values': values, 'agree': len(values) == 1})
    return rows


def reporting_sources(ipinfo=None, ip2location=None, vpnapi=None, proxycheck=None,
                      shodan=None, abuseipdb=None):
    """Providers that contributed at least one fact, in provider order."""
    seen = []
    for row in summarize(ipinfo, ip2location, vpnapi, proxycheck, shodan, abuseipdb):
        for group in row['values']:
            seen.extend(s for s in group['sources'] if s not in seen)
    return [s for s in SOURCES if s in seen]
