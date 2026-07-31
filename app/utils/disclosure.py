"""Where a submission goes and what is kept, per upload surface.

Backs ``templates/_use_notice.html``. The registry lives here rather than in the template
so ``app/tests/test_disclosure.py`` can hold it against the service layer: that test walks
every string constant in ``app/services/*.py``, pulls out the hostnames, and fails when
one is not classified below.

**The check sees URL literals, not clients.** A provider reached through a library that
builds its own URLs has no hostname in this tree. Shodan is the only one, so it is listed
by hand and the test cannot police it.
"""

from collections import namedtuple

# ``hosts`` is what test_disclosure.py matches against the service layer; it is not
# rendered. ``when`` separates a lookup the app performs from a pivot link it draws:
# ON_CLICK parties receive nothing unless the analyst follows the link.
Party = namedtuple('Party', 'key name hosts sends when')

Surface = namedtuple('Surface', 'label sends retained retention parties')

ALWAYS = 'always'
ON_CLICK = 'on_click'

RETENTION_DAYS = 30

RETENTION = (f'Records are kept for up to {RETENTION_DAYS} days and can be deleted '
             f'from the result page at any time.')

PARTIES = (
    Party('target_site', 'the site being scanned', (),
          'the full URL, fetched from this server', ALWAYS),
    # Rendered escaped, so keep them free of characters Jinja would turn into entities.
    Party('sender_site', 'the sender domain itself', (),
          'a TLS connection from this server to read its certificate', ALWAYS),
    Party('dns', 'public DNS', (), 'domain names and IP addresses', ALWAYS),
    # One party, three zones: the ASN zones carry IP addresses and the Malware Hash
    # Registry zone carries hashes, but it is one operator and one account-free service.
    Party('cymru', 'Team Cymru', ('asn.cymru.com', 'origin.asn.cymru.com',
                                  'malware.hash.cymru.com', 'team-cymru.com'),
          'IP addresses and file hashes, as DNS queries', ALWAYS),
    Party('circl', 'CIRCL hashlookup', ('hashlookup.circl.lu',), 'file hashes', ALWAYS),
    Party('ip2whois', 'IP2WHOIS', ('api.ip2whois.com',), 'domain names', ALWAYS),
    Party('abuseipdb', 'AbuseIPDB', ('api.abuseipdb.com',), 'IP addresses', ALWAYS),
    Party('vpnapi', 'VPNAPI.io', ('vpnapi.io',), 'IP addresses', ALWAYS),
    Party('otx', 'AlienVault OTX', ('otx.alienvault.com',),
          'IP addresses, domains and file hashes', ALWAYS),
    Party('virustotal', 'VirusTotal', ('www.virustotal.com',), 'file hashes', ALWAYS),
    Party('abusech', 'abuse.ch (MalwareBazaar, ThreatFox, URLhaus)',
          ('abuse.ch', 'auth.abuse.ch', 'mb-api.abuse.ch', 'bazaar.abuse.ch',
           'threatfox-api.abuse.ch', 'threatfox.abuse.ch', 'urlhaus-api.abuse.ch',
           'urlhaus.abuse.ch', 'hunting-api.abuse.ch', 'hunting.abuse.ch'),
          'file hashes and URLs', ALWAYS),
    Party('spamhaus', 'Spamhaus', ('zen.spamhaus.org',),
          'sending IP addresses, as DNS queries', ALWAYS),
    Party('spamcop', 'SpamCop', ('bl.spamcop.net',),
          'sending IP addresses, as DNS queries', ALWAYS),
    Party('barracuda', 'Barracuda Central', ('b.barracudacentral.org',),
          'sending IP addresses, as DNS queries', ALWAYS),
    Party('ipinfo', 'IPinfo', ('ipinfo.io', 'api.ipinfo.io'), 'IP addresses', ALWAYS),
    Party('ip2location', 'IP2Location', ('ip2location.io', 'api.ip2location.io'),
          'IP addresses', ALWAYS),
    Party('ipapi', 'IP-API', ('ip-api.com',), 'IP addresses', ALWAYS),
    Party('proxycheck', 'ProxyCheck.io', ('proxycheck.io',), 'IP addresses', ALWAYS),
    # No URL literal anywhere in the tree: the shodan package builds its own.
    Party('shodan', 'Shodan', ('api.shodan.io',), 'IP addresses', ALWAYS),
    Party('hackertarget', 'HackerTarget', ('api.hackertarget.com',),
          'IP addresses', ALWAYS),
    Party('crtsh', 'crt.sh', ('crt.sh',), 'domain names', ALWAYS),
    Party('urlscan', 'urlscan.io', ('urlscan.io',), 'URLs', ALWAYS),
    Party('microsoft', 'Microsoft', ('login.microsoftonline.com',),
          'AADSTS error codes', ALWAYS),
    Party('uws', 'Ultimate Windows Security', ('www.ultimatewindowssecurity.com',),
          'Windows Event IDs', ALWAYS),
    Party('talos', 'Cisco Talos', ('talosintelligence.com',), 'domain names', ON_CLICK),
    Party('phishtank', 'PhishTank', ('phishtank.org',), 'domains and URLs', ON_CLICK),
    Party('safebrowsing', 'Google Safe Browsing',
          ('transparencyreport.google.com',), 'URLs', ON_CLICK),
    Party('hybrid_analysis', 'Hybrid Analysis', ('www.hybrid-analysis.com',),
          'file hashes', ON_CLICK),
    Party('anyrun', 'ANY.RUN', ('any.run',), 'file hashes', ON_CLICK),
    Party('joesandbox', 'Joe Sandbox', ('www.joesandbox.com',), 'file hashes', ON_CLICK),
)

# Hostnames that appear in app/services/*.py but are not somewhere a submission is
# sent. Each needs a reason, because the coverage test treats this set as a waiver.
NOT_A_DESTINATION = {
    'asp.net': 'a technology name in scan_service._TECH_RULES, never a request target',
}

SURFACES = {
    'url_scan': Surface(
        label='URL scan',
        sends='the URL, its domain and the IP addresses it resolves to',
        retained=('the URL, screenshots, page text, every HTTP transaction, cookies '
                  'and the extracted indicators'),
        retention=RETENTION,
        parties=('target_site', 'dns', 'cymru', 'ip2whois'),
    ),
    'email': Surface(
        label='e-mail analysis',
        sends=('the sender domain, the Received-chain IP addresses and attachment '
               'SHA-256 hashes (never the message, its body or its attachments)'),
        retained=('parsed findings only: headers, the Received chain, attachment '
                  'names and hashes, and the extracted indicators. The message, its '
                  'body and attachment bytes are never written to disk'),
        retention=RETENTION,
        parties=('dns', 'sender_site', 'ip2whois', 'vpnapi', 'abuseipdb', 'otx',
                 'virustotal', 'abusech', 'circl', 'cymru', 'spamhaus', 'spamcop',
                 'barracuda', 'hybrid_analysis', 'anyrun', 'joesandbox'),
    ),
    'file': Surface(
        label='file analysis',
        sends='the SHA-256 and MD5 hashes of the sample (never the file itself)',
        retained=('nothing. The sample is written to a temporary file, analysed, and '
                  'deleted before the page renders'),
        retention=None,
        parties=('virustotal', 'abusech', 'otx', 'circl', 'cymru',
                 'hybrid_analysis', 'anyrun', 'joesandbox'),
    ),
}

_BY_KEY = {party.key: party for party in PARTIES}


def parties_for(surface):
    """(always, on_click) party tuples for one surface, in registry order. Raises
    ValueError for an unknown surface: the name is a literal in a template, so a typo
    must fail loudly rather than render an empty notice."""
    if surface not in SURFACES:
        raise ValueError(f'unknown disclosure surface {surface!r}')
    keys = SURFACES[surface].parties
    selected = [_BY_KEY[key] for key in keys]
    return (tuple(p for p in selected if p.when == ALWAYS),
            tuple(p for p in selected if p.when == ON_CLICK))


def for_template(surface):
    entry = SURFACES[surface] if surface in SURFACES else None
    if entry is None:
        raise ValueError(f'unknown disclosure surface {surface!r}')
    always, on_click = parties_for(surface)
    return {
        'label': entry.label,
        'sends': entry.sends,
        'retained': entry.retained,
        'retention': entry.retention,
        'always': [p.name for p in always],
        'on_click': [p.name for p in on_click],
    }


def setup_disclosure(app):
    app.jinja_env.globals['disclosure_for'] = for_template
