import ipaddress
import re
import logging
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Blueprint, request, jsonify

from app.utils.api_auth import require_api_key

logger = logging.getLogger(__name__)

enrichment_bp = Blueprint('enrichment', __name__)

MAX_BATCH_SIZE = 20

_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9]'
    r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
    r'+[a-zA-Z]{2,}$'
)


def _detect_type(indicator):
    """Return 'ip', 'url', or 'domain'. Raises ValueError if unknown."""
    try:
        ipaddress.ip_address(indicator)
        return 'ip'
    except ValueError:
        pass
    if re.match(r'^https?://', indicator, re.IGNORECASE):
        return 'url'
    if _DOMAIN_RE.match(indicator):
        return 'domain'
    raise ValueError(f"Cannot determine indicator type for: {indicator!r}")


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


# ---------------------------------------------------------------------------
# IP enrichment
# ---------------------------------------------------------------------------

def _enrich_ip(ip):
    from app.services.ip_service import (
        get_vpn_data,
        get_ipinfo_data,
        check_abuseipdb,
        get_shodan_info,
        get_alienvault_data,
    )

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(get_vpn_data, ip): 'vpnapi',
            executor.submit(get_ipinfo_data, ip): 'ipinfo',
            executor.submit(check_abuseipdb, ip): 'abuseipdb',
            executor.submit(get_shodan_info, ip): 'shodan',
            executor.submit(get_alienvault_data, ip): 'alienvault',
        }
        sources = {}
        for future in as_completed(futures):
            key = futures[future]
            try:
                sources[key] = future.result()
            except Exception as exc:
                logger.warning("IP enrichment source %s failed: %s", key, exc)
                sources[key] = None

    vpn = sources.get('vpnapi') or {}
    security = vpn.get('security', {})
    ipinfo = sources.get('ipinfo') or {}
    abuse = sources.get('abuseipdb') or {}
    shodan = sources.get('shodan') or {}
    alienvault = sources.get('alienvault') or {}

    general = alienvault.get('general', {})
    threat_pulse_count = general.get('pulse_info', {}).get('count', 0) if general else 0

    open_ports = [p.get('port') for p in shodan.get('ports', []) if p.get('port') is not None]

    network = vpn.get('network', {}) or {}
    location = vpn.get('location', {}) or {}

    summary = {
        'country': location.get('country') or ipinfo.get('country'),
        'city': location.get('city') or ipinfo.get('city'),
        'region': location.get('region') or ipinfo.get('region'),
        'asn': network.get('autonomous_system_number') or ipinfo.get('asn'),
        'org': network.get('autonomous_system_organization') or ipinfo.get('org'),
        'is_vpn': security.get('vpn', False),
        'is_proxy': security.get('proxy', False),
        'is_tor': security.get('tor', False),
        'abuse_score': abuse.get('abuse_confidence_score', 0),
        'total_abuse_reports': abuse.get('total_reports', 0),
        'threat_pulse_count': threat_pulse_count,
        'open_ports': open_ports,
    }

    def _clean_shodan(s):
        if not s:
            return None
        return {
            'ip': s.get('ip'),
            'organization': s.get('organization'),
            'isp': s.get('isp'),
            'operating_system': s.get('operating_system'),
            'hostnames': s.get('hostnames'),
            'domains': s.get('domains'),
            'country_name': s.get('country_name'),
            'city': s.get('city'),
            'last_update': s.get('last_update'),
            'tags': s.get('tags'),
            'ports': [
                {k: v for k, v in p.items() if k not in ('http', 'ssl', 'banner')}
                for p in (s.get('ports') or [])
            ],
            'vulnerabilities': s.get('vulnerabilities'),
        }

    def _clean_alienvault(a):
        if not a:
            return None
        general = a.get('general') or {}
        pulse_info = general.get('pulse_info') or {}
        return {
            'pulse_count': pulse_info.get('count', 0),
            'reputation': general.get('reputation'),
            'asn': general.get('asn'),
            'country_name': general.get('country_name'),
            'geo': a.get('geo'),
        }

    def _clean_abuseipdb(a):
        if not a:
            return None
        return {k: v for k, v in a.items() if k != 'reports'}

    return {
        'indicator': ip,
        'indicator_type': 'ip',
        'timestamp': _now(),
        'summary': summary,
        'sources': {
            'vpnapi': sources.get('vpnapi'),
            'ipinfo': sources.get('ipinfo'),
            'abuseipdb': _clean_abuseipdb(sources.get('abuseipdb')),
            'shodan': _clean_shodan(sources.get('shodan')),
            'alienvault': _clean_alienvault(sources.get('alienvault')),
        },
    }


# ---------------------------------------------------------------------------
# Domain / URL enrichment
# ---------------------------------------------------------------------------

def _enrich_domain(indicator, indicator_type):
    from app.services.domain_service import get_domain_info
    from app.services.ip_service import get_alienvault_data
    from urllib.parse import urlparse

    if indicator_type == 'url':
        domain = urlparse(indicator).netloc or indicator
    else:
        domain = indicator

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(get_domain_info, domain): 'domain_info',
            executor.submit(get_alienvault_data, domain): 'alienvault',
        }
        results = {}
        for future in as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except Exception as exc:
                logger.warning("Domain enrichment source %s failed: %s", key, exc)
                results[key] = None

    domain_info = results.get('domain_info') or {}
    alienvault = results.get('alienvault') or {}
    whois = domain_info.get('whois') or {}
    ssl = domain_info.get('ssl_info') or {}

    general = alienvault.get('general', {}) or {}
    threat_pulse_count = general.get('pulse_info', {}).get('count', 0) if general else 0

    # URL analysis for status code / redirects
    url_data = None
    status_code = None
    redirect_count = 0
    if indicator_type == 'url':
        try:
            from app.services.url_service import analyze_url_quick
            url_data = analyze_url_quick(indicator)
            if url_data:
                status_code = url_data.get('status_code')
                redirect_count = len(url_data.get('redirect_chain', [])) - 1
                redirect_count = max(redirect_count, 0)
        except Exception as exc:
            logger.warning("URL analysis failed: %s", exc)

    summary = {
        'registrar': whois.get('registrar'),
        'created_date': whois.get('create_date'),
        'expires_date': whois.get('expire_date'),
        'ip_address': domain_info.get('ip_address'),
        'ssl_valid': ssl is not None,
        'ssl_expires': ssl.get('not_after') if ssl else None,
        'threat_pulse_count': threat_pulse_count,
        'status_code': status_code,
        'redirect_count': redirect_count,
    }

    return {
        'indicator': indicator,
        'indicator_type': indicator_type,
        'timestamp': _now(),
        'summary': summary,
        'sources': {
            'whois': domain_info.get('whois'),
            'dns': domain_info.get('dns_records'),
            'ssl': domain_info.get('ssl_info'),
            'url_analysis': url_data,
            'alienvault': results.get('alienvault'),
        },
    }


# ---------------------------------------------------------------------------
# Shared dispatch
# ---------------------------------------------------------------------------

def _enrich_indicator(indicator):
    """Enrich a single indicator; returns result dict (may contain 'error')."""
    try:
        itype = _detect_type(indicator)
        if itype == 'ip':
            return _enrich_ip(indicator)
        else:
            return _enrich_domain(indicator, itype)
    except ValueError as exc:
        return {
            'indicator': indicator,
            'indicator_type': 'unknown',
            'timestamp': _now(),
            'error': str(exc),
        }
    except Exception as exc:
        logger.exception("Unexpected error enriching %s", indicator)
        return {
            'indicator': indicator,
            'indicator_type': 'unknown',
            'timestamp': _now(),
            'error': f"Internal error: {exc}",
        }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@enrichment_bp.route('/ip', methods=['POST'])
@require_api_key
def enrich_ip():
    data = request.get_json(silent=True) or {}
    ip = (data.get('ip') or '').strip()
    if not ip:
        return jsonify({'error': 'Missing required field: ip'}), 400
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({'error': f'Invalid IP address: {ip!r}'}), 400

    result = _enrich_ip(ip)
    return jsonify(result)


@enrichment_bp.route('/domain', methods=['POST'])
@require_api_key
def enrich_domain():
    data = request.get_json(silent=True) or {}
    indicator = (data.get('indicator') or '').strip()
    if not indicator:
        return jsonify({'error': 'Missing required field: indicator'}), 400

    try:
        itype = _detect_type(indicator)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400

    if itype == 'ip':
        return jsonify({'error': 'Use /api/enrich/ip for IP addresses'}), 400

    result = _enrich_domain(indicator, itype)
    return jsonify(result)


@enrichment_bp.route('/batch', methods=['POST'])
@require_api_key
def enrich_batch():
    data = request.get_json(silent=True) or {}
    indicators = data.get('indicators', [])

    if not isinstance(indicators, list) or not indicators:
        return jsonify({'error': 'Missing or empty required field: indicators'}), 400

    if len(indicators) > MAX_BATCH_SIZE:
        return jsonify({
            'error': f'Too many indicators. Maximum is {MAX_BATCH_SIZE}, got {len(indicators)}.'
        }), 400

    results = [None] * len(indicators)
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_idx = {
            executor.submit(_enrich_indicator, ind): idx
            for idx, ind in enumerate(indicators)
        }
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except Exception as exc:
                results[idx] = {
                    'indicator': indicators[idx],
                    'indicator_type': 'unknown',
                    'timestamp': _now(),
                    'error': f"Internal error: {exc}",
                }

    error_count = sum(1 for r in results if r and 'error' in r)

    return jsonify({
        'results': results,
        'meta': {
            'total': len(indicators),
            'processed': len(indicators),
            'errors': error_count,
            'timestamp': _now(),
        },
    })
