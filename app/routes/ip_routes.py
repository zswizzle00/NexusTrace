from flask import Blueprint, request, jsonify, send_file
import pandas as pd
import io
import logging
from ..services.ip_service import (
    check_abuseipdb,
    get_ipinfo_data,
    get_shodan_info,
    get_proxycheck_data,
    get_greynoise_data,
    get_alienvault_data,
    get_vpn_data
)
from ..utils.validators import is_valid_ip

logger = logging.getLogger(__name__)

ip_bp = Blueprint('ip', __name__)

@ip_bp.route('/check_ip', methods=['POST'])
def check_ip():
    data = request.json
    if not data:
        return jsonify({'error': 'Request body is required'}), 400

    ip_input = data.get('ip', '').strip() if data.get('ip') else ''
    if not ip_input:
        return jsonify({'error': 'IP address is required'}), 400

    ip_address = is_valid_ip(ip_input)
    if not ip_address:
        return jsonify({'error': 'Invalid IP address format. Please provide a valid IPv4 or IPv6 address.'}), 400

    try:
        # VPNapi is the primary source; everything else augments it.
        vpn_data = get_vpn_data(ip_address)
        if not vpn_data or 'error' in vpn_data:
            return jsonify({'error': vpn_data['error'] if vpn_data else 'VPN API lookup failed'}), 500
        
        results = {}

        try:
            results['abuse'] = check_abuseipdb(ip_address)
        except Exception as e:
            results['abuse'] = None

        try:
            results['ipinfo'] = get_ipinfo_data(ip_address)
        except Exception as e:
            results['ipinfo'] = None

        try:
            results['shodan'] = get_shodan_info(ip_address)
        except Exception as e:
            results['shodan'] = None

        try:
            results['proxycheck'] = get_proxycheck_data(ip_address)
        except Exception as e:
            results['proxycheck'] = None

        try:
            results['greynoise'] = get_greynoise_data(ip_address)
        except Exception:
            results['greynoise'] = None

        try:
            results['alienvault'] = get_alienvault_data(ip_address)
        except Exception as e:
            results['alienvault'] = None

        result = vpn_data if vpn_data else {}

        if results['abuse']:
            result['abuse'] = results['abuse']
        if results['ipinfo']:
            result.update(results['ipinfo'])
        if results['shodan']:
            result['shodan'] = results['shodan']
        if results['proxycheck']:
            result.update(results['proxycheck'])
        if results['greynoise']:
            result['greynoise'] = results['greynoise']
        if results['alienvault']:
            result['alienvault'] = results['alienvault']
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Measured throughput is ~2 IPs/s and flat: each row queries three providers behind
# process-global 2 req/s limiters, so more workers cannot raise it. 200 rows is what fits
# inside the 120s gunicorn/Docker request timeout; the old 1000 could not.
MAX_BATCH_IPS = 200


class UnreadableUpload(Exception):
    """Carries a message that is safe to return to the client: no pandas, codec, or
    zipfile internals, which the old broad `except` echoed straight back."""


def _parse_table(reader, raw, **kwargs):
    try:
        return reader(io.BytesIO(raw), **kwargs)
    except UnicodeDecodeError as e:
        logger.warning("Bulk IP upload is not UTF-8: %s", e)
        raise UnreadableUpload(
            'The file could not be decoded as UTF-8 text. Re-save it as UTF-8 CSV, '
            'or upload it as .xlsx.'
        ) from e
    except pd.errors.EmptyDataError as e:
        raise UnreadableUpload('The file is empty.') from e
    except Exception as e:
        logger.warning("Bulk IP upload could not be parsed: %s: %s", type(e).__name__, e)
        raise UnreadableUpload(
            'The file could not be read. Provide a CSV, XLSX, or TXT file with one IP '
            'address per row in the first column.'
        ) from e


def _first_cell_is_data(df):
    return df.shape[1] > 0 and is_valid_ip(str(df.columns[0]).strip()) is not None


def _read_ip_column(filename, raw):
    """First column of an uploaded CSV/XLSX/TXT as a list of cells.

    A headerless CSV/XLSX loses its first address to pandas' header row (a single-IP file
    loses its only one), so it is re-read with `header=None` when the header cell itself
    parses as an IP. TXT is always headerless.
    """
    name = (filename or '').lower()
    if name.endswith('.txt'):
        df = _parse_table(pd.read_csv, raw, header=None)
    elif name.endswith('.csv'):
        df = _parse_table(pd.read_csv, raw)
        if _first_cell_is_data(df):
            df = _parse_table(pd.read_csv, raw, header=None)
    elif name.endswith('.xlsx'):
        df = _parse_table(pd.read_excel, raw)
        if _first_cell_is_data(df):
            df = _parse_table(pd.read_excel, raw, header=None)
    else:
        raise UnreadableUpload('Unsupported file format. Upload a .csv, .xlsx, or .txt file.')

    if df.shape[1] == 0 or df.empty:
        raise UnreadableUpload('The file contains no rows to analyze.')
    return df.iloc[:, 0].tolist()


@ip_bp.route('/check_ips', methods=['POST'])
def check_ips():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'No file selected'}), 400

    try:
        cells = _read_ip_column(file.filename, file.read())
    except UnreadableUpload as e:
        return jsonify({'error': str(e)}), 400

    # Normalize first, so variants of the same address dedupe together.
    valid_ips = []
    seen = set()
    for cell in cells:
        normalized = is_valid_ip(str(cell).strip()) if cell is not None else None
        if normalized and normalized not in seen:
            seen.add(normalized)
            valid_ips.append(normalized)

    if not valid_ips:
        return jsonify({'error': 'No valid IP addresses found in the first column of the file.'}), 400

    # Capped after dedup, because unique addresses are what actually get looked up.
    if len(valid_ips) > MAX_BATCH_IPS:
        return jsonify({'error': (
            f'Too many IP addresses: {len(valid_ips)} unique, maximum is {MAX_BATCH_IPS}. '
            'Bulk analysis runs at roughly 2 IPs per second against rate-limited providers, '
            f'so more than {MAX_BATCH_IPS} cannot finish inside the request timeout. '
            'Split the file into smaller batches.'
        )}), 400

    from ..services.ip_service import BATCH_COLUMNS, process_ip_batch
    try:
        rows = process_ip_batch(valid_ips)
    except Exception:
        logger.exception("Bulk IP analysis failed for %d addresses", len(valid_ips))
        return jsonify({'error': 'Bulk analysis failed unexpectedly. Check the server log.'}), 500

    output = io.StringIO()
    # dtype=object: without it a column holding an int plus a null is inferred as float64
    # and abuse_score 42 is written as "42.0".
    pd.DataFrame(rows, columns=list(BATCH_COLUMNS), dtype=object).to_csv(output, index=False)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name='ip_report.csv'
    )
