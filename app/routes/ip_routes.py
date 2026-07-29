from flask import Blueprint, request, jsonify, send_file
import pandas as pd
import io
import logging
from ..services.ip_service import (
    check_abuseipdb,
    get_ipinfo_data,
    get_shodan_info,
    get_proxycheck_data,
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
        if results['alienvault']:
            result['alienvault'] = results['alienvault']
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@ip_bp.route('/check_ips', methods=['POST'])
def check_ips():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file)
        elif file.filename.endswith('.xlsx'):
            df = pd.read_excel(file)
        elif file.filename.endswith('.txt'):
            df = pd.read_csv(file, header=None, names=['ip'])
        else:
            return jsonify({'error': 'Unsupported file format'}), 400
        
        ip_addresses = df.iloc[:, 0].tolist()

        # Cap input size to prevent quota exhaustion against paid APIs.
        MAX_BATCH_IPS = 1000
        if len(ip_addresses) > MAX_BATCH_IPS:
            return jsonify({'error': f'Too many IPs. Maximum batch size is {MAX_BATCH_IPS}.'}), 400

        # Normalize first, so variants of the same address dedupe together.
        valid_ips = []
        seen = set()
        for ip in ip_addresses:
            if isinstance(ip, str):
                normalized = is_valid_ip(ip.strip())
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    valid_ips.append(normalized)
        
        if not valid_ips:
            return jsonify({'error': 'No valid IP addresses found in the file'}), 400

        from ..services.ip_service import process_ip_batch
        rows = process_ip_batch(valid_ips)

        if not rows:
            return jsonify({'error': 'No valid results could be obtained for any IP addresses'}), 400

        out_df = pd.DataFrame(rows)
        output = io.StringIO()
        out_df.to_csv(output, index=False)
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode()),
            mimetype='text/csv',
            as_attachment=True,
            download_name='ip_report.csv'
        )
    except Exception as e:
        return jsonify({'error': f'Error processing file: {str(e)}'}), 500 