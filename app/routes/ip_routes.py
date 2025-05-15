from flask import Blueprint, request, jsonify, send_file
import pandas as pd
import io
from ..services.ip_service import (
    check_abuseipdb,
    get_ipinfo_data,
    get_shodan_info,
    get_proxycheck_data,
    get_alienvault_data,
    get_vpn_data
)

ip_bp = Blueprint('ip', __name__)

@ip_bp.route('/check_ip', methods=['POST'])
def check_ip():
    ip_address = request.json.get('ip')
    if not ip_address:
        return jsonify({'error': 'IP address is required'}), 400
    
    try:
        # Get VPN API data first (primary source)
        vpn_data = get_vpn_data(ip_address)
        if 'error' in vpn_data:
            return jsonify({'error': vpn_data['error']}), 500
        
        # Run API calls sequentially
        results = {}
        
        # AbuseIPDB
        try:
            results['abuse'] = check_abuseipdb(ip_address)
        except Exception as e:
            results['abuse'] = None
            
        # IPinfo
        try:
            results['ipinfo'] = get_ipinfo_data(ip_address)
        except Exception as e:
            results['ipinfo'] = None
            
        # Shodan
        try:
            results['shodan'] = get_shodan_info(ip_address)
        except Exception as e:
            results['shodan'] = None
            
        # ProxyCheck
        try:
            results['proxycheck'] = get_proxycheck_data(ip_address)
        except Exception as e:
            results['proxycheck'] = None
            
        # AlienVault
        try:
            results['alienvault'] = get_alienvault_data(ip_address)
        except Exception as e:
            results['alienvault'] = None

        # Combine results with VPNapi.io data as primary source
        result = vpn_data if vpn_data else {}
        
        # Add other data sources
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
        # Read the file based on its extension
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file)
        elif file.filename.endswith('.xlsx'):
            df = pd.read_excel(file)
        elif file.filename.endswith('.txt'):
            df = pd.read_csv(file, header=None, names=['ip'])
        else:
            return jsonify({'error': 'Unsupported file format'}), 400
        
        # Extract IP addresses from the first column
        ip_addresses = df.iloc[:, 0].tolist()
        
        # Validate IP addresses
        valid_ips = []
        for ip in ip_addresses:
            try:
                # Basic IP validation
                if isinstance(ip, str) and len(ip.split('.')) == 4:
                    valid_ips.append(ip)
            except:
                continue
        
        if not valid_ips:
            return jsonify({'error': 'No valid IP addresses found in the file'}), 400

        # Process IPs concurrently
        from ..services.ip_service import process_ip_batch
        rows = process_ip_batch(valid_ips)

        if not rows:
            return jsonify({'error': 'No valid results could be obtained for any IP addresses'}), 400

        # Create a DataFrame and output as CSV
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