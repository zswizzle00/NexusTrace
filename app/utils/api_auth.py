import json
import os
import functools
from flask import request, jsonify

API_KEYS_FILE = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'api_keys.json')


def load_api_keys():
    if not os.path.exists(API_KEYS_FILE):
        return {}
    with open(API_KEYS_FILE) as f:
        return json.load(f).get('keys', {})


def require_api_key(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-API-Key')
        if not key:
            return jsonify({'error': 'Missing X-API-Key header'}), 401
        keys = load_api_keys()
        if not keys.get(key, {}).get('active', False):
            return jsonify({'error': 'Invalid or revoked API key'}), 403
        return f(*args, **kwargs)
    return decorated
