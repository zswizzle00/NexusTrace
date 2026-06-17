from flask import Blueprint, jsonify
from ..services.health_service import check_health

health_bp = Blueprint('health', __name__)

@health_bp.route('', strict_slashes=False)
@health_bp.route('/')
def health_check():
    """Health check endpoint for container orchestration. Served at /api/health
    (the blueprint is registered with the /api/health url_prefix)."""
    try:
        return jsonify(check_health()), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 503 