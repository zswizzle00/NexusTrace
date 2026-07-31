from flask import Blueprint, jsonify
from ..services.health_service import check_health

health_bp = Blueprint('health', __name__)

@health_bp.route('', strict_slashes=False)
@health_bp.route('/')
def health_check():
    """Container-orchestration health check. The blueprint carries the /api/health prefix,
    so this is served at /api/health."""
    try:
        return jsonify(check_health()), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 503 