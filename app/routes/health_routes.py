from flask import Blueprint, jsonify
from ..services.health_service import check_health

health_bp = Blueprint('health', __name__)

@health_bp.route('/health')
def health_check():
    """Health check endpoint for container orchestration."""
    try:
        health_status = check_health()
        if all(health_status['checks'].values()):
            return jsonify(health_status), 200
        else:
            health_status['status'] = 'unhealthy'
            health_status['message'] = 'One or more health checks failed'
            return jsonify(health_status), 503
    except Exception as e:
        health_status = {
            'status': 'unhealthy',
            'error': str(e)
        }
        return jsonify(health_status), 503 