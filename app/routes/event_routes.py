from flask import Blueprint, render_template, request, jsonify
import re
from app.services.event_service import get_event_info

event_bp = Blueprint('event', __name__)

@event_bp.route('/event/search', methods=['POST'])
def search_event():
    event_id = request.form.get('event_id', '').strip()
    
    # Validate event ID format (should be a number)
    if not event_id.isdigit():
        return jsonify({
            'error': 'Invalid event ID format. Please enter a valid event ID number.'
        }), 400
    
    # Get event information from the service
    event_info = get_event_info(event_id)
    
    return jsonify(event_info)

@event_bp.route('/event')
def event_section():
    return render_template('event_section.html') 