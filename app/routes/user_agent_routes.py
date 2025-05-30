from flask import Blueprint, render_template

user_agent_bp = Blueprint('user_agent', __name__)

@user_agent_bp.route('/user_agent_search', methods=['GET'])
def user_agent_search():
    """Render the user agent search page."""
    return render_template('user_agent_search.html') 