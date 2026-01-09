from flask import render_template, Blueprint, jsonify, request, redirect, url_for
import json
import os
import re
import logging

logger = logging.getLogger(__name__)

# Pattern for safe filenames: alphanumeric, underscore, hyphen only
SAFE_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{1,50}$')


def sanitize_filename(name):
    """Sanitize a filename to prevent path traversal attacks."""
    # Strip any path components
    name = os.path.basename(name)
    # Remove .json extension if present for validation
    if name.endswith('.json'):
        name = name[:-5]
    # Replace spaces with underscores
    name = name.lower().replace(' ', '_')
    # Only allow safe characters
    if not SAFE_FILENAME_PATTERN.match(name):
        return None
    return name


def is_safe_path(base_dir, filepath):
    """Check if the resolved filepath is within the base directory."""
    # Resolve to absolute paths
    base_dir = os.path.realpath(base_dir)
    filepath = os.path.realpath(filepath)
    # Check that filepath starts with base_dir
    return filepath.startswith(base_dir + os.sep) or filepath == base_dir


def register_cyberchef_routes(app):
    cyberchef_bp = Blueprint('cyberchef_tab', __name__)

    # Ensure recipes directory exists
    recipes_dir = os.path.realpath(os.path.join(app.root_path, '..', 'data', 'cyberchef_recipes'))
    os.makedirs(recipes_dir, exist_ok=True)

    @cyberchef_bp.route('/cyberchef', strict_slashes=False)
    def cyberchef_tab():
        return render_template('cyberchef_section.html')

    @cyberchef_bp.route('/api/cyberchef/recipes', methods=['GET'])
    def get_recipes():
        """Get list of saved recipes"""
        recipes = []
        try:
            for filename in os.listdir(recipes_dir):
                if filename.endswith('.json') and SAFE_FILENAME_PATTERN.match(filename[:-5]):
                    filepath = os.path.join(recipes_dir, filename)
                    if is_safe_path(recipes_dir, filepath):
                        with open(filepath, 'r') as f:
                            recipe = json.load(f)
                            recipes.append({
                                'name': recipe.get('name', filename[:-5]),
                                'description': recipe.get('description', ''),
                                'filename': filename
                            })
        except OSError as e:
            logger.error(f"Error reading recipes directory: {e}")
        return jsonify(recipes)

    @cyberchef_bp.route('/api/cyberchef/recipes', methods=['POST'])
    def save_recipe():
        """Save a new recipe"""
        data = request.json
        if not data or 'name' not in data:
            return jsonify({'error': 'Recipe name is required'}), 400

        # Sanitize the filename
        safe_name = sanitize_filename(data['name'])
        if not safe_name:
            return jsonify({'error': 'Invalid recipe name. Use only letters, numbers, underscores, and hyphens (max 50 chars)'}), 400

        filename = f"{safe_name}.json"
        filepath = os.path.join(recipes_dir, filename)

        # Verify path is safe
        if not is_safe_path(recipes_dir, filepath):
            logger.warning(f"Path traversal attempt blocked: {data['name']}")
            return jsonify({'error': 'Invalid recipe name'}), 400

        try:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
        except OSError as e:
            logger.error(f"Error saving recipe: {e}")
            return jsonify({'error': 'Failed to save recipe'}), 500

        return jsonify({'message': 'Recipe saved successfully', 'filename': filename})

    @cyberchef_bp.route('/api/cyberchef/recipes/<filename>', methods=['GET'])
    def load_recipe(filename):
        """Load a specific recipe"""
        # Sanitize the filename - strip path and validate
        safe_name = sanitize_filename(filename)
        if not safe_name:
            return jsonify({'error': 'Invalid filename'}), 400

        filename = f"{safe_name}.json"
        filepath = os.path.join(recipes_dir, filename)

        # Verify path is safe
        if not is_safe_path(recipes_dir, filepath):
            logger.warning(f"Path traversal attempt blocked: {filename}")
            return jsonify({'error': 'Invalid filename'}), 400

        if not os.path.exists(filepath):
            return jsonify({'error': 'Recipe not found'}), 404

        try:
            with open(filepath, 'r') as f:
                recipe = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.error(f"Error loading recipe: {e}")
            return jsonify({'error': 'Failed to load recipe'}), 500

        return jsonify(recipe)

    app.register_blueprint(cyberchef_bp)
