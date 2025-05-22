from flask import render_template, Blueprint, jsonify, request
import json
import os

def register_cyberchef_routes(app):
    cyberchef_bp = Blueprint('cyberchef_tab', __name__)
    
    # Ensure recipes directory exists
    recipes_dir = os.path.join(app.root_path, '..', 'data', 'cyberchef_recipes')
    os.makedirs(recipes_dir, exist_ok=True)
    
    @cyberchef_bp.route('/tools/cyberchef')
    def cyberchef_tab():
        """Render the CyberChef tab interface"""
        return render_template('cyberchef_section.html')
    
    @cyberchef_bp.route('/api/cyberchef/recipes', methods=['GET'])
    def get_recipes():
        """Get list of saved recipes"""
        recipes = []
        for filename in os.listdir(recipes_dir):
            if filename.endswith('.json'):
                with open(os.path.join(recipes_dir, filename), 'r') as f:
                    recipe = json.load(f)
                    recipes.append({
                        'name': recipe['name'],
                        'description': recipe.get('description', ''),
                        'filename': filename
                    })
        return jsonify(recipes)
    
    @cyberchef_bp.route('/api/cyberchef/recipes', methods=['POST'])
    def save_recipe():
        """Save a new recipe"""
        data = request.json
        filename = f"{data['name'].lower().replace(' ', '_')}.json"
        filepath = os.path.join(recipes_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        return jsonify({'message': 'Recipe saved successfully', 'filename': filename})
    
    @cyberchef_bp.route('/api/cyberchef/recipes/<filename>', methods=['GET'])
    def load_recipe(filename):
        """Load a specific recipe"""
        filepath = os.path.join(recipes_dir, filename)
        if not os.path.exists(filepath):
            return jsonify({'error': 'Recipe not found'}), 404
            
        with open(filepath, 'r') as f:
            recipe = json.load(f)
        return jsonify(recipe)
    
    app.register_blueprint(cyberchef_bp) 