from dotenv import load_dotenv
import os

# Load environment variables first, before any other imports
load_dotenv()

from app import create_app
from flask import send_from_directory

app = create_app()

# Serve the service worker at /sw.js
@app.route('/sw.js')
def service_worker():
    return send_from_directory('static', 'sw.js')

if __name__ == '__main__':
    # Ensure we bind to all interfaces in Docker
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    port = int(os.getenv('FLASK_PORT', 5050))
    app.run(host=host, port=port, threaded=True) 