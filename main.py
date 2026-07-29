from dotenv import load_dotenv
import os

load_dotenv()  # must precede app imports, which read env at import time

from app import create_app
from flask import send_from_directory

app = create_app()

# /sw.js must be at root scope for full-origin service-worker coverage. Use the
# absolute app.static_folder — relative 'static' resolves against app/, not the
# project root where static/ actually lives.
@app.route('/sw.js')
def service_worker():
    return send_from_directory(app.static_folder, 'sw.js')

if __name__ == '__main__':
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    port = int(os.getenv('FLASK_PORT', 5050))
    app.run(host=host, port=port, threaded=True) 