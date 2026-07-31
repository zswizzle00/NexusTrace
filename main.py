from dotenv import load_dotenv
import os

load_dotenv()  # must precede app imports, which read env at import time

from app import create_app
from flask import send_from_directory

app = create_app()

# /sw.js must be at root scope for full-origin service-worker coverage. The absolute
# app.static_folder is required: a relative 'static' resolves against app/, not the project
# root where static/ actually lives.
@app.route('/sw.js')
def service_worker():
    return send_from_directory(app.static_folder, 'sw.js')

def resolve_port(env=None):
    """Listen port: PORT, then FLASK_PORT, then 5050. Blank counts as unset.

    PORT wins because it is a platform contract, not a preference: Cloud Run injects it
    (8080) and fails the startup probe if nothing listens there, so honouring FLASK_PORT
    first would let a stray FLASK_PORT break the deploy in a way that looks like an app
    crash. Compose sets only FLASK_PORT, so it is unaffected. Keep this in sync with the
    Dockerfile CMD's ${PORT:-${FLASK_PORT:-5050}}.
    """
    env = os.environ if env is None else env
    for name in ('PORT', 'FLASK_PORT'):
        value = (env.get(name) or '').strip()
        if value:
            return int(value)
    return 5050


if __name__ == '__main__':
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    app.run(host=host, port=resolve_port(), threaded=True)