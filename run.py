import os
import multiprocessing
from gunicorn.app.wsgi import WSGIApplication

def run():
    port = os.getenv('PORT', '5000')
    workers = 4
    threads = 2
    timeout = 120
    
    options = {
        'bind': f'0.0.0.0:{port}',
        'workers': workers,
        'threads': threads,
        'timeout': timeout,
        'log_level': 'debug',
        'access_logfile': '-',
        'error_logfile': '-',
        'capture_output': True
    }
    
    WSGIApplication("%(prog)s [OPTIONS] [APP_MODULE]").run()

if __name__ == '__main__':
    run() 