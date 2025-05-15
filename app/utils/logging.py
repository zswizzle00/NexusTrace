import logging
import logging.handlers
import os

def setup_logging(app):
    """Setup logging for the application."""
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.handlers.RotatingFileHandler(
                'logs/app.log',
                maxBytes=10485760,  # 10MB
                backupCount=5
            )
        ]
    )

    # Set up request logging
    if app.debug:
        logging.getLogger('werkzeug').setLevel(logging.INFO) 