from .cache import setup_cache
from .rate_limiter import setup_rate_limiters
from .logging import setup_logging

def setup_utils(app):
    """Setup all utilities for the application."""
    setup_logging(app)
    setup_cache(app)
    setup_rate_limiters(app) 