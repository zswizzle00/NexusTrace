from .cache import setup_cache
from .disclosure import setup_disclosure
from .rate_limiter import setup_rate_limiters
from .logging import setup_logging

def setup_utils(app):
    setup_logging(app)
    setup_cache(app)
    setup_rate_limiters(app)
    setup_disclosure(app) 