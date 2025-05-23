# NexusTrace - OSINT Analysis Tool

NexusTrace is a powerful OSINT (Open Source Intelligence) tool designed for analyzing IP addresses, domains, URLs, and files. It provides comprehensive security and technical analysis through multiple data sources and APIs.

## Features

- **IP Analysis**
  - VPN/Proxy detection
  - Geolocation data
  - Network information
  - Abuse reports
  - Security scoring
  - WHOIS data
  - Port scanning
  - Vulnerability assessment

- **Domain Analysis**
  - WHOIS information
  - DNS records
  - SSL/TLS certificate details
  - IP resolution
  - Technology stack detection

- **URL Analysis**
  - Security headers
  - Redirect chain analysis
  - Technology stack detection
  - Meta information
  - Content analysis
  - Malware scanning

- **File Analysis**
  - Malware detection
  - Code reuse analysis
  - Threat classification
  - Family identification
  - Metadata extraction

## Project Structure

```
NexusTrace/
├── app/
│   ├── routes/              # API endpoints
│   │   ├── __init__.py     # Route registration
│   │   ├── ip_routes.py    # IP analysis endpoints
│   │   ├── domain_routes.py # Domain analysis endpoints
│   │   ├── url_routes.py   # URL analysis endpoints
│   │   ├── file_routes.py  # File analysis endpoints
│   │   └── health_routes.py # Health check endpoints
│   │
│   ├── services/           # Business logic
│   │   ├── __init__.py     # Service setup
│   │   ├── ip_service.py   # IP analysis services
│   │   ├── domain_service.py # Domain analysis services
│   │   ├── url_service.py  # URL analysis services
│   │   ├── file_service.py # File analysis services
│   │   └── health_service.py # Health check services
│   │
│   ├── utils/             # Utility functions
│   │   ├── __init__.py    # Utility setup
│   │   ├── cache.py       # Caching functionality
│   │   ├── rate_limiter.py # Rate limiting
│   │   └── logging.py     # Logging configuration
│   │
│   ├── tests/             # Test files
│   │   ├── minimal_flask_test.py
│   │   └── test_endpoints.py
│   │
│   ├── build/             # Build artifacts
│   │   ├── ip_checker.spec
│   │   └── Info.plist
│   │
│   └── app.py            # Main application file
│
├── templates/            # Jinja2 HTML templates
├── static/              # CSS, JS, images, favicon, etc.
├── frontend/            # Static HTML/assets
├── CyberChef_v10.19.4/  # External tool
├── icon_tools/          # Icon/favicon scripts
├── logs/                # Application logs
├── build/               # Build artifacts (if any)
├── tailwind-test/       # Tailwind experiments
├── app.py               # Flask entry point
├── wsgi.py              # WSGI entry point
├── run.py               # Flask run script
├── requirements.txt     # Python dependencies
├── Dockerfile           # Docker configuration
├── docker-compose.yml   # Docker Compose configuration
├── nginx.conf           # Nginx configuration
├── entrypoint.sh        # Docker entrypoint script
└── README.md            # This documentation
```

## API Endpoints

### IP Analysis
- `POST /check_ip`: Analyze a single IP address
- `POST /check_ips`: Batch analyze multiple IP addresses from a file

### Domain Analysis
- `POST /check_domain`: Analyze a domain name

### URL Analysis
- `POST /analyze_url`: Analyze a URL

### File Analysis
- `POST /analyze_file`: Analyze a file for malware

### Health Check
- `GET /health`: Check application health status

## Configuration

The application requires several API keys for full functionality:

```env
VPNAPI_KEY=your_vpnapi_key
IPINFO_TOKEN=your_ipinfo_token
SHODAN_KEY=your_shodan_key
ABUSEIPDB_KEY=your_abuseipdb_key
PROXYCHECK_KEY=your_proxycheck_key
ALIENVAULT_KEY=your_alienvault_key
INTEZER_API_KEY=your_intezer_key
IP2WHOIS_KEY=your_ip2whois_key
```

## Features

### Caching
- Implements LRU cache with TTL (Time To Live)
- Cache size limit: 1000 items
- Cache duration: 30 minutes
- Automatic cache clearing

### Rate Limiting
- Sliding window rate limiting
- Configurable request limits per time window
- Thread-safe implementation

### Logging
- Rotating file logs (10MB max size)
- Console output
- Detailed error tracking
- Request logging in debug mode

## Error Handling
- Comprehensive error handling across all services
- Detailed error logging
- Graceful degradation when services are unavailable
- User-friendly error messages

## Security Features
- Secure session configuration
- Rate limiting to prevent abuse
- API key validation
- Input validation
- Secure file handling

## Performance Optimizations
- Concurrent processing for batch operations
- Caching of API responses
- Efficient rate limiting
- Optimized database queries

## Development

### Setup
1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Set up environment variables
4. Run the application: `python run.py`

### Testing
- Unit tests for each service
- Integration tests for API endpoints
- Performance testing for batch operations

## Contributing
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License
[Add your license information here]

## Acknowledgments

- VPN API (vpnapi.io)
- IPinfo
- Shodan
- AlienVault OTX
- IP2WHOIS

## Support

For support, please open an issue in the GitHub repository. 