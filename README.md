# NexusTrace - Comprehensive OSINT Analysis Tool

NexusTrace is a powerful OSINT (Open Source Intelligence) tool designed for analyzing IP addresses, domains, URLs, files, hashes, and more. It provides comprehensive security and technical analysis through multiple data sources and APIs, with an integrated web interface and CyberChef integration.

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
  - AlienVault OTX integration

- **Domain Analysis**
  - WHOIS information
  - DNS records
  - SSL/TLS certificate details
  - IP resolution
  - Technology stack detection
  - Security headers analysis

- **URL Analysis**
  - Security headers
  - Redirect chain analysis
  - Technology stack detection
  - Meta information
  - Content analysis
  - Malware scanning

- **File Analysis**
  - Malware detection via Intezer
  - Code reuse analysis
  - Threat classification
  - Family identification
  - Metadata extraction

- **Hash Analysis**
  - Hash type detection
  - Malware analysis via Intezer
  - AlienVault OTX threat intelligence
  - Hash validation and formatting

- **Azure Error Analysis**
  - Azure AD error code lookup
  - Detailed error descriptions
  - Troubleshooting guidance
  - Error code validation

- **User Agent Analysis**
  - User agent string parsing
  - Browser and OS detection
  - Device information extraction
  - Security analysis

- **Event Analysis**
  - Event log analysis
  - Security event correlation
  - Timeline analysis

- **CyberChef Integration**
  - Embedded CyberChef interface
  - Custom recipe management
  - Recipe saving and loading
  - Data transformation tools

## Project Structure

```
NexusTrace/
├── app/
│   ├── routes/              # API endpoints
│   │   ├── __init__.py     # Route registration
│   │   ├── home_routes.py  # Main web interface routes
│   │   ├── ip_routes.py    # IP analysis endpoints
│   │   ├── domain_routes.py # Domain analysis endpoints
│   │   ├── file_routes.py  # File analysis endpoints
│   │   ├── hash_routes.py  # Hash analysis endpoints
│   │   ├── health_routes.py # Health check endpoints
│   │   ├── azure_error_routes.py # Azure error analysis
│   │   ├── cyberchef_routes.py # CyberChef integration
│   │   ├── cyberchef_api.py # CyberChef API endpoints
│   │   ├── user_agent_routes.py # User agent analysis
│   │   └── event_routes.py # Event analysis
│   │
│   ├── services/           # Business logic
│   │   ├── __init__.py     # Service setup
│   │   ├── ip_service.py   # IP analysis services
│   │   ├── domain_service.py # Domain analysis services
│   │   ├── url_service.py  # URL analysis services
│   │   ├── file_service.py # File analysis services
│   │   ├── hash_service.py # Hash analysis services
│   │   ├── health_service.py # Health check services
│   │   ├── azure_error_service.py # Azure error services
│   │   ├── cyberchef.py    # CyberChef services
│   │   ├── user_agent_service.py # User agent services
│   │   └── event_service.py # Event services
│   │
│   ├── utils/             # Utility functions
│   │   ├── __init__.py    # Utility setup
│   │   ├── cache.py       # Caching functionality
│   │   └── logging.py     # Logging configuration
│   │
│   ├── tests/             # Test files
│   │   ├── minimal_flask_test.py
│   │   └── test_endpoints.py
│   │
│   └── app.py            # Main application file
│
├── data/                 # Data storage directory
│   └── cyberchef_recipes/ # Saved CyberChef recipes
├── templates/            # Jinja2 HTML templates
├── static/              # CSS, JS, images, favicon, etc.
├── CyberChef_v10.19.4/  # Embedded CyberChef tool
├── icon_tools/          # Icon/favicon scripts
├── logs/                # Application logs
├── main.py              # Application entry point
├── requirements.txt     # Python dependencies
├── Dockerfile           # Docker configuration
├── docker-compose.yml   # Docker Compose configuration
├── nginx.conf           # Nginx configuration
└── README.md            # This documentation
```

## API Endpoints

### Web Interface
- `GET /`: Main web interface
- `GET /ip_search`: IP analysis interface
- `GET /domain_search`: Domain analysis interface
- `GET /hash_analysis`: Hash analysis interface
- `GET /azure_error_search`: Azure error analysis interface
- `GET /user_agent_search`: User agent analysis interface
- `GET /event_section`: Event analysis interface
- `GET /cyberchef`: CyberChef integration interface

### IP Analysis
- `POST /api/ip/check_ip`: Analyze a single IP address
- `POST /api/ip/check_ips`: Batch analyze multiple IP addresses from a file

### Domain Analysis
- `POST /api/domain/check_domain`: Analyze a domain name

### File Analysis
- `POST /api/file/analyze_file`: Analyze a file for malware

### Hash Analysis
- `POST /api/hash/check_hash`: Analyze a hash value
- `GET /api/hash/analyze`: Hash analysis web interface

### Azure Error Analysis
- `POST /api/azure_error/search`: Search Azure error codes

### CyberChef Integration
- `GET /api/cyberchef/recipes`: Get saved recipes
- `POST /api/cyberchef/recipes`: Save a new recipe
- `GET /api/cyberchef/recipes/<filename>`: Load a specific recipe

### Health Check
- `GET /api/health`: Check application health status

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
FLASK_HOST=0.0.0.0
FLASK_PORT=5050
MMDB_PATH=/path/to/ipinfo_lite.mmdb  # Optional: Path to IPinfo MMDB database
```

### IPinfo MMDB Database Integration

For enhanced performance and additional data fields, you can use the IPinfo MMDB database:

1. **Download the MMDB database:**
   - Visit [IPinfo Lite](https://ipinfo.io/lite)
   - Sign up for a free account
   - Download the MMDB database file
   - Extract and place `ipinfo_lite.mmdb` in the `data/` directory

2. **Run the setup script:**
   ```bash
   python scripts/download_ipinfo_mmdb.py
   ```

3. **Benefits of MMDB integration:**
   - Faster lookups (no API rate limits)
   - Additional fields: city, postal code, coordinates
   - Offline capability
   - Reduced API usage

The application will automatically use the MMDB database if available, falling back to the API for missing data.

## Features

### Web Interface
- Modern, responsive design
- Real-time analysis results
- Interactive data visualization
- Tabbed interface for different analysis types
- Export functionality for results

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

### Testing
- Unit tests for each service
- Integration tests for API endpoints
- Performance testing for batch operations
- API test suite for comprehensive endpoint testing

## Error Handling
- Comprehensive error handling across all services
- Detailed error logging
- Graceful degradation when services are unavailable
- User-friendly error messages
- Input validation and sanitization

## Security Features
- Secure session configuration
- Rate limiting to prevent abuse
- API key validation
- Input validation and sanitization
- Secure file handling
- CORS configuration

## Performance Optimizations
- Concurrent processing for batch operations
- Caching of API responses
- Efficient rate limiting
- Optimized database queries
- Static file serving via Nginx

## Development

### Setup
1. Clone the repository
2. Create a virtual environment: `python -m venv venv`
3. Activate the virtual environment:
   - Windows: `venv\Scripts\activate`
   - macOS/Linux: `source venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Set up environment variables in a `.env` file
6. Run the application: `python main.py`

### Docker Setup
1. Build the Docker image: `docker build -t nexustrace .`
2. Run with Docker Compose: `docker-compose up -d`
3. Access the application at `http://localhost:5050`

### Testing
- Run unit tests: `python -m pytest app/tests/`
- Run API tests: `python test_api.py`
- Run integration tests: `python -m pytest app/tests/test_endpoints.py`

## Deployment

### Docker Deployment
The application includes Docker support for easy deployment:

```bash
# Build and run with Docker Compose
docker-compose up -d

# Or build and run manually
docker build -t nexustrace .
docker run -p 5050:5050 nexustrace
```

### Production Deployment
For production deployment, the application uses:
- Gunicorn as the WSGI server
- Nginx as a reverse proxy
- Docker for containerization
- Environment-based configuration

## Contributing
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Commit your changes: `git commit -m 'Add some feature'`
4. Push to the branch: `git push origin feature/your-feature-name`
5. Create a Pull Request

## License
[Add your license information here]

## Acknowledgments

- VPN API (vpnapi.io)
- IPinfo
- Shodan
- AlienVault OTX
- IP2WHOIS
- Intezer
- CyberChef (GCHQ)
- Flask
- Bootstrap

## Support

For support, please open an issue in the GitHub repository or contact the development team.

## Roadmap

- [ ] Additional threat intelligence sources
- [ ] Machine learning-based analysis
- [ ] Advanced visualization features
- [ ] API rate limit management
- [ ] Enhanced reporting capabilities
- [ ] Mobile application
- [ ] Real-time threat feeds 