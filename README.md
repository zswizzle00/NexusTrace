# IP & Domain Analysis Tool

A powerful OSINT tool for analyzing IP addresses and domains, providing comprehensive information about security, location, and network details.

## Features

- **IP Analysis**
  - VPN/Proxy Detection
  - Geolocation Data
  - Network Information
  - Security Assessment
  - Abuse Reports
  - Shodan Integration
  - AlienVault OTX Integration

- **Domain Analysis**
  - WHOIS Information
  - DNS Records
  - SSL Certificate Details
  - Technology Stack Detection
  - Security Headers Analysis

- **Bulk Processing**
  - Support for CSV, Excel, and TXT files
  - Batch IP analysis
  - Export results to CSV

## Prerequisites

- Docker and Docker Compose
- API Keys for:
  - VPN API (vpnapi.io)
  - IPinfo
  - IP2WHOIS
  - Shodan
  - AlienVault OTX (optional)

## Quick Start

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd IP-Checker
   ```

2. Create a `.env` file with your API keys:
   ```env
   VPNAPI_KEY=your_vpnapi_key
   IPINFO_TOKEN=your_ipinfo_token
   IP2WHOIS_KEY=your_ip2whois_key
   SHODAN_KEY=your_shodan_key
   ALIENVAULT=your_alienvault_key
   ```

3. Build and start the containers:
   ```bash
   docker-compose up --build
   ```

4. Access the application at `http://localhost`

## Development Setup

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the development server:
   ```bash
   python app.py
   ```

## Production Deployment

The application is configured for production use with:

- Gunicorn WSGI server
- Nginx reverse proxy
- Docker containerization
- Security headers
- Proper error handling
- Health checks

### Production Configuration

- **Gunicorn Settings**:
  - 4 workers
  - 2 threads per worker
  - 120-second timeout
  - Automatic worker management

- **Nginx Configuration**:
  - Reverse proxy
  - Static file caching
  - Security headers
  - Proper timeouts

## API Endpoints

- `POST /check_ip`: Analyze a single IP address
- `POST /check_ips`: Bulk analyze IP addresses from a file
- `POST /check_domain`: Analyze a domain
- `POST /analyze_url`: Analyze a URL

## File Formats

The bulk analysis feature supports:
- CSV files
- Excel files (.xlsx)
- Text files (one IP per line)

## Security Features

- Non-root user in containers
- Security headers
- Rate limiting
- Input validation
- API key protection
- Proper error handling

## Performance Optimizations

- Caching of API responses
- Concurrent API requests
- Efficient database queries
- Static file caching
- Optimized Docker image

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- VPN API (vpnapi.io)
- IPinfo
- Shodan
- AlienVault OTX
- IP2WHOIS

## Support

For support, please open an issue in the GitHub repository. 