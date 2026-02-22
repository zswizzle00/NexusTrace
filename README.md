# NexusTrace

**Open-source threat intelligence and OSINT analysis platform.** Submit an IP, domain, URL, file hash, or user agent string and get enriched context from across the threat intelligence ecosystem — all in one dashboard.

Built for security analysts, incident responders, and researchers who need fast, cross-referenced context on indicators of compromise without jumping between a dozen tools.

---

## Features

### IP Analysis
- Geolocation, ASN, and network data (IPinfo + IP2Location)
- VPN / Proxy / Tor detection (VPNapi + ProxyCheck)
- Open ports and running services (Shodan)
- Known CVEs and vulnerabilities (Shodan)
- Abuse history and confidence score (AbuseIPDB)
- Threat intelligence pulses (AlienVault OTX)

### Domain & URL Analysis
- WHOIS registration data (IP2WHOIS)
- DNS records — A, AAAA, MX, NS, TXT, CNAME, SOA
- SSL/TLS certificate details
- HTTP security headers analysis
- SPF / DKIM / DMARC email security posture
- Subdomain enumeration via certificate transparency logs (crt.sh)
- Redirect chain tracking
- Technology stack fingerprinting
- Meta tags, OpenGraph, and favicon extraction
- Threat intelligence (AlienVault OTX)

### File & Hash Analysis
- Malware classification and code reuse analysis (Intezer)
- Multi-source reputation lookup (VirusTotal, MalwareBazaar, ThreatFox)
- Threat intelligence cross-reference (AlienVault OTX)

### Additional Tools
- **Azure AD Error Decoder** — Look up AADSTS error codes with descriptions and remediation steps
- **Windows Event ID Reference** — Decode Windows Security event IDs
- **User Agent Parser** — Break down browser, OS, device, and bot flags from any UA string
- **CyberChef** — Embedded CyberChef v10.19.4 for in-browser data encoding, decoding, and transformation

---

## Quick Start

### Option 1: Dev Server (Recommended for testing)

```bash
git clone https://github.com/your-org/NexusTrace.git
cd NexusTrace
cp .env.example .env
# Edit .env with your API keys
./start.sh
```

Server starts at `http://localhost:5050`

### Option 2: Docker (Recommended for deployment)

```bash
git clone https://github.com/your-org/NexusTrace.git
cd NexusTrace
cp .env.example .env
# Edit .env with your API keys
./start.sh --docker
```

- Flask app: `http://localhost:5050`
- Nginx reverse proxy: `http://localhost:80`

### Option 3: Production Docker (full rebuild)

```bash
./start.sh --prod
```

### Stopping the server

```bash
./stop.sh            # Stop dev server
./stop.sh --docker   # Stop Docker containers
./stop.sh --status   # Show what's running
./stop.sh --clean    # Stop and clean Python cache
```

---

## Configuration

Copy `.env.example` to `.env` and fill in your API keys:

```env
# IP Analysis
VPNAPI_KEY=            # https://vpnapi.io/
IPINFO_TOKEN=          # https://ipinfo.io/account/token
SHODAN_KEY=            # https://account.shodan.io/
ABUSEIPDB_KEY=         # https://www.abuseipdb.com/account/api
PROXYCHECK_KEY=        # https://proxycheck.io/dashboard
IP2LOCATION_KEY=       # https://www.ip2location.io/

# Domain Analysis
IP2WHOIS_KEY=          # https://www.ip2whois.com/
URLSCAN_API_KEY=       # https://urlscan.io/user/profile/

# File / Hash Analysis
INTEZER_KEY=           # https://analyze.intezer.com/account-details
VIRUSTOTAL_API_KEY=    # https://www.virustotal.com/gui/my-apikey

# Threat Intelligence
ALIENVAULT_KEY=        # https://otx.alienvault.com/api

# Server
SECRET_KEY=your-random-secret-key
FLASK_DEBUG=False
HOST=0.0.0.0
PORT=5050

# Optional: offline IP lookups
# MMDB_PATH=/path/to/ipinfo_lite.mmdb
```

> **All API keys are optional.** The tool gracefully skips any service whose key is not configured — cards for that service simply won't appear in results.

### IPinfo MMDB (optional, offline mode)

For faster lookups without API rate limits, download the IPinfo Lite MMDB database:

1. Sign up at [ipinfo.io/lite](https://ipinfo.io/lite)
2. Download and extract `ipinfo_lite.mmdb`
3. Place it in `data/ipinfo_lite.mmdb`
4. Set `MMDB_PATH=data/ipinfo_lite.mmdb` in `.env`

---

## Architecture

```
NexusTrace/
├── app/
│   ├── routes/          # Blueprint-organized HTTP handlers
│   │   ├── home_routes.py       # Main analyze endpoint + type detection
│   │   ├── ip_routes.py         # Batch IP analysis (CSV/XLSX/TXT)
│   │   ├── domain_routes.py     # Domain/URL analysis
│   │   ├── hash_routes.py       # Hash reputation lookup
│   │   ├── file_routes.py       # File malware analysis
│   │   ├── azure_error_routes.py
│   │   ├── user_agent_routes.py
│   │   └── event_routes.py
│   │
│   ├── services/        # Business logic + API integrations
│   │   ├── ip_service.py        # VPNapi, IPinfo, IP2Location, Shodan, AbuseIPDB, OTX
│   │   ├── domain_service.py    # WHOIS, DNS, SSL, crt.sh, email security
│   │   ├── url_service.py       # Security headers, redirect chains, BuiltWith
│   │   ├── file_service.py      # Intezer file analysis
│   │   ├── hash_service.py      # VirusTotal, MalwareBazaar, ThreatFox, Intezer
│   │   ├── user_agent_service.py
│   │   ├── azure_error_service.py
│   │   └── event_service.py
│   │
│   └── utils/
│       ├── cache.py       # Thread-safe LRU cache with TTL
│       └── rate_limiter.py  # Sliding window rate limiter
│
├── templates/           # Jinja2 HTML templates
├── static/              # CSS, JS, images, PWA service worker
├── CyberChef_v10.19.4/  # Embedded CyberChef (offline capable)
├── main.py              # App entry point
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── nginx.conf
├── start.sh             # Start script (dev / docker / prod modes)
└── stop.sh              # Stop script (dev / docker / all / status)
```

**How type detection works:** The `/analyze` POST endpoint auto-detects the indicator type from its format — IPv4/IPv6, domain pattern, URL scheme, MD5/SHA1/SHA256 hash, AADSTS code, Windows Event ID, or user agent string — and routes to the appropriate analysis pipeline.

---

## API Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| `POST` | `/analyze` | Auto-detect and analyze any indicator |
| `POST` | `/api/ip/check_ip` | Single IP analysis |
| `POST` | `/api/ip/check_ips` | Batch IP analysis (CSV/XLSX/TXT upload) |
| `POST` | `/api/domain/check_domain` | Domain info lookup |
| `POST` | `/api/domain/analyze` | Full domain/URL analysis |
| `POST` | `/api/file/analyze_file` | File malware analysis (upload) |
| `POST` | `/api/hash/check_hash` | Hash reputation lookup |
| `POST` | `/api/azure_error/search` | Azure AD error code lookup |
| `GET`  | `/api/health` | Health check |
| `GET`  | `/api/cyberchef/recipes` | List saved CyberChef recipes |
| `POST` | `/api/cyberchef/recipes` | Save a CyberChef recipe |

---

## Deployment

### Docker Compose (recommended)

The included `docker-compose.yml` runs Flask behind Nginx:

```bash
cp .env.example .env   # configure your keys
./start.sh --docker    # build and start
./stop.sh --docker     # stop
```

View logs:
```bash
docker compose logs -f
```

### Manual / Gunicorn

```bash
pip install -r requirements.txt
gunicorn --bind 0.0.0.0:5050 --timeout 120 --workers 4 main:app
```

---

## Caching & Rate Limiting

- **Response cache:** 30-minute TTL, LRU eviction, max 1,000 items per service. Repeated lookups for the same indicator return instantly.
- **Rate limiting:** Per-service sliding window limits (e.g., 2 req/sec for WHOIS, 4 req/sec for AlienVault). Prevents API key bans under load.

---

## Acknowledgments

| Service | Purpose |
|---------|---------|
| [VPNapi](https://vpnapi.io/) | VPN / proxy / Tor detection |
| [IPinfo](https://ipinfo.io/) | IP geolocation + ASN |
| [IP2Location](https://www.ip2location.io/) | IP geolocation |
| [Shodan](https://shodan.io/) | Port scanning + CVEs |
| [AbuseIPDB](https://www.abuseipdb.com/) | Abuse reporting |
| [ProxyCheck](https://proxycheck.io/) | Proxy + VPN detection |
| [AlienVault OTX](https://otx.alienvault.com/) | Threat intelligence |
| [IP2WHOIS](https://www.ip2whois.com/) | WHOIS lookups |
| [URLscan.io](https://urlscan.io/) | URL scanning + screenshots |
| [Intezer](https://intezer.com/) | Malware analysis |
| [VirusTotal](https://www.virustotal.com/) | Hash reputation |
| [MalwareBazaar](https://bazaar.abuse.ch/) | Malware hash database |
| [crt.sh](https://crt.sh/) | Certificate transparency logs |
| [CyberChef](https://github.com/gchq/CyberChef) | Data transformation (GCHQ) |

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m 'Add feature'`
4. Push and open a Pull Request

---

## License

[Add license here]
