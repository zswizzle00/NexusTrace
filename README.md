# NexusTrace

**Open-source threat intelligence and OSINT analysis platform.** Submit an IP, domain, URL, file, hash, e-mail (`.eml`), or user agent string and get enriched context from across the threat intelligence ecosystem, all in one dashboard.

Built for security analysts, incident responders, and researchers who need fast, cross-referenced context on indicators of compromise without jumping between a dozen tools.

---

## Features

### IP Analysis
- Geolocation, ASN, and network data (IPinfo + IP2Location)
- VPN / Proxy / Tor detection (VPNapi + ProxyCheck)
- Open ports and running services (Shodan)
- Known CVEs and vulnerabilities (Shodan)
- Abuse history and confidence score (AbuseIPDB)
- Threat intelligence pulses (AlienVault OTX) and IOC cross-reference (ThreatFox, URLhaus)
- Batch analysis: upload a CSV/XLSX/TXT of IPs and get an enriched CSV back

### Domain & URL Analysis
- WHOIS registration data (IP2WHOIS)
- DNS records: A, AAAA, MX, NS, TXT, CNAME, SOA
- SSL/TLS certificate details
- HTTP security headers analysis
- SPF / DKIM / DMARC email security posture
- Subdomain enumeration via certificate transparency logs (crt.sh)
- Redirect chain tracking, validated hop-by-hop before the browser ever navigates (SSRF guard)
- Technology stack fingerprinting
- Meta tags, OpenGraph, and favicon extraction
- Threat intelligence (AlienVault OTX) and IOC cross-reference (ThreatFox, URLhaus)
- Heuristic verdict with explicit signals (structural only, no reputation source yet)
- Form capture with credential-prompt (password field) detection
- Dropper detection: file downloads are hashed (SHA-256) and pivot into hash reputation lookup
- Staged screenshots (on load / after scroll / after cookie-consent dismissal)
- Defanged IOC extraction (URLs, domains, IPv4) from page content and network activity

### File & Hash Analysis
- Static inspection: magic-byte identification, Shannon entropy, embedded-executable detection,
  and a dedicated Windows `.lnk` shortcut parser (30+ attacker-relevant signals)
- Office macro extraction (`oletools`): auto-executing macros, obfuscated VBA, download
  cradles, and shell execution
- PDF structure inspection: JavaScript, automatic actions, launch actions and embedded
  files, counted as whole normalised name tokens so hex-escaped keywords like
  `/J#61vaScript` are caught and reported as obfuscated
- YARA matching against operator-supplied rules, off until rules are installed
- Multi-source reputation lookup: VirusTotal, MalwareBazaar, ThreatFox, CIRCL hashlookup
  (NIST NSRL-backed), and Team Cymru's Malware Hash Registry
- Threat intelligence cross-reference (AlienVault OTX)
- Heuristic verdict with explicit, weighted signals

### E-mail Analysis (`.eml`)
- Upload an `.eml` file or paste raw message source (no mail server needed)
- SPF / DKIM / DMARC authentication parsing
- Spoofing detection: Reply-To mismatch, Return-Path mismatch, display-name impersonation
- URL display-text-vs-target mismatch detection in message bodies
- Attachment hashing (MD5 + SHA-256) with a reputation pivot into hash analysis
- Received-chain IP extraction with enrichment (geolocation, ASN, abuse score)
- DNSBL sender-IP reputation (Spamhaus, SpamCop, Barracuda)
- Defanged IOC extraction with copy-all, and a heuristic verdict with explicit signals
- Only parsed findings are ever stored: the raw message, body, and attachment bytes are not

### Community Reporting
- Queue an indicator or a re-attached malware sample for submission to abuse.ch
  (MalwareBazaar / ThreatFox) directly from a result page
- Queueing never transmits anything by itself: a human operator reviews and explicitly
  approves each submission before it leaves the deployment

### Data Governance
- Every result page shows exactly which third parties a lookup reaches and what it sends them
- Records (scans, e-mail analyses) can be deleted on demand from their own result page
- 30-day default retention for stored analysis records

### Programmatic Access
- **Enrichment API** (`/api/enrich/*`): API-key-authenticated endpoints for IP, domain/URL, and
  batch (up to 20 mixed indicators) lookups, built for SIEM/SOAR and EDR triage pipelines.
  See [`docs/enrichment-api.md`](docs/enrichment-api.md).

### Additional Tools
- **Azure AD Error Decoder**: Look up AADSTS error codes with descriptions and remediation steps
- **Windows Event ID Reference**: Decode Windows Security event IDs
- **User Agent Parser**: Break down browser, OS, device, and bot flags from any UA string
- **CyberChef**: Embedded CyberChef v11.3.0 for in-browser data encoding, decoding, and transformation

---

## Quick Start

> **Prerequisite:** dependencies are managed with [uv](https://docs.astral.sh/uv/).
> Install it once with `curl -LsSf https://astral.sh/uv/install.sh | sh`.
> (Docker builds do not use uv: the image installs from `requirements.txt` with pip, so
> after `uv add <pkg>` you must run `uv export --no-dev --no-hashes -o requirements.txt`
> or the Docker build silently misses the new dependency.)

### Option 1: Dev Server (Recommended for testing)

```bash
git clone https://github.com/zswizzle00/NexusTrace.git
cd NexusTrace
cp .env.example .env
# Edit .env with your API keys
./start.sh          # runs `uv sync`, then starts the dev server
```

Server starts at `http://localhost:5050`

### Option 2: Docker (Recommended for deployment)

```bash
git clone https://github.com/zswizzle00/NexusTrace.git
cd NexusTrace
cp .env.example .env
# Edit .env with your API keys
./start.sh --docker
```

- Flask app: `http://localhost:5050`
- Nginx reverse proxy: `http://localhost:80`

### Option 3: Production Docker

```bash
./start.sh --prod     # cached build - minutes
./start.sh --clean    # cold rebuild, discards the cache - ~40 minutes
```

`--prod` reuses cached layers. Only reach for `--clean` when you actually need a cold
build (base-image refresh, suspected corrupt cache): it re-downloads Chromium, every
apt package, and every wheel.

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
VIRUSTOTAL_API_KEY=    # https://www.virustotal.com/gui/my-apikey

# Threat Intelligence
ALIENVAULT_KEY=        # https://otx.alienvault.com/api
ABUSECH_AUTH_KEY=      # https://auth.abuse.ch/ - MalwareBazaar, ThreatFox, URLhaus, Hunting

# Server
SECRET_KEY=your-random-secret-key
SECURE_COOKIES=false   # set true when running behind HTTPS
FLASK_DEBUG=False
FLASK_HOST=0.0.0.0
FLASK_PORT=5050

# Optional: offline IP lookups
# MMDB_PATH=/path/to/ipinfo_lite.mmdb
```

> **All API keys are optional.** The tool gracefully skips any service whose key is not configured; cards for that service simply won't appear in results. CIRCL hashlookup and Team Cymru MHR need no key at all.

### IPinfo MMDB (optional, offline mode)

For faster lookups without API rate limits, download the IPinfo Lite MMDB database:

1. Sign up at [ipinfo.io/lite](https://ipinfo.io/lite)
2. Download and extract `ipinfo_lite.mmdb`
3. Place it in `data/ipinfo_lite.mmdb`
4. Set `MMDB_PATH=data/ipinfo_lite.mmdb` in `.env`

### YARA rules (optional)

NexusTrace ships with no detection rules, so YARA matching is off and the YARA card
never renders. To turn it on:

```bash
uv run python scripts/setup_yara_rules.py
```

This downloads [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) into
`data/yara/`, which is git-ignored. Rules compile once at start-up, so restart the app
afterwards.

Those rules are published under Detection Rule License 1.1. It requires that messages
based on a match identify the rule's author, which is why the result card has an Author
column. Leave it in place.

To use a different ruleset, put `.yar` files in `data/yara/` yourself, or point
`NEXUSTRACE_YARA_DIR` somewhere else. A ruleset that fails to compile disables matching
and logs the reason rather than breaking uploads.

---

## Architecture

```
NexusTrace/
├── app/
│   ├── routes/          # Blueprint-organized HTTP handlers
│   │   ├── home_routes.py       # Main analyze endpoint + type detection
│   │   ├── ip_routes.py         # Single + batch IP analysis (CSV/XLSX/TXT)
│   │   ├── domain_routes.py     # Domain/URL analysis
│   │   ├── hash_routes.py       # Hash reputation lookup
│   │   ├── file_routes.py       # File malware analysis
│   │   ├── scan_routes.py       # URL scanner (submit + result + screenshots + delete)
│   │   ├── email_routes.py      # .eml analysis (upload/paste + result + delete)
│   │   ├── submission_routes.py # Queue abuse.ch submissions (never transmits)
│   │   ├── enrichment_routes.py # API-key-authenticated enrichment API
│   │   ├── health_routes.py
│   │   ├── cyberchef_routes.py / cyberchef_api.py
│   │   ├── azure_error_routes.py
│   │   ├── user_agent_routes.py
│   │   └── event_routes.py
│   │
│   ├── services/        # Business logic + API integrations
│   │   ├── ip_service.py        # VPNapi, IPinfo, IP2Location, Shodan, AbuseIPDB, OTX
│   │   ├── domain_service.py    # WHOIS, DNS, SSL, crt.sh, email security
│   │   ├── url_service.py       # Security headers, redirect chains, BuiltWith
│   │   ├── file_service.py      # File hashing, static inspection, OTX reputation
│   │   ├── hash_service.py      # VirusTotal, MalwareBazaar, ThreatFox, CIRCL, Cymru MHR
│   │   ├── abusech.py           # MalwareBazaar / ThreatFox / URLhaus / Hunting client
│   │   ├── submissions.py       # Queue-then-approve outbound abuse.ch submissions
│   │   ├── scan_service.py      # Playwright URL scanner
│   │   ├── scan_rules.py        # Scanner heuristic verdict (pure)
│   │   ├── email_service.py     # .eml enrichment + persistence
│   │   ├── email_rules.py       # E-mail heuristic verdict (pure)
│   │   ├── file_rules.py        # File/LNK heuristic verdict (pure)
│   │   ├── health_service.py
│   │   ├── user_agent_service.py
│   │   ├── azure_error_service.py
│   │   └── event_service.py
│   │
│   └── utils/
│       ├── cache.py         # Thread-safe LRU cache with TTL
│       ├── rate_limiter.py  # Sliding window rate limiter
│       ├── storage.py       # Local/GCS-backed record storage
│       ├── url_guard.py     # SSRF / target-safety guard for the scanner
│       ├── email_parse.py   # .eml parsing (pure, stdlib only)
│       ├── file_inspect.py  # Magic bytes, entropy, embedded executables (pure)
│       ├── lnk_parse.py     # Windows .lnk shortcut parser (pure)
│       ├── office_inspect.py # Office macro extraction via oletools (pure)
│       ├── pdf_inspect.py   # PDF keyword and structure detection (pure, stdlib only)
│       ├── yara_scan.py     # YARA matching, operator-supplied rules (pure)
│       ├── hash_reputation.py # CIRCL/Cymru MHR response mapping (pure)
│       ├── disclosure.py    # Acceptable-use registry backing the data-governance notice
│       ├── iocs.py          # IOC extraction + defanging (pure)
│       ├── validators.py    # IP / domain / URL validation
│       └── api_auth.py      # API-key auth for the enrichment API
│
├── templates/           # Jinja2 HTML templates
├── static/              # CSS, JS, images, PWA service worker
├── CyberChef_v11.3.0/   # Embedded CyberChef (offline capable)
├── main.py              # App entry point
├── pyproject.toml       # Project metadata + dependencies (uv)
├── uv.lock              # Pinned, resolved dependency lockfile
├── Dockerfile
├── docker-compose.yml
├── nginx.conf
├── start.sh             # Start script (dev / docker / prod / clean modes)
├── stop.sh              # Stop script (dev / docker / all / status)
└── nexus_auto_update.sh # Production updater: fetch + reset + cached rebuild, in place
```

**How type detection works:** The `/analyze` POST endpoint auto-detects the indicator type from its format (IPv4/IPv6, domain pattern, URL scheme, MD5/SHA1/SHA256 hash, AADSTS code, Windows Event ID, or user agent string) and routes to the appropriate analysis pipeline.

---

## API Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| `POST` | `/analyze` | Auto-detect and analyze any indicator |
| `GET`  | `/i/<indicator>` | Same analysis via a shareable deep link |
| `POST` | `/url_scan` | Run a URL scan, redirects to the result page |
| `GET`  | `/url_scan/screenshot/<scan_id>` | Serve a stored (optionally staged) screenshot |
| `POST` | `/api/ip/check_ip` | Single IP analysis |
| `POST` | `/api/ip/check_ips` | Batch IP analysis (CSV/XLSX/TXT upload) |
| `POST` | `/api/domain/check_domain` | Domain info lookup |
| `GET,POST` | `/api/domain/analyze` | Full domain/URL analysis |
| `GET`  | `/file_analysis` | File analysis form |
| `POST` | `/api/file/analyze` | File analysis, renders the result page |
| `POST` | `/api/file/analyze_file` | File malware analysis (upload), JSON |
| `POST` | `/api/hash/check_hash` | Hash reputation lookup |
| `GET,POST` | `/api/hash/analyze` | Hash analysis page |
| `GET`  | `/email_analysis` | E-mail analysis form + recent analyses |
| `POST` | `/email_analysis` | Analyze an `.eml` upload or pasted raw source |
| `GET`  | `/email_analysis/<analysis_id>` | E-mail analysis result page |
| `POST` | `/submit/queue` | Queue an IOC submission for operator approval |
| `POST` | `/submit/sample` | Queue a re-attached sample for operator approval |
| `POST` | `/api/azure_error/search` | Azure AD error code lookup |
| `POST` | `/api/event/search` | Windows Event ID lookup |
| `GET`  | `/api/health` | Health check + which API keys are configured |
| `GET,POST` | `/api/cyberchef/recipes` | List / save CyberChef recipes |
| `POST` | `/api/enrich/ip` | Enrichment API: IP (API key auth) |
| `POST` | `/api/enrich/domain` | Enrichment API: domain or URL (API key auth) |
| `POST` | `/api/enrich/batch` | Enrichment API: up to 20 mixed indicators (API key auth) |

Every browser-facing route above (everything except `/api/enrich/*`) is protected by
Flask-WTF CSRF; the enrichment API authenticates with `X-API-Key` instead. See
[`docs/enrichment-api.md`](docs/enrichment-api.md) for full enrichment API request/response schemas.

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

Dependencies are managed with [uv](https://docs.astral.sh/uv/). Install it once:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Then sync the environment and run. The URL scanner launches a real browser per scan, so
the process must use threads rather than multiple workers:

```bash
uv sync                                                          # create .venv from uv.lock
uv run gunicorn --bind 0.0.0.0:5050 --workers 1 --threads 8 --worker-class gthread --timeout 120 main:app
```

---

## Caching & Rate Limiting

- **Response cache:** 30-minute TTL, LRU eviction. Repeated lookups for the same indicator return instantly.
- **Rate limiting:** Per-service sliding window limits (e.g., 2 req/sec for WHOIS and abuse.ch, 4 req/sec for AlienVault and Team Cymru MHR, 4 req/**min** for VirusTotal's free tier). Prevents API key bans under load.

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
| [VirusTotal](https://www.virustotal.com/) | Hash reputation |
| [abuse.ch](https://abuse.ch/) | MalwareBazaar, ThreatFox, URLhaus malware/IOC intelligence |
| [CIRCL hashlookup](https://www.circl.lu/services/hashlookup/) | NSRL-backed hash reputation |
| [Team Cymru](https://team-cymru.com/) | Malware Hash Registry + ASN lookup |
| [crt.sh](https://crt.sh/) | Certificate transparency logs |
| [CyberChef](https://github.com/gchq/CyberChef) | Data transformation (GCHQ) |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development environment setup, coding conventions, and how to submit a pull request.

---

## License

[MIT](LICENSE)
