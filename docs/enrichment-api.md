# NexusTrace Enrichment API

The enrichment API provides programmatic access to NexusTrace's threat intelligence data. It is designed for integration into SIEM/SOAR pipelines, EDR triage workflows, and automation scripts. All endpoints authenticate via an API key — no browser session or CSRF token required.

Replace `<your-host>` throughout this document with your NexusTrace instance URL (e.g. `http://localhost:5050` for local dev, or your deployed host).

---

## Authentication

Every request must include the `X-API-Key` header.

```
X-API-Key: <your-key>
```

Requests without a key return `401`. Requests with a revoked or invalid key return `403`.

### Create a key

Run this on the server where NexusTrace is deployed:

```bash
python3 scripts/manage_api_keys.py create "My Integration Name"
```

Example output:
```
Created API key for 'My Integration Name':
  d6be269f749d6ee26e054dc95dc359d7c963e1800c08548189ba17995c50ff19

Store this key securely — it will not be shown again.
```

### List keys

```bash
python3 scripts/manage_api_keys.py list
```

### Revoke a key

```bash
python3 scripts/manage_api_keys.py revoke <full-key>
```

Keys are stored in `data/api_keys.json` on the server. This file is gitignored and never committed.

---

## Endpoints

### POST `/api/enrich/ip`

Enrich a single IP address.

**Request**

```bash
curl -s -X POST <your-host>/api/enrich/ip \
  -H "X-API-Key: <your-key>" \
  -H "Content-Type: application/json" \
  -d '{"ip": "8.8.8.8"}'
```

**Body**

| Field | Type   | Required | Description       |
|-------|--------|----------|-------------------|
| `ip`  | string | Yes      | IPv4 or IPv6 address |

**Response**

```json
{
  "indicator": "8.8.8.8",
  "indicator_type": "ip",
  "timestamp": "2026-02-23T15:00:00Z",
  "summary": {
    "country": "US",
    "city": "Mountain View",
    "region": "California",
    "asn": "AS15169",
    "org": "Google LLC",
    "is_vpn": false,
    "is_proxy": false,
    "is_tor": false,
    "abuse_score": 0,
    "total_abuse_reports": 0,
    "threat_pulse_count": 2,
    "open_ports": [53, 443]
  },
  "sources": {
    "vpnapi":     { ... },
    "ipinfo":     { ... },
    "abuseipdb":  { ... },
    "shodan":     { ... },
    "alienvault": { ... }
  }
}
```

`summary` fields at a glance:

| Field                 | Source      | Description                              |
|-----------------------|-------------|------------------------------------------|
| `country`, `city`, `region` | VPNapi / IPinfo | Geolocation                      |
| `asn`, `org`          | VPNapi / IPinfo | Network / ASN info                  |
| `is_vpn`              | VPNapi      | Whether the IP is a known VPN exit node  |
| `is_proxy`            | VPNapi      | Whether the IP is a known proxy          |
| `is_tor`              | VPNapi      | Whether the IP is a Tor exit node        |
| `abuse_score`         | AbuseIPDB   | Abuse confidence score (0–100)           |
| `total_abuse_reports` | AbuseIPDB   | Number of abuse reports in 90 days       |
| `threat_pulse_count`  | AlienVault  | Number of OTX threat pulses              |
| `open_ports`          | Shodan      | Open ports detected by Shodan            |

`sources` contains trimmed data from each upstream service (large blobs like Shodan HTTP screenshots, AlienVault pulse lists, and AbuseIPDB individual reports are excluded), or `null` if that service is unconfigured or failed.

| Source      | Fields included                                                                 |
|-------------|---------------------------------------------------------------------------------|
| `vpnapi`    | Full response (small — security flags, network, location)                       |
| `ipinfo`    | Full response (small — geo, ASN, org)                                           |
| `abuseipdb` | Score, report count, ISP, usage type — individual reports omitted               |
| `shodan`    | Org, ISP, OS, hostnames, ports (number/service/product/version), vulnerabilities — banners and HTTP screenshots omitted |
| `alienvault`| Pulse count, reputation, ASN, country, geo — full pulse/malware/passive DNS lists omitted |

---

### POST `/api/enrich/domain`

Enrich a domain or URL.

**Request**

```bash
# Domain
curl -s -X POST <your-host>/api/enrich/domain \
  -H "X-API-Key: <your-key>" \
  -H "Content-Type: application/json" \
  -d '{"indicator": "google.com"}'

# URL
curl -s -X POST <your-host>/api/enrich/domain \
  -H "X-API-Key: <your-key>" \
  -H "Content-Type: application/json" \
  -d '{"indicator": "https://phishing-example.com/login"}'
```

**Body**

| Field       | Type   | Required | Description                          |
|-------------|--------|----------|--------------------------------------|
| `indicator` | string | Yes      | A domain (`google.com`) or full URL (`https://...`) |

**Response**

```json
{
  "indicator": "google.com",
  "indicator_type": "domain",
  "timestamp": "2026-02-23T15:00:00Z",
  "summary": {
    "registrar": "MarkMonitor Inc.",
    "created_date": "1997-09-15T04:00:00Z",
    "expires_date": "2028-09-14T04:00:00Z",
    "ip_address": "142.250.80.46",
    "ssl_valid": true,
    "ssl_expires": "Apr 14 08:00:00 2026 GMT",
    "threat_pulse_count": 0,
    "status_code": 200,
    "redirect_count": 1
  },
  "sources": {
    "whois":        { ... },
    "dns":          { ... },
    "ssl":          { ... },
    "url_analysis": { ... },
    "alienvault":   { ... }
  }
}
```

`status_code` and `redirect_count` are only populated for URL indicators (i.e. when `indicator` starts with `http://` or `https://`). They will be `null` for plain domain lookups.

---

### POST `/api/enrich/batch`

Enrich up to **20** indicators in a single request. Indicators can be a mix of IPs, domains, and URLs. Each is processed in parallel. A failure on one indicator does not affect the others.

**Request**

```bash
curl -s -X POST <your-host>/api/enrich/batch \
  -H "X-API-Key: <your-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "indicators": [
      "8.8.8.8",
      "1.1.1.1",
      "google.com",
      "https://suspicious-site.example/payload"
    ]
  }'
```

**Body**

| Field        | Type            | Required | Description                                   |
|--------------|-----------------|----------|-----------------------------------------------|
| `indicators` | array of strings | Yes     | Mix of IPs, domains, and URLs. Max 20 entries. |

**Response**

```json
{
  "results": [
    {
      "indicator": "8.8.8.8",
      "indicator_type": "ip",
      "timestamp": "...",
      "summary": { ... },
      "sources": { ... }
    },
    {
      "indicator": "google.com",
      "indicator_type": "domain",
      "timestamp": "...",
      "summary": { ... },
      "sources": { ... }
    },
    {
      "indicator": "bad-input!!!",
      "indicator_type": "unknown",
      "timestamp": "...",
      "error": "Cannot determine indicator type for: 'bad-input!!!'"
    }
  ],
  "meta": {
    "total": 3,
    "processed": 3,
    "errors": 1,
    "timestamp": "2026-02-23T15:00:00Z"
  }
}
```

Results are returned in the same order as the input `indicators` array. Entries with an `"error"` field failed individually; all other results are valid.

---

## Error Reference

| HTTP status | Meaning                                        |
|-------------|------------------------------------------------|
| `200`       | Success                                        |
| `400`       | Bad request — missing or invalid field         |
| `401`       | Missing `X-API-Key` header                     |
| `403`       | Invalid or revoked API key                     |
| `500`       | Server-side error (check server logs)          |

---

## Self-Hosting Notes

### API key storage and Docker

API keys are stored in `data/api_keys.json` on the server. This file is gitignored and never committed. When running via Docker Compose, the `data/` directory must be bind-mounted into the container or the app will not find any keys:

```yaml
# docker-compose.yml — web service volumes section
volumes:
  - app_logs:/app/logs
  - ./data:/app/data   # required for API key persistence
```

After adding this mount, recreate the container:

```bash
docker-compose up -d --force-recreate web
```

Keys created with `manage_api_keys.py` on the host are immediately visible to the running container through the mount.

### Running behind a reverse proxy

If NexusTrace is deployed behind Nginx, Caddy, or a cloud load balancer, ensure the `X-API-Key` header is forwarded to the origin. Most reverse proxies pass unknown headers through by default — no special configuration is needed unless you have a header allowlist in place.

If you terminate TLS at the proxy, set the following in your `.env` on the origin server:

```
SECURE_COOKIES=true
```

This marks session cookies as `Secure` so they are only sent over HTTPS.

### Caching

NexusTrace caches upstream API responses for 30 minutes per indicator. Repeated queries for the same IP, domain, or URL within that window are served from cache without hitting upstream APIs again. This applies to both the web UI and the enrichment API.

---

## Quick Integration Examples

### Python

```python
import requests

BASE = "http://<your-host>"  # e.g. http://localhost:5050
HEADERS = {"X-API-Key": "<your-key>", "Content-Type": "application/json"}

def enrich_ip(ip):
    r = requests.post(f"{BASE}/api/enrich/ip", json={"ip": ip}, headers=HEADERS, timeout=60)
    r.raise_for_status()
    return r.json()

def enrich_batch(indicators):
    r = requests.post(f"{BASE}/api/enrich/batch", json={"indicators": indicators}, headers=HEADERS, timeout=120)
    r.raise_for_status()
    return r.json()

result = enrich_ip("8.8.8.8")
print(result["summary"]["is_vpn"])

batch = enrich_batch(["1.1.1.1", "google.com", "https://example.com"])
for item in batch["results"]:
    if "error" in item:
        print(f"[ERROR] {item['indicator']}: {item['error']}")
    else:
        print(f"{item['indicator']} ({item['indicator_type']}): {item['summary']}")
```

### PowerShell

```powershell
$base    = "http://<your-host>"
$headers = @{ "X-API-Key" = "<your-key>"; "Content-Type" = "application/json" }

$body   = '{"ip": "8.8.8.8"}'
$result = Invoke-RestMethod -Method POST `
    -Uri "$base/api/enrich/ip" `
    -Headers $headers `
    -Body $body

$result.summary
```

### jq filtering (curl + jq)

```bash
# Extract just the summary from an IP enrichment
curl -s -X POST <your-host>/api/enrich/ip \
  -H "X-API-Key: <your-key>" \
  -H "Content-Type: application/json" \
  -d '{"ip": "8.8.8.8"}' | jq '.summary'

# Get all IPs from a batch that are VPNs
curl -s -X POST <your-host>/api/enrich/batch \
  -H "X-API-Key: <your-key>" \
  -H "Content-Type: application/json" \
  -d '{"indicators": ["1.1.1.1", "185.220.101.1", "8.8.8.8"]}' \
  | jq '[.results[] | select(.summary.is_vpn == true) | .indicator]'
```
