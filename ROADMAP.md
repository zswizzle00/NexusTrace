# NexusTrace Roadmap

Forward-looking plan for major capabilities. Items are grouped by theme with a rough
priority and the key technical decisions involved. This is a living document.

---

## 1. User Accounts + Per-User API Keys + Database

**Goal:** let users sign in and store their own API keys (encrypted), instead of one
global set of keys in `.env`. This is the foundation for multi-user use and history.

### Phase 1 - Introduce a database
- Add **SQLAlchemy** (ORM) + **Alembic** (migrations). SQLite for local dev, **PostgreSQL**
  for production (swap via `DATABASE_URL`).
- Initial models:
  - `User` (id, email, password_hash, created_at, is_active, role)
  - `ApiKey` (id, user_id FK, provider, encrypted_value, created_at, last_used)
  - `AnalysisHistory` (optional: id, user_id, indicator, type, created_at) for recent lookups
- Run via the existing Docker stack; add a `db` service (postgres) to `docker-compose.yml`
  and a one-shot migration step.

### Phase 2 - Authentication
- **Flask-Login** for session management + **argon2-cffi** (or werkzeug) for password hashing.
- Registration, login, logout, password reset. CSRF is already enabled globally.
- Gate per-user features behind `@login_required`; keep anonymous use working with env keys.
- Consider optional OAuth/SSO (Google/Microsoft) later for SOC team adoption.

### Phase 3 - Per-user encrypted API key vault
- Encrypt keys at rest with **Fernet** (`cryptography`); the master key comes from an env
  var / secrets manager (NEVER stored in the DB).
- Resolve keys at request time: **use the logged-in user's key if present, else fall back to
  the env key**. This keeps the current behavior for anonymous users.
- A settings page to add/test/revoke keys per provider, with a "test key" button that does a
  cheap live call to validate.

**Security notes:** keys are secrets - never log them, never return them to the client after
save (write-only), and scope DB access least-privilege. Add per-user rate limiting once the
shared cache/limiter (section 2) lands.

---

## 2. Caching + Shared State (Performance)

**Current state:** `app/utils/cache.py` is an in-process `timed_lru_cache` (30-min TTL,
max 1000 items). It is per-process, lost on restart, and NOT shared across gunicorn threads
or multiple instances. The rate limiters are likewise per-process.

**Goal:** faster repeat lookups and correct throttling under concurrency / horizontal scaling.

### Plan
- Introduce **Redis** as a shared cache + rate-limit backend (add a `redis` service to
  docker-compose).
- Cache external API responses keyed by `provider:indicator` with per-provider TTLs
  (reuse the 30-min default; tune per source). Wrap each service call through a small
  `cache.get_or_set(key, ttl, fn)` helper so all services cache consistently.
- Move rate limiting to Redis (sliding window) so limits are correct across workers/instances.
  This fixes the fragmentation where N workers each get their own limiter (e.g. Shodan would
  become N req/s). Until then we run a single gunicorn worker with threads on purpose.
- Optionally cache fully-rendered result fragments for hot indicators.
- Add cache-hit/miss counters surfaced on `/api/health` or a `/metrics` endpoint.

**Quick win before Redis:** the in-process cache is already decent for a single instance;
the highest-impact change is ensuring every service goes through the cache (some do not yet)
and that slow external calls run concurrently (already true for IP/domain/URL).

---

## 3. CyberChef Update Cadence

**Current:** vendored `CyberChef_v10.19.4/` (built ~a year ago) served as static files.

**Recommendation:**
- Check for new CyberChef releases **quarterly**, and update sooner if a release notes a
  **security fix** or an operation we rely on.
- CyberChef ships occasional minor/patch releases; there is no urgent monthly cadence, but a
  year-old build should be refreshed.
- Process to update: download the new release build, replace the `CyberChef_vX.Y.Z/` folder,
  update the version references (`cyberchef_routes.py`, docs, this file), and smoke-test the
  embedded iframe.
- Automate the check: a scheduled **GitHub Action** that queries the CyberChef releases API
  and opens an issue when a newer version exists (Dependabot does not track a vendored static
  folder).

---

## 4. More Enrichment Sources (free / scriptable, low external dependency)

Goal: broaden enrichment using **free APIs and scriptable techniques** that do not require
paid tooling. Grouped by indicator type. (* = no API key required.)

### IP
- **RDAP*** (`rdap.org` / RIR RDAP) - structured registration/ASN data, replaces legacy WHOIS.
- **Team Cymru IP-to-ASN*** - bulk ASN/BGP origin via DNS/whois, very fast, no key.
- **GreyNoise Community API** - is this IP internet background-noise / a known scanner (free tier).
- **ISC / DShield API*** - attack/report counts for an IP.
- **Public blocklists*** - Spamhaus DROP/EDROP, FireHOL aggregated lists, Tor exit-node list,
  Feodo Tracker (abuse.ch). Download + cache locally, then do O(1) membership checks.

### Domain / URL
- **RDAP*** for domain registration (free, structured).
- **URLhaus + abuse.ch feeds*** - known malicious URLs/domains (free).
- **OpenPhish / PhishTank*** - phishing feeds.
- **Certificate Transparency*** (crt.sh, already used) - subdomains + cert history.
- **Google Safe Browsing** (free API key) - malware/phishing verdict.
- DNS-based blocklists (Spamhaus DBL) via simple DNS queries*.

### File / Hash
- **abuse.ch MalwareBazaar / ThreatFox*** (already integrated, free).
- **CIRCL hashlookup*** - is this hash known-good (NSRL) or known-bad, free API.
- **Local YARA scanning*** - run YARA rules over uploaded files, fully offline/scriptable.
- File hashing locally (already done for the file endpoint after the Intezer removal).

### General threat-intel feeds (scriptable, free)
- **abuse.ch suite** (URLhaus, MalwareBazaar, ThreatFox, Feodo Tracker).
- **CISA Known Exploited Vulnerabilities (KEV)*** catalog.
- **MISP** feeds (self-hostable) for org-curated intel.
- **AlienVault OTX** (already integrated).

### Scriptable techniques (no external tool)
- Local **MMDB** GeoIP (already supported via `MMDB_PATH`).
- SSL/TLS certificate parsing (already), **JA3/JARM** fingerprinting.
- Passive DNS via free sources; DNS resolution + record analysis (already).

**Approach:** add these as individual service modules behind the existing cache + rate-limiter
pattern, each degrading gracefully when unavailable (same model as today). Prioritize the
no-key sources (RDAP, Team Cymru, abuse.ch feeds, blocklists, hashlookup) for immediate wins.

---

## Suggested order

1. Shared cache + Redis rate limiting (section 2) - unblocks correct scaling and speeds up repeats.
2. Free no-key enrichment sources (section 4) - high analyst value, low risk, no auth needed.
3. Database + accounts + per-user key vault (section 1) - larger effort, enables multi-user.
4. CyberChef refresh + automated version check (section 3) - small, do alongside the above.
