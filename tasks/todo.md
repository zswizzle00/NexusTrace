# UI fixes + backend cleanup (2026-06-16)

Goal: fix "buggy" UI and "weird loading times"; deep-dive code cleanup.
Scope chosen with user: **Fixes + visual polish** (keep dark/blue identity) and
**pre-built static Tailwind CSS** (no everyday build step).

## Root cause of slow/weird loading
- `cdn.tailwindcss.com` is a **runtime in-browser compiler** (dev-only) → FOUC + delay.
- jsPDF + jspdf-autotable + html2canvas (~450 KB) loaded **render-blocking on every page**,
  but their only consumer was `static/js/main.js`, which **no template ever loaded** (dead).
- Service worker `fetch` handler was an empty no-op while precaching assets it never served.

## Done
- [x] Pre-compiled Tailwind → `static/css/tailwind.css` (23 KB, minified) via standalone v3.4.17 CLI.
      Replaced CDN `<script>` with `<link>`. Added font `preconnect`. Config: `tailwind.config.js`,
      input: `static/css/tailwind-input.css` (both committed). Binary in `tools/` (gitignored).
- [x] Deleted dead `static/js/main.js` (53 KB) and `static/js/cyberchef.js` (unused).
- [x] Removed the 3 render-blocking PDF CDN scripts from `base.html` (only consumer was dead main.js).
- [x] Rewrote `static/sw.js`: network-first for navigations (no stale pages after deploy),
      stale-while-revalidate for `/static/` assets; bumped cache to `nexustrace-v2`; dropped main.js.
- [x] UI bugs: CyberChef iframe offset (`4.5rem` → `var(--header-height,64px)`, removes 8px gap);
      dropdown z-index hierarchy (main 100 / submenu 110, both above sticky header z-50).
- [x] Visual polish (inline `<style>`, the cascade-authoritative block): body radial-accent atmosphere,
      header blur+depth, card gradient + lift hover, gradient buttons with active state, focus ring,
      animated center-out nav underline.
- [x] Backend cleanup: narrowed bare `except:` (ip_routes.py); deleted dead `get_ip_info()`
      (ip_service.py, imported a non-existent module); 3 silent `except: pass` → `logger.debug`
      (url_service x2, domain_service x1); standardized AlienVault env (`ALIENVAULT_API_KEY` →
      `OTX_API_KEY` to match file_service + docs); test ports 5000 → 5050 (both test files).

## Verification
- `python3 -m py_compile` on all 6 changed Python files → OK.
- `get_ip_info` has zero remaining references; no dangling main.js/cyberchef.js/jspdf/CDN-tailwind refs.
- Tailwind output class-coverage spot-checked (incl. dynamically-applied `bg-gray-700/50`,
  `bg-green-900`, etc.) + preflight base layer present.
- base.html inline `<style>` brace-balanced (63/63).
- NOT run: live server / Selenium screenshots; Flask deps aren't installed in this env.
  User should boot the app and hard-refresh (clear old SW) to confirm visuals (see summary).

## Deferred (recommended follow-ups, need test coverage to do safely)
- Full removal of the ~380-line inline `<style>` in base.html that duplicates `styles.css`
  (risky to do blind without visual verification; inline block currently wins the cascade).
- ~~Dedupe `is_valid_ip`/`is_valid_domain`/`is_valid_url` into `app/utils/validators.py`~~
  Already done: `app/utils/validators.py` is the only definition site.
- ~~Shared `app/utils/constants.py` for the duplicated TIMEOUT_* constants.~~
  Already done in `c9a24788`; audited 2026-07-29, every HTTP/socket timeout in the service
  layer routes through `TIMEOUT_SHORT`/`MEDIUM`/`LONG` and `app/routes/` has none. The one
  remaining raw literal is `scan_service.py:203,210` `socket.create_connection(..., timeout=8)`
  for TLS inspection; 8 matches no constant, left deliberately.
- ~~`test_endpoints.py` paths are also stale~~ Rewritten 2026-07-29: 127 assertions, green.
- PDF export was dead code: if it's a wanted feature, re-add it lazy-loaded on result pages only.

---

# 2026-07-28: Scanner hardening + Detonator ports

Branch `feat/scanner-hardening`. Full context: `docs/superpowers/2026-07-28-session-record.md`.
Plan: `docs/superpowers/plans/2026-07-28-scanner-hardening-and-detonator-ports.md`.

## Acceptance criteria
- [x] A redirect to a private/link-local address is not fetched by the scanner
- [x] Subresources cannot surface internal-host status/IP in the rendered report
- [x] Legitimate `http://` -> `https://` redirects still scan correctly, at the right origin
- [x] No new dependencies; existing tests still pass
- [x] Scanner renders a real verdict instead of a hardcoded `informational`
- [x] Dropper URLs yield a payload hash that pivots into hash reputation
- [x] Scans persisted before this work still render

## Progress
- [x] Task 1: `app/utils/url_guard.py` SSRF guard, 64 test cases (review clean)
- [x] Task 2: guard installed on every Chromium request (10 findings fixed)
- [x] Task 2: re-review gate run 2026-07-29. **The popup hole was real.** A `window.open`
      popup could write `nav_state` and falsify the report's DNS/TLS/ASN/PTR/WHOIS and the
      `cross_domain_redirect` signal. Reproduced against real Chromium with the unmodified
      guard. Fixed by gating on `request.frame is page.main_frame` instead of
      `parent_frame is None`; regression pinned by `app/tests/test_nav_gate.py`.
- [x] Tasks 3-5: forms/password capture, dropper payload capture, staged screenshots
- [x] Tasks 6-7: rule engine + wiring (highest remaining risk; see tasks/lessons.md)
- [x] Tasks 8-9: IOC extract/defang + wiring
- [x] Tasks 10-11: verdict UI, payload hash pivot, IOC panel, filmstrip
- [x] Task 12: docs + full verification sweep

## Working notes
- `data/scans/*.json` is re-read from disk: every new key needs `.get()` in Python
  and a `{% if %}` guard in templates, or old scans 500.
- Rule-engine bands ended at 0.85 malicious / 0.25 suspicious, NOT Detonator's 0.80 (no
  reputation source in the scan path). Labelled a structural heuristic in the UI. Both bands
  are derived from the case table in `test_scan_rules.py`; changing a weight means
  re-deriving them.
- Docker installs from `requirements.txt` via pip, not uv. After `uv add`, run
  `uv export --no-dev --no-hashes -o requirements.txt` or Docker misses the dep.

## Results (as of 2026-07-28)
SSRF hole closed and verified: redirects to `169.254.169.254` / `127.0.0.1` blocked in
0.6s before a browser opens; `http://github.com` still completes (301->200, all links
`https`, `main_ip` 140.82.112.4 / AS36459); `https://example.com` 200 in 2.8s.
45 behavioural checks on the guard module all pass.

## Next session
~~All three items done; see the 2026-07-29 close-out at the bottom of this file.~~
1. ~~Run Task 2's re-review gate (the popup question above).~~ Done; the hole was real.
2. ~~Continue Tasks 3-12.~~ Done.
3. ~~Derez Phase 1: e-mail (`.eml`) analysis.~~ Done.

## Scanner follow-ups (deliberately out of scope in 2026-07-28 plan)

- **Reputation in the scan path.** `scan_rules.py` has no reputation signal, so its
  top band (`MALICIOUS_THRESHOLD = 0.85`) is structural-only.
  `ip_service.get_alienvault_data` and `hash_service.get_virustotal_report` already
  exist; wiring them into `run_scan` (concurrently, like `home_routes._run_parallel`)
  would let the malicious band mean what it says. Detonator weights these at 0.90
  (Web Risk) and 0.50 (VT).
- ~~**Suspicious-band tuning.**~~ Resolved: `SUSPICIOUS_THRESHOLD` raised 0.20 → 0.25, the
  top of the range the test case table permits, so weak headers (0.10) plus a fresh Let's
  Encrypt cert (0.10) no longer reach the band on their own. Verified: live scans of
  `example.com` and `github.com` both return `benign`.
- **Public-suffix list.** `validators.registrable_domain()` (moved out of `scan_rules.py`)
  uses a hardcoded multi-label-suffix set. Correct fix is a PSL, which is a new dependency.
  Now shared by the scanner *and* e-mail analysis, so the blast radius of getting it wrong
  has doubled.
- **Per-request guard latency.** `_install_fetch_guard` round-trips every request to
  Python. Measured acceptable on ordinary pages; revisit if a content-heavy scan
  starts timing out at the 120s gunicorn limit.
- **Subresource redirect re-validation.** A subresource whose own URL redirects is
  not re-validated on that redirect hop (upstream Playwright limitation; see
  `_install_fetch_guard`'s docstring). Currently mitigated, not eliminated, by
  filtering `transactions`/`domains`/`ips` through the guard again before
  persistence, so an internal host's status/IP cannot reach the rendered report,
  but the request itself still went out.
- **DNS-rebinding TOCTOU.** Validation and Chromium's own later connection are
  separate resolutions; an attacker who wins that race is not stopped. Closing it
  needs resolve-and-pin at the network layer (e.g. Chromium
  `--host-resolver-rules`) or egress restriction on the scanner host/container.
- ~~**WebSocket guard verification.**~~ Resolved: `app/tests/test_ws_guard.py` asserts both
  `_validate_ws_target` and that the installed handler never calls `connect_to_server()` for
  a blocked target (40 + 40 + 3 cases, mutation-checked). Still unasserted: that Playwright
  actually dispatches `route_web_socket` for a page's `new WebSocket(...)`; that needs live
  Chromium and a listening server, and remains a log-line confirmation.
- **Cloaking heuristic.** Detonator weakens a `benign` verdict on a young,
  never-before-scanned domain reached from datacenter egress, on the theory the kit
  served us a decoy. Needs prior-scan history to be meaningful here.

---

# 2026-07-29, Derez Phase 1: e-mail analysis

Branch `feat/scanner-hardening`. Spec: `docs/superpowers/specs/2026-07-29-email-analysis-design.md`.
Plan: `.superpowers/sdd/2026-07-29-email-analysis/`.

## Acceptance criteria
- [x] Upload an `.eml` or paste raw message source and get a parsed, scored analysis
- [x] SPF/DKIM/DMARC authentication parsed from `Authentication-Results` / `Received-SPF`
- [x] Spoofing detection: reply-to mismatch, return-path mismatch, display-name impersonation
      (word-boundary brand matching, not substring)
- [x] URL display-text-vs-target mismatch flagged in extracted body URLs
- [x] Attachments hashed (MD5 + SHA-256) and metadata-only, never bytes, persisted
- [x] Received-chain public IPs extracted and enriched, bounded to `MAX_ENRICH_IPS = 5`
- [x] Attachment hashes enriched via hash reputation, bounded to `MAX_ENRICH_HASHES = 3`
      (3, not 5: VirusTotal's 4-req/min limiter *blocks*, so a 5th hash sleeps past
      `ENRICH_DEADLINE` and silently drops the one signal that reaches `malicious` alone)
- [x] DNSBL sender-IP reputation lookup (Spamhaus, SpamCop, Barracuda)
- [x] Heuristic verdict (`app/services/email_rules.py:score()`), banded at
      `SUSPICIOUS_THRESHOLD = 0.30` / `MALICIOUS_THRESHOLD = 0.75`, with the ambient-header
      floor property verified (`missing_message_id`/`missing_mime_version`/`date_anomaly`/
      `suspicious_mailer` sum to 0.20, below the suspicious band)
- [x] Findings persisted to `data/analyses/<uuid>.json`; raw message/body/attachment bytes
      never persisted, enforced by an explicit `_assemble()` allowlist
- [x] Malformed messages degrade to `status='error'` / `verdict.level='unknown'`, never a 500
- [x] Forward-compatible rendering: every field read with `.get()`, guarded in templates
- [x] `app/tests/test_email_parse.py` and `app/tests/test_email_rules.py` added, no hard-coded
      absolute dates (date-sensitive cases computed relative to now)
- [x] No new dependencies; all pre-existing test suites still pass

## Working notes
- Pure/orchestration split mirrors the scanner: `app/utils/email_parse.py` and
  `app/services/email_rules.py` are pure stdlib, no network; `app/services/email_service.py`
  owns network + filesystem.
- `registrable_domain()` moved from `app/services/scan_rules.py` to
  `app/utils/validators.py` so `scan_rules.py` and `email_parse.py` share one implementation.
  If you go looking for it in the scanner module, it isn't there anymore.
- `ENRICH_DEADLINE = 20.0` (in `email_service.py`, via `concurrent.futures.wait(..., timeout=...)`)
  was added beyond the original spec because IP enrichment chains three sequential per-call
  timeouts (vpnapi -> AbuseIPDB -> OTX) that could sum to roughly a minute against hung
  endpoints. A source past the deadline degrades to a null result, same as any other enrichment
  failure.

## Results (2026-07-29)
All six unit-test suites pass (`test_email_parse`, `test_email_rules`, `test_scan_rules`,
`test_url_guard`, `test_iocs`, `test_ipv6_otx`); `create_app()` succeeds; no diff in
`pyproject.toml` / `uv.lock` / `requirements.txt`. Documentation updated in `CLAUDE.md`,
`README.md`.

## Follow-ups (spec §9, explicitly out of scope for Phase 1)
- `POST /api/enrich/email` for SIEM/SOAR pipelines, following the existing `X-API-Key` pattern.
- `.msg` (Outlook OLE) support: `.eml` / RFC 822 source only for now.
- Attachment deep analysis: roadmap Phase 3 (`pefile` static analysis) and Phase 4 (archive
  unpacking, macro extraction, document analysis).
- Retention/purge policy for `data/analyses/`. Shares the unaddressed retention question with
  `data/scans/` and `data/screenshots/`.
- A public-suffix list would improve `registrable_domain()` for both this and the scanner; it's
  a new dependency and remains deferred.

---

# 2026-07-29: Branch close-out

Closed the open items on `feat/scanner-hardening`. Three parallel subagents; every claim below
has command output behind it.

## Done
- [x] **Task 2 re-review gate: popup `nav_state` clobber is real and now fixed.** Confirmed
      against real Chromium: `window.open('about:blank')` + opener-driven `location.href`, and a
      popup self-navigating, both had `is_navigation_request() == True` and
      `parent_frame is None`, and both poisoned `nav_state`. The *initial* `window.open(url)`
      was accidentally safe (Playwright raises on `request.frame` before the frame exists, and
      the gate fails closed). Fix: `request.frame is page.main_frame`, with `page` passed in via
      a `page_ref` holder because the guard is installed before `context.new_page()`.
      Scope: report-integrity, not SSRF; popup requests are still validated by the same guard
      and their responses never enter `transactions`.
- [x] **WebSocket guard regression test**: `app/tests/test_ws_guard.py`, 83 cases.
- [x] **Nav-gate regression test**: `app/tests/test_nav_gate.py`, 8 cases, mutation-checked
      (restoring the old `parent_frame is None` gate makes "popup main frame" fail).
- [x] **Legacy scans still render**: all 5 real records on disk plus synthetic pre-branch
      scaffolds return 200 through the real route. Every new key (`blocked_requests`, `forms`,
      `payload`, `visible_text`, `screenshots`, `iocs`) is already `{% if %}`-guarded, and the
      verdict block uses `.get()` with a default so a legacy `level='informational'` renders.
- [x] **Dropper hash pivot works**: SHA-256 renders, `href="/i/<sha256>"`, and `_run_analysis`
      classifies a bare SHA-256 as a hash (hash check precedes the user-agent fallback).
- [x] Oversized payloads now say *why* there is no hash instead of showing a mute `-`.
- [x] Legacy scans show "scanned before scoring existed" instead of a misleading `score 0.00`.
- [x] `data/analyses/` added to `.gitignore` (it was untracked-but-unignored, so a broad
      `git add` would have committed sender addresses, subjects, and Received-chain IPs).
- [x] README: CyberChef v10.19.4 → v11.3.0, `HOST`/`PORT` → `FLASK_HOST`/`FLASK_PORT`,
      architecture tree updated with the scanner/e-mail modules.

## Verification
All eight pure suites green: `test_ipv6_otx`, `test_url_guard`, `test_scan_rules`, `test_iocs`,
`test_ws_guard` (83), `test_nav_gate` (8), `test_email_parse`, `test_email_rules`.
Live scans after the guard change: `https://example.com` → done/benign, `http://github.com` →
done/benign, final URL `https://github.com/`, `main_ip` 140.82.112.3 (i.e. `nav_state` is still
written by the legitimate main frame; the gate did not over-tighten). Smoke-test screenshots
were cleaned up; no scan records were added or modified.

## Round 2 (same day): backlog knock-out

- [x] **Novel-hash dead-end fixed.** A hash no source has seen now renders a real state in
      `hash_analysis.html` (hash shown + copy button, per-source status distinguishing
      *queried and empty* from *skipped, no API key* from *errored*, plus VT/MalwareBazaar/
      sandbox pivots) instead of the generic `no_results.html`. "Unknown is not clean" is
      stated explicitly, since for a fresh dropper that is the analytically useful reading.
- [x] **`get_scan` normalises `page`** to a dict; a record whose `page` is null/list/string
      rendered a 500 through `scan.page.get(...)`. A non-dict *record* now 404s.
- [x] **`list_scans` no longer silently drops** those records (the reported bug).
- [x] **`visible_text` now rendered**: collapsed, escaped "Page Text" panel. It was 20 KB
      per scan persisted with no consumer.
- [x] **`scripts/purge_data.py`**: retention/purge for `data/scans|screenshots|analyses`.
      Dry-run default, `--yes` to apply, 30-day default, UUID-name allowlist, no symlink
      following, screenshots travel with their scan record, mtime-based (never a `created_at`
      inside a record). Not wired into cron/Docker.
- [x] **`test_endpoints.py` rewritten**: 127 assertions enumerated from `app/routes/`,
      CSRF token scraped and reused, key-independent assertions, cleans up what it creates,
      never POSTs `/url_scan`. The old file asserted nothing and exited 0 regardless.
- [x] **Two real app bugs found by that suite and fixed:**
      `GET /api/domain/analyze` 500'd with `UnboundLocalError` because `indicator` was only
      bound in the POST branch, and `POST /domain_search` redirects there as a GET, so the
      whole Domain/URL search form was broken end-to-end. Now reads `request.values`.
      `GET /favicon.ico` served from `app/static` (nonexistent); the real file is
      `static/favicon_io/favicon.ico`. Now uses `current_app.static_folder`.
- [x] **Tailwind CSS rebuilt.** `bg-red-900/20` (the dropper banner) and other classes used
      by this branch's templates were missing from the committed `static/css/tailwind.css`,
      so they rendered unstyled. Rebuild added 21 classes, pruned 5 genuinely unused ones.
      **Rebuild whenever templates gain utility classes; there is no build step at runtime.**

## Round 3 (2026-07-29): PSL, comment scale-back, audits

- [x] **Public-suffix list.** `registrable_domain()` now uses `publicsuffixlist` (zero required
      deps, bundles its own dated snapshot, verified no network at import; pinned `==` so the
      snapshot date is legible). `requirements.txt` regenerated, the step that silently breaks
      Docker. New `app/tests/test_validators.py` (171 assertions; the module had none).
      Fixed real bugs: every `*.github.io` / `*.azurewebsites.net` tenant used to share one
      registrable domain, and `1.2.3.4` / `9.9.3.4` both returned `'3.4'`, comparing equal.
- [x] **Codebase comment scale-back.** Python 2044 → 1277 comment+docstring lines (−37%);
      template comment blocks 219 → 34 (−84%). Verified by AST equivalence across all 59 project
      files (58 identical; the 1 difference is the deliberate `ssl_valid` fix below) plus a
      token-stream check on the services slice and byte-identical canonical markup on 18 rendered
      pages. Policy recorded in `CLAUDE.md` under "Comment Policy".
- [x] **`/api/enrich/domain` shipped a constant `ssl_valid: True`**; `ssl` is coalesced to `{}`
      one line above, so `ssl is not None` was never False. SIEM/SOAR consumers were reading a
      field that never varied. Now `bool(ssl)`; verified across `None` / `{}` / real-cert shapes.
- [x] **Unknown-hash state unified** across `/i/<hash>`, `POST /analyze`, and
      `POST /api/hash/analyze` (byte-compared HTML), with ThreatFox and OTX pivots added to
      `hash_service.reference_links` so provider URLs stay defined in one place.
- [x] **Reputation-in-scan-path plan written**:
      `docs/superpowers/plans/2026-07-29-reputation-in-scan-path.md`. Ten decisions pending.

### Bugs found by these audits, NOT yet fixed
- **`scripts/setup_mmdb.py` is not idempotent and can corrupt a source file.** It rewrites
  `app/services/ip_service.py` by string replacement and calls `f.write()` unconditionally even
  when the anchor doesn't match; a second run inserts the same block twice. Highest-risk of these.
- **`scan_service.resolve_all`'s except clause** is `except (NoAnswer, NXDOMAIN, Timeout,
  NoNameservers, Exception)`: the trailing bare `Exception` subsumes the rest, so it swallows
  programming errors too. The four named classes are decorative.
- **`inspect_certificate` opens a second TLS connection per scan** purely to test verification,
  and `authorized = bool(cert)` on the line above is dead (unconditionally overwritten).
  Doubles the handshake cost of every scan.
- `home_routes.domain_search()` has an if/else whose two branches are byte-identical.
- `get_event_info` / `get_azure_error_info` import `re` unused; `_enrich_domain` allocates
  `max_workers=3` for 2 futures; `setup_mmdb.py` imports `zipfile`/`gzip` unused.
- `templates/domain_search.html` and `user_agent_search.html` now have empty `<script>` blocks
  (their only content was a placeholder comment).
- **PSL side effect:** `scan_rules._brand_domain_mismatch` does substring matching, so
  `microsoft-login.github.io` now *contains* "microsoft" and no longer trips the brand check.
  The same weakness already existed for `microsoft-login.com`, so it is not a new class, but it
  is a real net loss on that rule. Fix: match the brand token against the registrant label only.

### The bulk IP analyzer is broken (audited, not fixed)
`POST /api/ip/check_ips` fails 100% of the time from the browser:
1. `ip_search.html:163` builds a fresh `FormData` and **never sends the CSRF token**, despite
   `base.html` exposing the meta tag and `azure_error_section.html:111` doing it correctly.
2. The CSRF handler 303s to `/`, `fetch` follows redirects, `response.ok` is `true`, so the JS
   **saves the homepage HTML as `ip_report.csv` and reports "Analysis complete!"**.
3. `ip_service.py:394` returns `None` for the whole row if VPNapi fails, making `VPNAPI_KEY` a
   hard undocumented dependency, contradicting the project's "missing key is skipped" rule.
Also: failed IPs are silently dropped with no error column; a headerless CSV silently eats the
first IP; `.CSV` uppercase is rejected; UTF-16/empty files 500 with leaked pandas internals;
private IPs including `169.254.169.254` are shipped to third parties unguarded.
**Measured 0.508 s/IP, dead flat**: three sources at 2 req/s run sequentially per worker behind
process-global limiters, so the ceiling is 2 IPs/sec and adding workers cannot help. **The
1000-row cap and the 120s gunicorn timeout are mutually inconsistent; the real ceiling is ~235.**
`/api/enrich/batch` by contrast works correctly and is the model to copy (per-row `error`, an
errors count in `meta`, null summaries rather than dropped rows). One bug there: `_detect_type`
passes raw values to `ipaddress.ip_address`, so `123` becomes `"0.0.0.123"`.

## Still open after round 2
- **`POST /api/hash/analyze` still uses the old partial-result path** for an unknown hash;
  only `/i/<hash>` and `POST /analyze` got the new state. Unify when convenient.
- **`no_results.html`'s `error_type == 'hash'` branch is now unreachable** from
  `_run_analysis`, but still reachable via `GET /no_results?error_type=hash`. Left in place.
- **No search pivots for ThreatFox and OTX** on the unknown-hash page: `hash_service.
  reference_links` has no entry for either, and inventing URL shapes in the route would put
  provider URLs in two places.
- **49 of 61 stored screenshots are orphans** with no scan record (~18 MB). They age out
  under the 30-day purge default; worth understanding why they were orphaned.
- **`GET /api/domain/analyze?indicator=...` is slow** (WHOIS + DNS + SSL + crt.sh + OTX,
  serial, no keys configured); a live request exceeded 2 minutes in testing. The scanner
  path is the modern one; this older aggregation path may deserve the same parallel fan-out
  `home_routes._run_parallel` gives IP analysis.
- Three endpoint-suite `SKIP`s that need a provisioned environment: authenticated
  `/api/enrich/*`, the `/api/ip/check_ips` CSV report, and any scanner-bound indicator.

## Open items found during implementation
- The Received-chain IP enrichment renders `vpnapi`/`abuseipdb` response shapes in
  `email_result.html` that were inferred by reading `ip_service.py`'s return values, not
  exercised against live provider data: no API keys are configured in this environment. Verify
  the rendered fields (country, ASN, abuse score) against a real response before relying on them.
- `ENRICH_DEADLINE`'s threads are not cancellable: a future past the 20s deadline keeps its
  underlying thread running in the background after the executor detaches (Python cannot force
  a thread to stop). This matches existing behavior in `home_routes._run_parallel` elsewhere in
  the app, but is worth remembering if `data/analyses/` enrichment ever needs a hard kill.

---

# 2026-07-31: hash reputation without a VirusTotal key

Goal: hash reputation stays useful when VirusTotal is throttled. VT's free tier is 4 requests
per **minute** and there is no keyless VT API, so the answer is not to bypass VT; it is to stop
VT from blocking and to add sources that need no key at all.

Owner approved both new outbound destinations (CIRCL hashlookup, Team Cymru MHR).

## Acceptance criteria
- [x] A rate-limited VT lookup reports `rate_limited` and makes no HTTP request, rather than
      sleeping in the request thread.
- [x] `rate_limited` is a distinct state from `skipped`, which means "no key, never asked".
- [x] `RateLimiter.acquire()` and its context manager keep their blocking behaviour unchanged;
      every other service depends on that politeness with sub-second windows.
- [x] A pasted SHA-256 gets a real reputation answer with no API keys configured at all.
- [x] An MHR hit never on its own marks a file malicious.
- [x] Presence in NSRL never clears a file.
- [x] No weight or threshold in any of the three rule engines changes.
- [x] Both destinations declared in `disclosure.py`; `test_disclosure.py` green.
- [x] Both new cached functions added to the eager list in `cache.py:clear_caches()`.
- [x] New pure test script, house style, no network. Existing 23 suites keep byte-identical
      `PASS:` counts.

## Working notes
The real defect is not the key, it is that `virustotal_limiter.acquire()` loops in `time.sleep`.
At 4 per minute the fifth lookup parks a request thread for up to ~60s, and with `--threads 8`
a handful of lookups can wedge the server. That is what makes VT feel unusable.

Both keyless sources were verified live before any code was written:

| Source | Key | Transport | Accepts | Unknown |
|---|---|---|---|---|
| CIRCL hashlookup | none | HTTPS | md5, sha1, sha256 | HTTP 404 |
| Team Cymru MHR | none | DNS TXT | md5, sha1 only | empty answer |

Two findings from that testing, both load-bearing:

1. **MHR flagged the empty-file MD5 at 91%** (`d41d8cd98f00b204e9800998ecf8427e` returns
   `"1445018789 91"`). It is noisy on ubiquitous artifacts, so it must never feed
   `known_malware_hash`, which `file_rules.py` weights at exactly `MALICIOUS_THRESHOLD` so a
   hit reaches `malicious` alone.
2. **EICAR is in NSRL** and simultaneously flagged `KnownMalicious`, shipped on a Linux distro
   ISO. So NSRL presence is not evidence of anything good.

MHR being md5/sha1 only matters more than it looks: `/hash_analysis` input is usually a
SHA-256, so MHR contributes nothing there. `file_digests()` already computes all three, but
`file_service` passed only the sha256 into `get_hash_info_quick`, so uploads needed the md5
plumbed through.

## Deliberately out of scope
- Scraping the VirusTotal web GUI. It needs an authenticated session, is behind anti-bot, and
  violates their terms.
- Any weight or band change in the rule engines. `file_rules.check_band_derivation()`
  recomputes its interval from `WEIGHTS` at test time, so a new weighted signal re-bands every
  verdict and needs its own case-table work.
- Raising `MAX_ENRICH_HASHES` above 3. The cap's documented justification is that the VT
  limiter blocks, so the reasoning needs revisiting now that it does not, but the cap itself
  stays until that is done deliberately.

---

# 2026-09-22: Capability backlog (sources, Kali tooling, infrastructure)

Consolidated from a research session that probed every candidate live rather than
trusting its documentation. Kept here so rejected options are not re-researched.

Nothing below is started. Ordering rationale is at the bottom.

## A. File and e-mail surface: local analysis, no network, no queue

> **A1, A2 and A3 SHIPPED** in PR #18, merged 2026-09-24. `office_inspect.py`,
> `pdf_inspect.py` and `yara_scan.py`, 20 weighted signals, three result cards, plus
> `scripts/setup_yara_rules.py`. A4 to A9 below are still open.

`file_inspect.py` today does magic sniffing, entropy, strings, embedded PE/ELF, digests
and LNK parsing. It cannot look inside an Office document or a PDF, which are the two
most common malicious-attachment vectors. All packages below are confirmed present in
`kali-rolling` (index pulled 2026-09-22, 71,517 packages).

| Id | Package | Licence | Closes |
|---|---|---|---|
| ~~A1 | `oletools` | **DONE** | BSD | Office macro extraction and deobfuscation. Importable. |
| ~~A2 | `pdfid`, `pdf-parser` | **DONE** | public domain | `/JS`, `/OpenAction`, `/Launch`, `/EmbeddedFile` |
| ~~A3 | `yara` | **DONE** | BSD-3 | Rule hits as weighted signals in `file_rules.py`. Importable. |
| A4 | `libimage-exiftool-perl` | Artistic/GPL | Author, creation tool, GPS, producer software |
| A5 | `readpe` | GPL-2 | PE imports and sections, beyond the magic-byte check |
| A6 | `ssdeep` | GPL-2 | Fuzzy hashing; clusters near-identical samples |
| A7 | `upx-ucl` | GPL-2 | Detects and unpacks UPX, which explains high entropy |
| A8 | `pst-utils` | GPL | Outlook PST/OST. The e-mail surface handles `.eml` only. |
| A9 | `clamav` | GPL-2 | A verdict where nothing leaves the box. Separate decision: 1 GB+ signature DB plus a `freshclam` timer. |

**Licence rule.** GPL tools invoked as a subprocess are mere aggregation and do not
affect the MIT licence of this tree. Importing GPL Python into it creates a derivative
work and is the reason PhoneInfoga, BBOT and theHarvester were rejected as libraries.
`oletools` (BSD) and `yara` (BSD-3) are the only two here that may be imported.

## B. Keyless intel sources

> **B1, B2 and B3 SHIPPED** in PR #19. GreyNoise, RDAP and Wayback, with a
> `could not be checked` state kept distinct from `no archive history`. B4 (RIPEstat)
> and B5 (Pulsedive) are still open.
>
> **J1a and J1i SHIPPED** in PR #23, stacked on #19: Shodan InternetDB (keyless Shodan)
> and StopForumSpam (forum spam plus a Tor exit flag, which nothing else here provides).
>
> **E2 SHIPPED** in PR #22: the FTC Do Not Call store and ingest, which is now the
> worked reference every J2 feed copies.

Every endpoint below was probed with no auth header on 2026-09-22 and returned data.

| Id | Source | Surface | Verified behaviour |
|---|---|---|---|
| ~~B1 | GreyNoise Community | IP | `noise`, `riot`, `classification`, `name`. **HTTP 404 is the "not observed" answer, not an error.** |
| ~~B2 | RDAP via `rdap.org` | domain | Registration date, so domain age stops needing an IP2WHOIS key. 302s to a per-TLD registry, so it interacts with `url_guard`. |
| ~~B3 | Wayback CDX | domain, URL | First-snapshot timestamp. Corroborates B2 from an independent source. |
| B4 | RIPEstat | IP | ASN, routing and abuse contact. Team Cymru does not give the abuse contact. |
| B5 | Pulsedive | IP, domain, URL | Risk, threats, ports, technology. **1 request/second; a second immediate call was rejected.** Its `threats` list is historical, so it needs SkipCalls-style handling: report the link and its date, never a verdict. |

B1 is the highest-value single addition. AbuseIPDB says an address was *reported*;
GreyNoise says whether it is indiscriminate background noise, which removes the false
positive where a Shodan crawler reads as hostile.

## C. Identity surface

- **C1.** `socid-extractor` (MIT) turns "an account exists" into a display name, internal
  user id and creation date. Fetches the target profile, so it needs the SSRF guard and a
  `disclosure.py` party.
- **C2.** user-scanner's `core/cross_scan.py`, `core/confidence.py` and `core/pivots.py`
  are installed and never called. Cross-scan pivoting is the library's advertised
  differentiator, so the dependency is currently being paid for without it.
- **C3.** user-scanner ships `email_scan/adult/` (roughly 17 adult sites) which runs in
  e-mail mode. That is in the scan path and in stored records today. Needs an explicit
  keep-or-exclude decision rather than a default.

## D. Passive recon: blocked on E1

| Id | Tool | Licence | Runtime |
|---|---|---|---|
| D1 | `subfinder` | MIT | seconds; the pick |
| D2 | `amass -passive` | Apache-2.0 | minutes |
| D3 | `theHarvester` | GPL-2, subprocess only | minutes; many sources now need keys |

## E. Infrastructure

### E1. Local persistence: job store and the seen-before index

Two things that share one storage decision, staged so each pays off on its own.

**E1a. Seen-before index. Build this first.** Every indicator ever looked up, with its
verdict and the date. Rendered as a card: "you looked at this IP on 2026-08-14, verdict
suspicious." It is the smallest piece here and the one an analyst feels immediately,
because it is the only question this app currently cannot answer at all. It also makes the
rest of E1 worth building instead of being pure plumbing.

Two properties that are not optional. It is a **local** lookup, so no third party learns
what is being investigated, which is the same argument the phone spec makes for its
offline tier. And it must honour the existing retention posture: a record deleted from a
result page has to leave the index too, or "delete this scan" quietly stops being true.

**E1b. Job store.** `data/jobs/` as a further store through `storage.validate_key()`, a
worker as a systemd unit on the `nexustrace-purge.service` pattern, and a polling result
page with `queued`/`running`/`done`/`failed`. Not Celery or Redis: this app has no database
on purpose. Needed because gunicorn runs `--workers 1 --threads 8`, so a multi-minute job
in-request holds a thread and a timeout kills the entire worker. Gates D, J2 and J6a.

#### Build order, and permission to stop

Each step must be useful standing alone. Stop at any point where the next one stops being
worth it; stopping early is the expected outcome, not a failure.

1. **E1a, the seen-before index.** Visible payoff, smallest piece.
2. **J2 feeds plus J4 allowlist.** The allowlist improves every verdict the app already
   produces, which is the highest-leverage item anywhere in this file.
3. **J6a feed-freshness dashboard.** Now the ingested data can be trusted, rather than
   assumed current. This is the failure that started E2.
4. **Retro-hunt**, only if wanting it comes up in practice. Once feeds and an index both
   exist, "check each new feed entry against a watchlist" is a loop inside the ingest job.
   Delivery (e-mail, webhook) is the fiddly part, not the matching.
5. **A relationship graph**, only if step 1 shows connected things are actually
   accumulating. At this scale it is an edge table and a rendering problem, not a
   distributed system. An empty graph answers nothing, so it has to be earned.

#### What this is, said plainly

This is a scope decision, not a feature. NexusTrace today is stateless triage and this
file's own project notes open with "there is no database". A persistent index, feeds, and
eventually a graph make it a threat-intelligence platform. That is the stated direction,
but it should be chosen deliberately rather than arrived at, and every step above has to
keep the triage path fast or it has made the product worse.

The maintenance is also real: every feed that changes format is ours to fix, with no
community absorbing it.

#### Deliberately not rebuilt

Decided against on grounds of scale, not difficulty. Roughly 80% of a platform's value at
one analyst on one box is reachable with a small fraction of its complexity, because
almost all of that complexity is distribution, multi-tenancy and cross-organisation
interchange.

- **The full STIX 2.1 object model.** Eighteen object types, relationship semantics,
  deduplication and merge rules, confidence propagation. Six object types cover this app.
  `stix2` (BSD) can still emit bundles on *export* for MISP and TAXII interchange without
  the model being adopted internally.
- **Elasticsearch, RabbitMQ, MinIO.** They exist to index millions of objects across
  distributed workers. SQLite and the filesystem are correct at this scale, which is
  already the reasoning recorded in the E2 spec.
- **Multi-user RBAC and data segmentation.** One analyst, and the fine-grained version is
  an Enterprise Edition feature in OpenCTI regardless.
- **Connector parity.** Fifteen ported sources is the right number. Two hundred is not a
  goal.
### E2. FTC Do Not Call ingest

Spec approved at `docs/superpowers/specs/2026-09-22-phone-reports-store-design.md`.
**Implementation plan still owed.** SkipCalls self-reports `last_updated: 2026-08-02` and
missed 33 of 80 sampled numbers carrying 2026 FCC complaints.

It is also the worked reference for every J2 feed: fetch with a browser-like UA, parse,
insert, prune, idempotent via a day ledger, on a systemd timer. Building it first means the
rest of the feeds copy a proven shape rather than inventing one.

## F. Loose ends

> **F1 SHIPPED** in PR #18. The landing page now names phone and e-mail, with a new
> `test_home_routes.py` scoped to the hero blurb (a body-wide assertion passed on the
> pre-fix page, because the nav already links to /phone_analysis and /email_analysis).

- **F1.** `templates/home.html` blurb and search placeholder list only hash and user agent.
  No mention of phone or username, so two shipped features are invisible from the landing
  page. Same class as the missing phone nav entry.
- **F2.** Any new store needs wiring into `scripts/purge_data.py`, which carries its own
  `STORES` tuple *and* hand-written per-store logic. Adding to the tuple alone is not
  enough; that already bit the identity store.
- **F3.** Every new outbound host needs a `disclosure.py` party or `test_disclosure.py`
  fails. Working as designed.

## G. Rejected, with reasons

| Rejected | Reason |
|---|---|
| OSINT-Search (`am0nt31r0`) | **No LICENCE file**, so all rights reserved. Abandoned 2021-06-15. Wraps Pipl (dead), FullContact/TowerData/opencnam (paid), Censys/WhatCMS (keyed), Shodan and `phonenumbers` (already integrated). No unique capability. |
| typo-sniper (`ChiefGyk3D`) | AGPL-3.0. Read for ideas only. |
| PhoneInfoga, BBOT, theHarvester **as imports** | GPL/AGPL into an MIT tree creates a derivative work. Subprocess is fine. |
| nmap, nuclei, nikto, sqlmap, gobuster, ffuf, masscan, wpscan | Active attack traffic. The public role has no browser authentication, so wiring these to a form makes the server an open attack proxy for targets the submitter does not own. Admin role at best. |
| Censys, ZoomEye, Fofa, Onyphe, BinaryEdge, FullHunt, Netlas, Quake, CriminalIP | Keyed, and all overlap Shodan, which is already integrated. |
| Hunter.io, Snov.io | Keyed, thin free tier, and finding a person's address is enumeration rather than indicator lookup. |
| IntelX, SecurityTrails, Defender TI, ThreatBook | Keyed; free tiers too thin to justify a card. |
| grep.app, mnemonic pDNS, bgp.tools, Ahmia | Probed and failed or gated: 429, 503, a required contact-bearing User-Agent, and a 302 into an HTML session respectively. |

## Suggested order

1. ~~**A1 to A3.**~~ Shipped, PR #18.
2. ~~**B1 to B3.**~~ Shipped, PR #19.
3. ~~**F1.**~~ Shipped, PR #18.
4. **E2.** The spec is approved and the plan is owed. **Next.**
5. **E1**, then **D1**.

Also open and needing a decision rather than work: **C3**, the adult-site checkers
user-scanner runs in e-mail mode, which are in the scan path and in stored records now.

## H. OpenCTI and Kasm: pivot targets, not replacements

**Decision.** Everything in sections A through G is built natively into NexusTrace.
OpenCTI is an optional sidecar that NexusTrace can pivot to and from; it never becomes a
dependency and it never absorbs a capability listed above. NexusTrace stays what it is:
stateless, fast triage with no database.

This matters because the temptation runs the other way. OpenCTI has STIX modelling, graph
relationships and persistence, which are exactly the things this app refuses on purpose.
Adopting them here means becoming a worse OpenCTI. Pivoting to the real one instead costs
nothing and keeps both tools doing the single thing each is good at.

**Do not fork OpenCTI.** It is open core: the Community Edition is Apache-2.0 but
Enterprise Edition files carry a separate Filigran commercial licence identified by
per-file headers, so a fork means tracking which files are which forever. It is also
493 MB of TypeScript, React and GraphQL against this Flask tree, and it ships
calendar-versioned releases roughly weekly (`7.260921.0`, 2026-09-21) against 2,156 open
issues, so a fork diverges immediately and never reconverges.

| Id | Integration | Depends on | Note |
|---|---|---|---|
| H1 | NexusTrace to OpenCTI: push findings as STIX observables via `pycti` | **E1** | Queued for human review, never automatic. `submissions.py` is the existing precedent: an outbound submission writes a `pending` record and a human approves it. |
| H2 | OpenCTI to NexusTrace: a "seen before" card queried from the local graph | none | The sleeper. It is a local lookup, so no third party learns what is being investigated, and it gets more valuable as the graph grows. |
| H3 | Kasm pivot: open this indicator in an isolated streamed browser | none | Non-attributable browsing, disposable containers, reachable from any device. Kasm ships an official Kali workspace image, which pairs with sections A and D. |

**Hard rule for all three.** Each must degrade to absent when unconfigured, exactly like a
missing API key makes a provider card never render. No OpenCTI, no Kasm, no `pycti` on the
box means NexusTrace behaves precisely as it does today. That keeps the Cloud Run and
single-container shapes working unchanged.

**Cost, so it is not a surprise.** OpenCTI's compose file brings up elasticsearch, redis,
postgres, minio, rabbitmq, the platform, a worker, `xtm-composer`, `xtm-one` and roughly
ten connectors: sixteen-plus containers. Elasticsearch dominates and 8 GB of RAM for
OpenCTI alone is the realistic floor. With Kasm on the same host, size for 32 GB. That
hardware decision is the real gate here, not the licence.

## I. VirusTotal: quota, persistence, and the pivot-link option

The existing implementation is sound and should not be rewritten. `_QuotaExhausted` is
raised rather than returned so `lru_cache` cannot memoize it, `try_acquire` avoids parking
a gunicorn thread for a whole minute, and `rate_limited` is kept distinct from `skipped`
and `no_record`. The problem is the budget, not the code: 4 requests/minute, 500/day,
15,500/month.

- **I1. Persist the VT cache to disk, keyed by SHA-256.** `timed_lru_cache` is in-memory,
  so every restart and every deploy wipes it and the app pays full price again. A file
  hash is immutable, so the key is perfectly stable. This converts a 500/day ceiling into
  500 *new* hashes per day, which is a different budget entirely. Biggest single win.
- **I2. Give VT its own TTL, measured in days.** The global 30 minutes is tuned for things
  that change; a VT verdict on a fixed hash drifts over weeks. Caveat to encode rather
  than rediscover: `cache.py`'s TTL is per-function, not per-key, so one expiry flushes
  that function's entire cache. A 24-hour TTL trades constant churn for one lumpy daily
  flush, which is an argument for doing I1 properly rather than only raising the number.
- **I3. Model the daily and monthly quotas, not only the per-minute one.** Only the 4/min
  limiter exists today, so crossing the daily ceiling surfaces as the same `rate_limited`
  string. Those are different claims and need different words: "spent for this minute,
  retry in 60 seconds" versus "spent for the day, retry tomorrow". An analyst told the
  former against a spent daily budget refreshes for ten minutes for nothing.
- **I4. Ask VT last.** The fan-out spends a token unconditionally, in parallel with
  MalwareBazaar, CIRCL hashlookup and Cymru MHR, which are generous or unlimited. Once A3
  (YARA) and A9 (ClamAV) can answer locally at zero quota, querying VT only when the cheap
  sources came back empty is a real saving. The cost is latency on the sequential path, so
  it is a tradeoff rather than a free win.
- **I5. Decide the public-role terms question.** VT's Public API is **non-commercial only**
  and its terms state it may not be used in commercial products or services. The public
  role is internet-facing with no browser authentication. This is the same shape as the
  IPQualityScore decision already pre-resolved in the phone spec (admin role only, off by
  default). VT deserves the same explicit decision rather than an implicit one.
- **I6. Keep the pivot link regardless.** `hash_service.py:87` already builds
  `https://www.virustotal.com/gui/search/<hash>`, and `disclosure.py` already has an
  `ON_CLICK` party class for exactly this: a destination that receives nothing unless the
  analyst chooses to follow the link (Talos, PhishTank, Safe Browsing, Hybrid Analysis,
  ANY.RUN, Joe Sandbox are all already modelled this way).

  **This is the escape hatch for every problem above.** A VT pivot link costs no quota, no
  key, and raises no terms question, because the analyst's own browser and their own VT
  session make the request. If I5 resolves against calling the API from the public role,
  demoting VT from an `ALWAYS` party to an `ON_CLICK` party keeps the capability on the
  page and loses only the inline detection count. Keep the link present and prominent in
  every outcome, including `rate_limited`, where it is the most useful thing on the card.

**Do not rotate multiple free API keys.** It is the obvious workaround, it is an explicit
terms violation, and it gets keys banned. VT grants uplifts to academic and research users
on request, which is the legitimate path.

Extending VT to IPs, domains and URLs is possible on the same v3 API but draws from the
*same* quota, so it would worsen the pressure. Defer until I1 and I2 are done.

**Order:** I1, I2, I3, I5, then I4. I6 is independent and should be true at all times.

## J. Native connectors: everything NexusTrace can absorb without OpenCTI

**Framing.** NexusTrace is the primary tool and does as much as it possibly can on its
own. Kasm is the pivot for hands-on forensics when a lookup is not enough. OpenCTI is a
separate thing entirely and may never be needed; nothing below depends on it.

The OpenCTI **connectors** repository is **Apache-2.0**, unlike the core platform, which
is open core. That repo holds roughly 75 enrichment connectors and 200 import connectors,
each a small maintained Python client for one provider. It is usable at two levels:

- **Read it for endpoint knowledge.** Which URL, which parameters, what the response
  contains. Facts are not copyrightable, so this carries no licensing weight at all. Every
  source below was found this way and then probed directly.
- **Port client code.** Apache-2.0 into this MIT tree is fine, but those files keep their
  Apache header and the NOTICE travels with them. Worth it only where the logic is
  genuinely intricate, which for these sources it is not.

### J1. Keyless per-indicator lookups, all probed and returning data on 2026-09-22

These need no key, so unlike Shodan or VirusTotal they are never skipped for an
unconfigured deployment, and they can serve the public role unconditionally.

| Id | Source | Surface | Returns | Note |
|---|---|---|---|---|
| J1a | **Shodan InternetDB** `internetdb.shodan.io/<ip>` | IP | open ports, CPEs, hostnames, tags, CVEs | The standout. Shodan data with no key at all. |
| J1b | **FIRST EPSS** `api.first.org/data/v1/epss` | CVE | exploit probability + percentile | Answers "will this actually be exploited". |
| J1c | **CISA KEV** | CVE | authoritative actively-exploited catalogue | Public domain. Pairs with J1b: KEV is *already* exploited, EPSS is *likely to be*. |
| J1d | **CVE record** `cve.circl.lu/api/cve/<id>` | CVE | full CVE 5.1 record | Same operator as the hashlookup already integrated. |
| J1e | **GreyNoise Community** | IP | noise, riot, classification, actor name | **HTTP 404 is the "not observed" answer, not an error.** |
| J1f | **RDAP** via `rdap.org` | domain | registration date, status, registrar | Makes domain age keyless. 302s to a per-TLD registry, so it touches `url_guard`. |
| J1g | **Wayback CDX** | domain, URL | first-snapshot timestamp | Corroborates J1f independently. |
| J1h | **RIPEstat** | IP | ASN, routing, **abuse contact** | Cymru does not give the abuse contact. |
| J1i | **StopForumSpam** | IP | appears, frequency, lastseen, **torexit** | The Tor exit flag is free signal NexusTrace has nowhere else. |
| J1j | **Google DoH** `dns.google/resolve` | domain | DNS over HTTPS | Independent second opinion when the system resolver is suspect. |
| J1k | **Pulsedive** | IP, domain, URL | risk, threats, ports, technology | **1 request/second**; a second immediate call was rejected. Its `threats` list is historical, so report the link and its date, never a verdict. |

A CVE surface does not exist yet. J1b, J1c and J1d only pay off once one does, or once
J1a starts returning `vulns` for an IP, which is the natural trigger.

### J2. Free bulk feeds: need a local store and a scheduled ingest

All probed and returning data. These are ingests rather than lookups, so they depend on
**E1** and follow the **E2** pattern exactly: fetch on a systemd timer, index locally,
serve from disk, and no third party learns what is being looked up.

| Id | Feed | Size | Gives |
|---|---|---|---|
| J2a | **CISA KEV** | 1.7 MB | Actively exploited CVEs, `catalogVersion` dated |
| J2b | **red-flag-domains** | 818 KB, daily | Newly registered malicious `.fr` domains |
| J2c | **IPsum** | 1.8 MB, daily | Aggregated malicious IP list with hit counts |
| J2d | **TweetFeed** | 11 KB/day | Community IOCs, CSV, dated |
| J2e | **Phishunt** | 38 KB | Live phishing URLs |
| J2f | **VX Vault** | 4.5 KB | Recent malware URLs (HTML `<pre>`, needs parsing) |
| J2g | **MISP warninglists** | 21 MB | **Allowlists**, including Tranco top 1M. See J4. |

`URLhaus`, `ThreatFox`, `MalwareBazaar` and `AlienVault OTX` are also in the catalogue and
are already integrated through their APIs. No action.

#### J2h. TAXII: not now, but keep the door cheap

Considered and deferred. **The free public TAXII landscape has largely collapsed**, probed
2026-09-22:

| Server | Result |
|---|---|
| MITRE ATT&CK, `attack-taxii.mitre.org/api/v21/` | **200, live, keyless** |
| `cti-taxii.mitre.org`, the old MITRE server | Resolves, connection times out. Deprecated. |
| HailATaxii | **No A record**, only MX. The site is gone. |
| Anomali Limo | Discontinued. |

That leaves MITRE ATT&CK as the only live free server, and it serves the *knowledge base*
(techniques, groups, software, mitigations), **not indicators**. ATT&CK is also published
as plain JSON on GitHub, so implementing a TAXII client to reach it would be strictly more
work for the same data.

TAXII genuinely pays for exactly one thing: **ISAC membership** (FS-ISAC, MS-ISAC, H-ISAC)
and CISA AIS. That content is current, valuable, and available no other way. So the
question is not whether TAXII is worth supporting but whether there is a server we are
entitled to poll. Until there is, the J2 feeds above deliver more, fresher, for far less
machinery.

**Requirement that follows, and it is the actionable part.** Build the J2 ingest layer
**source-agnostic**: a fetcher returns records and the indexer does not care whether they
arrived as CSV, JSON, a text list, or a TAXII collection. E2 is already close to this
shape. Do that and adding TAXII later is roughly 150 lines plus `taxii2-client` and
`stix2` (both BSD, both OASIS), so the decision defers at near-zero cost.

**Guard against one trap:** do not adopt STIX as the *internal* model in order to consume
TAXII. That inherits the object model's full complexity, which E1 already rejects on
scale grounds, in exchange for feeds we mostly do not have access to yet. Parse STIX at the
boundary, store observables in the existing shape.

### J3. Free tier but key-gated, lower priority

`crowdsec`, `maltiverse`, `ismalicious`, `hostio` (probed: 400, token required). Each adds
less than any J1 entry and adds key management. Revisit only if a J1 source dies.

### J4. `hygiene`: the allowlist NexusTrace does not have

The `hygiene` connector checks observables against MISP warninglists to suppress false
positives. **There is no allowlist anywhere in this app today**, and several sources are
known-noisy: the NSRL note earlier in this file is the same problem, and SkipCalls flagged
Apple's real support line as spam.

Fed by J2g, this would let a verdict say "this domain is in the Tranco top 1M, so a single
low-confidence hit against it is probably noise". That is a quality improvement across
every surface at once, not a new source.

### J5. `dnstwist` (Apache-2.0, 5.7k stars): typosquatting, done legally

Generates domain permutations and reports which resolve. Permutation generation is fully
offline; only resolution touches the network. On a phishing-triage tool this is a real
feature: submit `paypal.com`, see which lookalikes exist and where they point.

This is the licence-clean answer to typo-sniper, which is AGPL-3.0 and therefore rejected
in section G.

### J6. Dashboards

An admin activity dashboard already exists (`admin_routes.py:_dashboard`, backed by the
append-only log in `app/utils/activity.py`). It answers "who used this app". The gap is a
dashboard that answers "is this app currently telling the truth", which matters more here
because there is no database and every answer comes from a source that can quietly rot.

- **J6a. Feed freshness.** Once J2 lands: every local feed, its last successful ingest, its
  entry count, and a staleness warning past a threshold. This directly addresses the
  failure that started the FTC work, where SkipCalls was seven weeks stale and nothing on
  the page said so.
- **J6b. Source health and quota.** Which providers are configured, which are rate-limited
  right now, and how much daily quota remains. Depends on **I3**, and makes the VirusTotal
  budget visible instead of surfacing only as a `rate_limited` string mid-lookup.
- **J6c. Verdict mix.** Counts by verdict over a window, derived from the existing stores
  rather than new persistence. Cheap, and it makes a miscalibrated rule engine visible: a
  week where nothing was ever `malicious` is a signal about the scoring, not the traffic.

J6a and J6b belong on the **admin role**, beside the existing dashboard. J6c is arguably
public, but it leaks aggregate usage, so default it to admin too.

### Suggested order for this section

1. **J1a, J1e, J1f, J1g** keyless, no infrastructure, land on IP and domain today
2. **J5** dnstwist, self-contained and directly serves phishing triage
3. **E1**, then **J2g + J4**, because the allowlist improves every existing verdict
4. **J2** feeds, then **J6a**
5. **J1b to J1d** when a CVE surface exists
