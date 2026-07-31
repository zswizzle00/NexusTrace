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
