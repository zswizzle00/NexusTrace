# UI fixes + backend cleanup (2026-06-16)

Goal: fix "buggy" UI and "weird loading times"; deep-dive code cleanup.
Scope chosen with user: **Fixes + visual polish** (keep dark/blue identity) and
**pre-built static Tailwind CSS** (no everyday build step).

## Root cause of slow/weird loading
- `cdn.tailwindcss.com` is a **runtime in-browser compiler** (dev-only) → FOUC + delay.
- jsPDF + jspdf-autotable + html2canvas (~450 KB) loaded **render-blocking on every page**,
  but their only consumer was `static/js/main.js` - which **no template ever loaded** (dead).
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
- NOT run: live server / Selenium screenshots - Flask deps aren't installed in this env.
  User should boot the app and hard-refresh (clear old SW) to confirm visuals - see summary.

## Deferred (recommended follow-ups, need test coverage to do safely)
- Full removal of the ~380-line inline `<style>` in base.html that duplicates `styles.css`
  (risky to do blind without visual verification; inline block currently wins the cascade).
- Dedupe `is_valid_ip`/`is_valid_domain`/`is_valid_url` into `app/utils/validators.py`
  (implementations differ between files - unifying changes behavior; needs tests first).
- Shared `app/utils/constants.py` for the duplicated TIMEOUT_* constants.
- `test_endpoints.py` paths are also stale (`/health` vs `/api/health`, etc.) - only the port was fixed.
- PDF export was dead code: if it's a wanted feature, re-add it lazy-loaded on result pages only.

---

# 2026-07-28 — Scanner hardening + Detonator ports

Branch `feat/scanner-hardening`. Full context: `docs/superpowers/2026-07-28-session-record.md`.
Plan: `docs/superpowers/plans/2026-07-28-scanner-hardening-and-detonator-ports.md`.

## Acceptance criteria
- [x] A redirect to a private/link-local address is not fetched by the scanner
- [x] Subresources cannot surface internal-host status/IP in the rendered report
- [x] Legitimate `http://` -> `https://` redirects still scan correctly, at the right origin
- [x] No new dependencies; existing tests still pass
- [ ] Scanner renders a real verdict instead of a hardcoded `informational`
- [ ] Dropper URLs yield a payload hash that pivots into hash reputation
- [ ] Scans persisted before this work still render

## Progress
- [x] Task 1 — `app/utils/url_guard.py` SSRF guard, 64 test cases (review clean)
- [x] Task 2 — guard installed on every Chromium request (10 findings fixed)
- [ ] Task 2 — re-review gate NOT yet run. Open: can a `window.open` popup clobber
      `nav_state`? A popup's main frame also has `parent_frame is None` — same class
      as the iframe Critical that was found and fixed.
- [ ] Tasks 3-5 — forms/password capture, dropper payload capture, staged screenshots
- [ ] Tasks 6-7 — rule engine + wiring (highest remaining risk; see tasks/lessons.md)
- [ ] Tasks 8-9 — IOC extract/defang + wiring
- [ ] Tasks 10-11 — verdict UI, payload hash pivot, IOC panel, filmstrip
- [ ] Task 12 — docs + full verification sweep

## Working notes
- `data/scans/*.json` is re-read from disk: every new key needs `.get()` in Python
  and a `{% if %}` guard in templates, or old scans 500.
- Rule-engine bands are 0.70/0.35, NOT Detonator's 0.80 — no reputation source in the
  scan path. Must be labelled a structural heuristic in the UI.
- Docker installs from `requirements.txt` via pip, not uv. After `uv add`, run
  `uv export --no-dev --no-hashes -o requirements.txt` or Docker misses the dep.

## Results (as of 2026-07-28)
SSRF hole closed and verified: redirects to `169.254.169.254` / `127.0.0.1` blocked in
0.6s before a browser opens; `http://github.com` still completes (301->200, all links
`https`, `main_ip` 140.82.112.4 / AS36459); `https://example.com` 200 in 2.8s.
45 behavioural checks on the guard module all pass.

## Next session
1. Run Task 2's re-review gate (the popup question above).
2. Continue Tasks 3-12.
3. Then Derez Phase 1: e-mail (`.eml`) analysis — see the merge roadmap.
