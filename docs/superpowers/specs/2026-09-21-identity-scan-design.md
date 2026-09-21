# Identity scan: username and e-mail OSINT

Date: 2026-09-21
Status: approved, ready for implementation planning

Adds a username and e-mail identity-enumeration surface to NexusTrace, built on two
vendor engines (Sherlock and user-scanner) plus a direct Hudson Rock breach lookup.
Also removes the two public "recent items" listings.

Phone number intelligence is deliberately **out of scope here**. It is being researched
separately and gets its own spec.

---

## 1. Decisions

These were settled during brainstorming and are not open for re-litigation during
implementation.

| Decision | Choice |
|---|---|
| Engines | Both Sherlock and user-scanner, results merged and deduped |
| Execution | Synchronous with a hard time budget, not a background job |
| Scope | Username, e-mail mode, profile metadata, and Hudson Rock breach data |
| Entry point | Dedicated page, plus `/analyze` auto-detection of a bare e-mail address |
| History listings | Removed from `/email_analysis` and `/url_scan`; records still stored |

## 2. Vendor findings that drive the design

Both packages are MIT, so neither conflicts with this project's license. Both install
cleanly on Python 3.12 against the existing pins. Beyond that, the two behave very
differently, and these findings were verified by running the libraries, not by reading
their documentation.

### Sherlock is usable as a library

`sherlock_project.sherlock.sherlock()` has a stable, importable signature:

```
sherlock(username: str,
         site_data: dict[str, dict[str, str]],
         query_notify: QueryNotify,
         dump_response: bool = False,
         proxy: str | None = None,
         timeout: int = 60) -> dict[str, dict[str, str | QueryResult]]
```

`sherlock_project.sites.SitesInformation` loads the site list. `QueryNotify` is a
no-op-able base class, so the CLI's printing behavior is avoidable.

### user-scanner is a CLI wearing a library's clothes

Three hazards, all confirmed by reading the installed package:

1. **`core.hudson.run_hudson_scan()` prints to stdout and returns `None`.** It is a
   display function with no structured return value, so the breach data cannot be
   retrieved through it. The endpoint it calls is public and visible in its source:
   `https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-{email,username}`.
2. **Three blocking `input()` calls** exist, in `core/hudson.py`, `core/loud_prompt.py`,
   and `utils/updater_logic.py`. In a gunicorn worker thread these raise `EOFError` or
   block indefinitely.
3. **`utils/update.py:update_self()` shells out to `pip uninstall` then `pip install`.**
   Inside a container that mutates the running image's site-packages.

The mitigating fact: every `input()` call and the updater are reached **only from
`user_scanner/__main__.py`**, the CLI entry point. The orchestrators are plain
synchronous functions returning `list[Result]`:

```
core.orchestrator.run_user_full(username, configs: ScanConfig) -> list[Result]
core.email_orchestrator.run_email_full_batch(email, configs: ScanConfig) -> list[Result]
```

With the default `ScanConfig(allow_loud=False)`, `orchestrator.py:60` and
`email_orchestrator.py:90` skip loud sites rather than prompting. `ScanConfig` is a
frozen dataclass: `allow_loud`, `no_nsfw`, `show_all`, `verbose`, `timeout`.

**Rule for implementers: never import or invoke `user_scanner.__main__`, and never call
anything in `user_scanner.utils`.** Use only `core.orchestrator` and
`core.email_orchestrator`.

`Result` carries `username`, `category`, `site_name`, `status`, `url`, `extra`, `media`,
`reason`, `is_email`.

## 3. Architecture

### 3.1 Engines run in a subprocess

`app/tools/identity_worker.py` is a module entry point (`python -m
app.tools.identity_worker`) that runs both engines and writes a single JSON document to
stdout. `identity_service.py` spawns it with `stdin=DEVNULL` and a hard deadline, and
kills it when the deadline passes.

This is the load-bearing decision. It exists for three reasons:

- **The deadline becomes enforceable.** `sherlock()` blocks on an internal futures pool
  and cannot be interrupted. In-process, an overrunning scan leaves hundreds of sockets
  and a live thread pool inside the single gunicorn worker with no way to reclaim them.
  A subprocess can be killed.
- **`input()` becomes harmless.** With stdin closed, a prompt raises `EOFError` in the
  child instead of hanging the server.
- **Vendor stdout stays out of the application log.** `core/orchestrator.py` contains
  five `print`/console calls per run.

The worker must exit non-zero and emit a JSON error document on failure rather than a
traceback on stdout, so the parent never has to distinguish a crash from a partial
result by parsing stderr.

**Worker contract.** The worker takes the target and the mode (`username` or `email`) as
arguments and emits one JSON object on stdout:

```json
{
  "target": "...",
  "mode": "username|email",
  "engines": {
    "sherlock":     {"status": "ok|timed_out|error|not_applicable", "findings": [...]},
    "user-scanner": {"status": "ok|timed_out|error", "findings": [...]}
  }
}
```

Sherlock is username-only, so in e-mail mode it reports `not_applicable` rather than an
error. The worker emits raw per-engine findings; **normalization and merging happen in
the parent**, in `identity_findings.py`, so that logic stays pure and unit-testable
without spawning anything.

**Hudson Rock does not run in the worker.** It runs in the parent, in
`identity_service.py`, via `hudson.py`. It is a single fast request against one endpoint
under our own rate limiter, it has nothing to do with the vendor engines, and keeping it
in the parent means a killed worker still yields breach data. It is subject to the
overall budget but does not consume the engines' share of it.

### 3.2 Modules

| File | Purpose | Pure? |
|---|---|---|
| `app/tools/identity_worker.py` | Subprocess entry point; runs both engines, emits JSON | no |
| `app/services/identity_service.py` | Spawns worker, enforces deadline and concurrency cap, builds the record | no |
| `app/services/hudson.py` | Direct Hudson Rock client with its own `RateLimiter` | no |
| `app/utils/identity_findings.py` | Normalize and merge the two engines' results | **yes** |
| `app/routes/identity_routes.py` | Blueprint: form, submit, result, delete | no |
| `templates/identity_scan.html` | Submission form | n/a |
| `templates/identity_result.html` | Result page | n/a |

`identity_findings.py` is pure on purpose. It is hand-written matching logic, which
`tasks/lessons.md` (2026-07-28, "Hand-authored matching logic is where my own defects
cluster") identifies as the highest-defect-density category in this codebase. It must be
testable with no network, no subprocess, and no Flask.

`hudson.py` follows the shape of `app/services/abusech.py`: module-level `RateLimiter`,
its own timeout constants, and a mapping function separated from the request.

### 3.3 Normalized finding

Both engines normalize to one shape before merging:

```python
{
  'site':      str,          # normalized display name
  'category':  str | None,   # user-scanner supplies this; Sherlock does not
  'url':       str | None,
  'status':    str,          # 'found' | 'not_found' | 'unknown' | 'rate_limited' | 'error'
  'engines':   list[str],    # ['sherlock'], ['user-scanner'], or both
  'metadata':  dict,         # bio, avatar, follower counts, from user-scanner's `extra`/`media`
  'reason':    str | None,   # why a status was assigned; carries merge conflicts
}
```

### 3.4 Merge and dedupe

Dedupe key: normalized site name plus the URL's registrable domain. Reuse
`app/utils/validators.py:registrable_domain()` rather than writing a second host
comparison; that function already backs the scanner's redirect logic and `.eml` spoofing
detection, and a second implementation would drift.

Rules:

- Two engines reporting the same site merge into one row with `engines` listing both.
  **Corroboration is surfaced, never collapsed.** Two independent engines agreeing that a
  handle exists is a stronger claim than either alone, and the result page marks those
  rows.
- Status conflicts resolve toward the stronger status, ordered
  `found > rate_limited > unknown > not_found > error`, and the losing claim is recorded
  in `reason` so a disagreement is visible rather than silently discarded.
- A row that only one engine checked is not evidence the other engine disagreed. The
  page must distinguish "the other engine said no" from "the other engine does not cover
  this site."

### 3.5 Time budget and concurrency

- **Total wall-clock budget: 70 seconds.** This sits under the ~100s Cloudflare 524
  ceiling and the 120s gunicorn `--timeout` (see `Dockerfile:83`), leaving room to build
  and render the page. With `--worker-class gthread`, a gunicorn timeout kills the whole
  worker and every other in-flight request with it, so this margin is not cosmetic.
- **Per-request timeout inside each engine: ~8 seconds**, so one dead site cannot consume
  the budget. Sherlock takes `timeout=`; user-scanner takes `ScanConfig(timeout=)`.
- Engines run concurrently inside the worker and are harvested independently. One engine
  finishing while the other times out produces a page with partial results that says so,
  per engine. Partial results are a normal labeled outcome, not an error.
- **App-wide semaphore: 2 concurrent identity scans**, plus a `RateLimiter` on scan
  starts. Without this, a handful of browser tabs saturates all 8 gunicorn threads and
  fires roughly 10,000 outbound requests.
- A request that cannot acquire the semaphore gets a flash message and a redirect back to
  the form, not a queue and not a 500.

### 3.6 Hudson Rock

`app/services/hudson.py` calls the public endpoint directly with `requests`, because the
vendor function only prints. Direct implementation is strictly better here for a reason
beyond convenience: the hostname becomes a string literal inside `app/services/`, which
is exactly what `app/tests/test_disclosure.py` walks. The breach lookup therefore
**cannot** ship undisclosed. Wrapping the vendor would hide it from that test.

Endpoints:

```
GET https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=...
GET https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username=...
```

Response carries a `stealers` array with `stealer_family`, `date_compromised`,
`operating_system`, `computer_name`, `antiviruses`, `top_logins`. A 404 means no data,
not an error, and must not surface as a failure.

## 4. Surface

### 4.1 Routes

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/identity_scan` | Form, with separate username and e-mail fields |
| `POST` | `/identity_scan` | Run the scan, store the record, redirect to the result |
| `GET` | `/identity_scan/<scan_id>` | Result page |
| `GET,POST` | `/identity_scan/<scan_id>/delete` | Confirm and delete, mirroring the e-mail flow |

**There is no listing route.** This is a requirement, not an omission, and
`test_identity_routes.py` asserts it.

`identity_bp` registers without a `url_prefix`, like `scan_bp` and `email_bp`, and
encodes full paths in its decorators.

### 4.2 `/analyze` integration

`app/routes/home_routes.py` gains bare e-mail address detection, routing to identity
e-mail mode. Usernames stay explicit: a username is any string, so auto-detecting one
would turn every mistyped domain into a 1,300-vector scan.

The `.eml` result page gains a pivot link to scan the sender's address, matching the
existing attachment-to-hash-reputation pivot.

### 4.3 No threat verdict

The result page presents an **exposure summary**, not a malicious/benign verdict:
accounts found, how many corroborated by both engines, and whether breach data exists.

"This person has a Reddit account" is not a threat signal. `app/services/scan_rules.py`
is careful in its docstring to present a structural prior rather than a reputation
verdict, and this surface has even less basis for a verdict claim. Do not add a scoring
engine here to match the other surfaces' shape.

## 5. Storage and governance

- New `identity` store added to `app/utils/storage.py:STORES`, at
  `data/identity/<uuid>.json`. `app/tests/test_storage.py:74` iterates `STORES`, so the
  path-traversal battery covers the new store automatically.
- **`scripts/purge_data.py:59` keeps a second, hand-maintained `STORES` tuple.** It must
  gain `'identity'` too. This duplication is a live trap: a store added to one and not
  the other is retained forever with no error anywhere.
- Add `data/identity/` to `.gitignore` beside the other runtime record directories, with
  a comment noting it holds account enumeration and breach findings about named people.
- 30-day retention applies, and the result page carries a delete button.

### 5.1 Disclosure

`app/utils/disclosure.py` gains an `identity` surface with:

- A `target_platforms` party in the style of the existing `target_site`: no hostnames,
  describing that the identifier is sent to the platforms being tested.
- `hudson_rock`, with hostname `cavalier.hudsonrock.com`, sending "usernames and e-mail
  addresses."

**Known limit, to be stated in the notice rather than papered over:** the ~1,300 platform
hostnames live inside the vendor packages, not as string literals in `app/services/`, so
`test_disclosure.py` structurally cannot enumerate or police them. The notice says so in
prose. An implementer must not claim that test covers this surface.

This is the most privacy-sensitive surface in the application. The use notice states
plainly that the identifier is sent to over a thousand third-party platforms and to
Hudson Rock, and that findings about a named person are retained for 30 days and can be
deleted from the page.

## 6. Tests

All offline, all standalone scripts in the existing `app/tests/` style: a `main()`,
printed `PASS`/`FAIL` lines, non-zero exit on failure. No pytest.

| File | Covers |
|---|---|
| `test_identity_findings.py` | Normalization, dedupe, corroboration, status-conflict resolution, "not covered" vs "not found", against fixture results from both engines |
| `test_identity_budget.py` | Deadline enforcement against a fake slow worker |
| `test_hudson.py` | Response mapping through an injected client, 404-is-not-an-error, mirroring `test_hash_reputation.py` |
| `test_identity_routes.py` | CSRF enforcement, 404 on a malformed id, delete, and the absence of any listing route |

`test_identity_budget.py` must assert the **outcome**: the child process is gone, a
partial result came back, and the unfinished engine is marked timed out. Asserting that
a deadline variable was set is the failure mode `tasks/lessons.md` records twice
(2026-07-28, "Verification that checks the wrong signal"). The fake worker is a script
that sleeps; no real engine and no network.

## 7. Dependencies

Add to `pyproject.toml`, pinned exactly, with comments in the established house style
explaining why the pin is exact:

```
sherlock-project==0.16.2
user-scanner==1.5.2
```

The pins are exact because **the site lists are the product**. A drifting version
silently changes coverage, which changes results without changing any code in this repo.

Then, and this is not optional:

```
uv lock && uv export --no-dev --no-hashes -o requirements.txt
```

Docker installs from `requirements.txt` with pip, not from `pyproject.toml`.

New transitive dependencies: `requests-futures`, `stem`, `PySocks`, `colorama` from
Sherlock; `httpx[http2]`, `curl_cffi`, `rich`, `socksio` from user-scanner. `curl_cffi`
is compiled, so the Docker build must be verified rather than assumed, and the image will
grow.

## 8. Separate change: remove the history listings

Bounded, independent of everything above, and safe to land first.

| File | Change |
|---|---|
| `app/routes/email_routes.py:32` | Drop `recent=list_analyses(10)`; drop the import on line 8 |
| `templates/email_analysis.html:68` | Remove the Recent Analyses block |
| `app/routes/scan_routes.py:41` | Drop `recent = list_scans(10)`; drop the import on line 5 |
| `templates/url_scan.html:51` | Remove the Recent Scans thumbnail grid |
| `app/services/email_service.py:307` | Delete `list_analyses()`, now dead |
| `app/services/scan_service.py:61` | Delete `list_scans()`, now dead |
| `app/services/scan_service.py:91,1035` | Reword two comments that reference `list_scans` |

Those two routes are the only callers, so both functions become dead on removal and are
deleted, the same way `get_ip_info()` was.

Records, direct links, delete buttons, and 30-day retention are untouched. A visitor can
no longer browse what other people submitted; an analyst who kept their own link still
has it.

## 9. Open items

- The Docker build with `curl_cffi` on the slim base image is unverified. Confirm during
  implementation before claiming the image builds.
- Whether `user_scanner.core.helpers.load_config()` writes its config file when absent is
  unconfirmed. `CONFIG_PATH` resolves inside site-packages, which may be read-only in the
  container. `USER_SCANNER_CONFIG` overrides the path and is the mitigation if needed.
- Phone number intelligence is under research and is not part of this spec.
