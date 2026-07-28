# Lessons

Failure mode → detection signal → prevention rule. Newest first.
Reviewed at session start and before major refactors.

---

## 2026-07-28 — A plan can specify a security fix that silently does nothing

**Failure mode.** The scanner-hardening plan specified installing the SSRF guard via
Playwright's `context.route('**/*', handler)` with `validate_target` then
`route.continue_()`. Playwright invokes a route handler **once per request object**:
when a routed response is itself a redirect, Chromium follows it internally and the
redirect target never re-enters the handler. The guard would have been installed,
tested green, and blocked nothing on the exact vector it existed to close.

**Detection signal.** The implementer's live verification found `blocked_requests`
empty on a URL that redirected to `169.254.169.254`. The unit tests passed — they
exercised the guard function, not the guard's *installation*.

**Prevention rule.** For a security control, the acceptance test must exercise the
control **through the real integration path**, not the pure function underneath it.
"Validated the URL" and "the browser could not reach the URL" are different claims;
assert the second. When a plan specifies a framework callback as a security
chokepoint, verify from the framework's own docs/issues that the callback actually
fires on every path being defended — before writing the plan step.

---

## 2026-07-28 — Verification that checks the wrong signal reports a false failure

**Failure mode.** I twice declared an implementer's fix missing when it was correct.
(1) I checked `normalize().host` for a stripped trailing dot; the implementation
correctly stripped it at *comparison* time inside the denylist and deliberately kept
the dot in `.host` for URL round-trip fidelity — a better design than I specified.
(2) I demanded the authority screen reject `\t`/`\r`/`\n`; Python's `urlsplit`
removes exactly those three bytes before any code can see them, matching what
WHATWG/Chromium strips, so there was no parser differential and nothing to screen.

**Detection signal.** Both times the *security outcome* was already correct
(`is_scannable` returned `False`) while my chosen intermediate signal looked wrong.
The second was caught only by reading the stdlib's behaviour rather than assuming it.

**Prevention rule.** Assert on the security-relevant outcome, not an intermediate
representation. When an implementation diverges from a spec, first ask whether the
divergence achieves the requirement by a different mechanism — and check the
platform's real behaviour before asserting a gap. Record adjudications with evidence
so a correct implementation is never filed as an implementer miss.

---

## 2026-07-28 — Hand-authored matching logic is where my own defects cluster

**Failure mode.** Every defect in the SSRF guard module traced to the design I wrote,
not the transcription: missing IPv4-mapped-IPv6 unwrapping, `is_global` wrongly
assumed to cover multicast / `fec0::/10` / NAT64 `64:ff9b::/96`, `UnicodeError`
escaping an `except OSError`, a `host:port` regression, and a parser-differential
bypass via `http://127.0.0.1\@example.com/`. The implementer matched the brief
byte-for-byte; the brief was wrong.

**Detection signal.** Spec compliance passed while task quality failed with two
Criticals. Reviewer findings clustered in one file — mine.

**Prevention rule.** When a plan contains hand-written parsing, matching, or scoring
logic with a security-adjacent purpose, keep the reviewer on the most capable model
and instruct it to verify library semantics by running them rather than reasoning
from memory. Do not scale reviewers down for these tasks just because the diff is
small. Applies to the pending rule engine and IOC regexes for the same reason.

---

## 2026-07-28 — Agent scratch directories swallow the audit trail

**Failure mode.** I gitignored `.superpowers/` as scratch. All security review
findings, adjudications, and verification evidence for the day lived there and would
have been destroyed by `git clean -fdx`, leaving only commit messages.

**Detection signal.** A direct question — "is everything tracked and documented?" —
that I could not answer yes to.

**Prevention rule.** Separate regenerable scratch (briefs, diffs) from findings that
are the record (reviews, decisions, deferred items). Keep scratch ignored; commit the
findings. Write the durable record as the work happens, not at the end.
