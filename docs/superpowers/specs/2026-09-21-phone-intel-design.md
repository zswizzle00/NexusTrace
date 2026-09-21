# Phone number intelligence

Date: 2026-09-21
Status: approved, ready for implementation planning

Adds phone number lookup to NexusTrace using free, keyless sources only. Separate from
and independent of the identity scan work in
`2026-09-21-identity-scan-design.md`.

**Framing, which drives every decision below: this is number metadata and allocation
intelligence, not "phone OSINT".** Everything reliable and permanent in this space is
derived from published numbering plans. Every capability promising owner identity, live
carrier, or handset location turned out to be paid, dead, or scraping a service that now
blocks it. The feature should be accurate about what it knows rather than impressive
about what it implies.

---

## 1. Decisions

| Decision | Choice |
|---|---|
| First cut sources | Keyless only: libphonenumber, LocalCallingGuide, SkipCalls |
| Keyed providers | None in the first cut |
| IPQualityScore, if ever added | Admin role only, off by default. Pre-decided, see §7 |
| Verdict | None. Metadata and reported-signal display only |
| Persistence | None. Rendered inline, no stored record |

## 2. Verified findings

Everything here was confirmed by running the library and hitting the endpoints on
2026-09-21, not taken from documentation.

### 2.1 Offline data is nearly useless for NANP numbers

```
+12127363100   US  valid=True  type=FIXED_LINE_OR_MOBILE  carrier=''          geo='New York, NY'
+14155552671   US  valid=True  type=FIXED_LINE_OR_MOBILE  carrier=''          geo='San Francisco, CA'
+18002752273   US  valid=True  type=TOLL_FREE             carrier=''          geo=''
+33612345678   FR  valid=True  type=MOBILE                carrier='SFR'       geo='France'
+4915112345678 DE  valid=True  type=MOBILE                carrier='T-Mobile'  geo='Germany'
```

libphonenumber ships **no NANP carrier data at all**, and every US or Canadian number
resolves to `FIXED_LINE_OR_MOBILE`. Toll-free and premium rate are detected; mobile
versus landline versus VoIP is not. Non-NANP regions return a real type and a real
carrier.

This single fact is why LocalCallingGuide is in the first cut rather than being optional:
without it, a US lookup returns validity and a city and nothing more.

### 2.2 The carrier field is a portability trap

`carrier.name_for_number()` returns the **original range holder**, not the current
carrier. libphonenumber ships a second function, `safe_display_name()`, which
deliberately returns an empty string for any region with mobile number portability.
Confirmed: FR and DE both returned `''` from `safe_display_name()` while
`name_for_number()` returned `SFR` and `T-Mobile`.

**Requirement: this field renders as "original range holder (pre-portability)", never as
"carrier".** Presenting it as the current carrier is how OSINT tools produce confidently
wrong intel. Use `name_for_number()` with the caveat visible in the UI, not
`safe_display_name()`, which is empty across most of the developed world.

### 2.3 Reserved and fiction ranges are invisible offline

`+447911123456`, an Ofcom drama range reserved for television, resolves to region `GG`,
Guernsey, carrier `JT`. The offline dataset has no concept of a number reserved for
fiction. Known limit for the first cut; the Ofcom dataset in §7 would fix it.

### 2.4 LocalCallingGuide closes the NANP gap

Verified live. `GET https://localcallingguide.com/xmlprefix.php?npa=212&nxx=736` returns
a `<prefixdata>` record with `ocn`, `company-name`, `company-type`, `ilec-ocn`,
`ilec-name`, `rc` (rate center), `region`, `lata`, `switch`, `switchname`, `switchtype`,
`rc-lat`, `rc-lon`, `effdate`, `discdate`, `udate`. An unassigned prefix (212-555)
returns zero `<prefixdata>` elements rather than an error.

`company-type` is the valuable field: `I` = ILEC, `C` = CLEC, `W` = wireless. That is the
mobile/landline/VoIP discrimination libphonenumber cannot provide for NANP.

The response is XML preceded by a large HTML-entity DTD, so the parser must handle that
rather than assuming a compact document.

### 2.5 SkipCalls is a reported-signal database, not a verdict

Verified live. `GET https://spam.skipcalls.com/stats` returned `total_numbers: 3172472`
and `last_updated: 2026-08-02`, roughly seven weeks stale.

Research measured a false positive on Apple's real support line (`+18002752273` returned
`is_spam: true`, status "unknown") and on fictional 555 numbers.

**Requirement: `is_spam` means "this number appears in a crowd-report database". It is
rendered as the reported category and count, never as a verdict and never as a score.**
The service looks single-operator with no SLA or status page, so any failure is a silent
skip.

## 3. Licensing

| Component | License | Status |
|---|---|---|
| `phonenumbers` | Apache-2.0 | Safe to import |
| LocalCallingGuide data | no formal terms | See note |
| SkipCalls | no formal terms | Best-effort |

**Rejected on license grounds.** PhoneInfoga is **GPL-3.0**, confirmed from its LICENSE
file, and so are Phunter, X-osint, OwlTrack, osint-X, and Inspector. None may be imported
into this MIT application. Shipping a GPL binary inside the Docker image is distribution
of that binary and carries source-offer obligations even if the Flask code stays MIT.

This costs nothing: PhoneInfoga's unique free capability, after removing its
libphonenumber wrapper and its key-requiring scanners, is one OVH endpoint and a Google
dork URL string builder. It is also self-declared unmaintained by its own maintainer.

**LocalCallingGuide terms are genuinely unclear and the two research passes disagreed.**
One found site documentation recommending automated lookups and caching. The other found
a disclaimer stating the site is non-commercial and that commercial use is at the user's
own risk. There is no formal terms page. Both readings are probably accurate. The
practical posture: cache aggressively, rate-limit conservatively, set a descriptive
User-Agent, and fail soft. Revisit if NexusTrace is ever offered commercially.

## 4. Architecture

| File | Purpose | Pure? |
|---|---|---|
| `app/utils/phone_parse.py` | libphonenumber wrapper: parse, validate, classify, format | **yes** |
| `app/services/phone_service.py` | LocalCallingGuide and SkipCalls clients, own rate limiters | no |
| `app/routes/phone_routes.py` | Blueprint: form and result | no |
| `templates/phone_analysis.html` | Result page | n/a |

`phone_parse.py` holds no network calls, so it joins the existing pure-leaf set
(`validators`, `url_guard`, `email_parse`, `file_inspect`, `lnk_parse`, `iocs`,
`hash_reputation`) and is unit-testable with no server. It owns normalization to E.164,
the number-type mapping, and the reserved-range flagging in §2.3.

`phone_service.py` follows `abusech.py`'s shape: module-level `RateLimiter` per provider,
explicit timeout constants, and response mapping separated from the request so the
mapping can be tested against fixtures.

### 4.1 Caching and rate limits

Prefix allocation data changes rarely, so LocalCallingGuide results cache with a long TTL
via `app/utils/cache.py:timed_lru_cache`. **Note the documented quirk: the TTL is
per-function, not per-key, and one expiry flushes that function's entire cache.** That is
acceptable here and should not be mistaken for a bug during implementation.

Rate limits, both conservative because neither service publishes one:

- LocalCallingGuide: 2 requests/second.
- SkipCalls: 1 request/second.

### 4.2 No stored record

A phone lookup is fast and cheap, so it renders inline like the IP and domain surfaces
rather than writing a record. No new store, no `STORES` entry, no delete flow, no
retention concern, and nothing added to `scripts/purge_data.py`.

This also means the history question that motivated removing the other listings never
arises here.

## 5. Surface

- A dedicated form, plus **`/analyze` auto-detection of E.164 numbers** (a leading `+`
  followed by 7 to 15 digits). E.164 is unambiguous. A bare `2127363100` is not, and must
  not be auto-detected: it collides with other numeric indicators.
- The dedicated form accepts an optional default region so an analyst can look up a
  national-format number without hand-building E.164.
- **No verdict banner.** The page shows what is known and labels what is not:
  - Validity, possible-vs-valid, number type, region, timezone, formatted variants.
  - Original range holder, explicitly labeled pre-portability.
  - For NANP: OCN, company name, ILEC/CLEC/wireless classification, rate center, LATA.
  - Reported-spam signal as category and count, with its source and data date shown.
- Where a field is unavailable rather than empty, say which. "libphonenumber ships no
  carrier data for NANP" is useful; a blank box is not.

## 6. Disclosure

`app/utils/disclosure.py` gains a `phone` surface:

- `localcallingguide`, host `localcallingguide.com`, sends "the area code and prefix of
  the number, not the full number".
- `skipcalls`, host `spam.skipcalls.com`, sends "the full phone number".

Both hostnames are string literals in `app/services/phone_service.py`, so
`test_disclosure.py` polices them automatically.

The notice should state something the other surfaces cannot: **the offline tier sends
nothing anywhere.** Validity, type, region, timezone, and range holder are computed
locally, which matters for an OSINT tool, because a live lookup tells the provider who
you are investigating.

## 7. Deferred

Recorded so the reasoning is not re-derived later.

- **Ofcom allocation dataset.** `codelist.zip`, 3.08 MB, refreshed weekly, free to
  redistribute **with attribution** ("Contains Ofcom copyright material"). Gives UK block
  holder, block status, allocation date, and the drama/reserved ranges that would fix
  §2.3. Blocker: Ofcom's CDN sits behind Cloudflare bot protection and returns 403 to
  plain `requests`. Either reuse the already-pinned `playwright==1.61.0` for a weekly
  refresher, or vendor a dated snapshot the way `publicsuffixlist` is already pinned.
- **IPQualityScore.** The only free source of fraud score, do-not-call status, active-line
  status, owner name, and a breach-exposure flag, at 1,000 credits/month shared across all
  their endpoints. **Pre-decided: admin role only, off by default**, because their terms
  forbid republishing API responses to third parties and the public role is
  internet-facing with no authentication on browser routes.
- **FTC Do Not Call complaint data.** Daily CSVs, US public domain, no restrictions of any
  kind. Ingested locally it gives unlimited reported-call history with better provenance
  than SkipCalls and would obsolete it. Needs a scheduled ingest and a local index.
- **Veriphone.** 1,000/month, no card. Adds independent validation and region. Low
  marginal value over the offline tier; revisit only if the offline tier proves
  insufficient.

Rejected outright, with reasons, so they are not re-researched: NumVerify (free tier is
HTTP-only, and its terms forbid storing the data), Vonage Number Insight (sunset
2027-02-04), Telnyx and 1lookup and Byteplant (no recurring free tier), free HLR services
(the category does not exist; every offer is format validation with an upsell), Hudson
Rock (no phone search key on any tier), WhatsApp and Telegram registration probes
(platform ToS violation and exposes a real bound account).

## 8. Tests

Offline, standalone-script style, consistent with `app/tests/`.

| File | Covers |
|---|---|
| `test_phone_parse.py` | E.164 normalization, validity vs possibility, type mapping, the NANP `FIXED_LINE_OR_MOBILE` case asserted explicitly as expected behavior, reserved-range flagging, and that the range-holder field is never labeled as current carrier |
| `test_phone_sources.py` | LocalCallingGuide XML parsing against a captured fixture including the DTD preamble, the empty-result case for an unassigned prefix, and SkipCalls response mapping including that `is_spam: true` maps to a reported category rather than a verdict |

Both use fixtures. Neither makes a network call.

## 9. Dependencies

```
phonenumbers==9.0.39
```

Apache-2.0, zero runtime dependencies, 23 MB installed (19 MB of that is multilingual
geocoding data). Pin exactly: the bundled metadata **is** the intel, so a drifting version
silently changes results with no code change in this repo, exactly like the
`publicsuffixlist` pin.

Do not substitute `phonenumberslite`. It is 3.2 MB but ships no `geodata`, `carrierdata`,
or `tzdata`, so `geocoder`, `carrier`, and `timezone` all raise `ModuleNotFoundError`.

Then `uv lock && uv export --no-dev --no-hashes -o requirements.txt`, or Docker misses it.
