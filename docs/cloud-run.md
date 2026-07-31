# Deploying NexusTrace on Cloud Run

This is the runbook for running NexusTrace as a Cloud Run service. It assumes the
VM / `docker-compose` deployment stays as it is; the same image works in both, and
nothing here changes local development.

The declarative half of this lives in [`service.yaml`](../service.yaml) at the repo
root. Every non-obvious number in that file has a comment explaining why; this
document covers the surrounding procedure and the platform behaviours that no
manifest can express.

**Read [§7 Security](#7-security) before the first deploy.** Two items there
(service-account scope and the malware quarantine) are decisions the operator has to
make, not defaults to inherit.

---

## 0. What is different about Cloud Run

Cloud Run is not "Docker Compose in the cloud". Six differences change how this app
behaves, all of them verified against the current code:

| # | Platform behaviour | Consequence here |
|---|--------------------|------------------|
| 1 | The port is injected as `PORT` (8080) | Handled: the `Dockerfile` `CMD` binds `${PORT:-${FLASK_PORT:-5050}}` and `main.py:resolve_port()` uses the same precedence. Compose still gets 5050. |
| 2 | Instances are replaceable and multiple | `SECRET_KEY` **must** be fixed (§2). Otherwise CSRF tokens minted by one instance are rejected by the next. |
| 3 | 80 concurrent requests per instance by default | Pinned to 8 to match `--threads 8`, because every URL scan holds its thread while a real Chromium process runs (§4). |
| 4 | Request bodies are capped at 32 MiB by the platform | The app allows 50 MB. Uploads between 32 MiB and 50 MB fail **before** Flask sees them (§5). |
| 5 | CPU is only allocated during requests by default | The 30-minute cache-clearing daemon thread in `app/utils/cache.py` would not fire. `service.yaml` sets CPU always-allocated (§4). |
| 6 | No nginx; TLS terminates at Google's front end | `nginx.conf` is dead weight here: its `client_max_body_size 50M` and 300s proxy timeouts do not apply (§5, §6). |

And one more that belongs to the storage work: **the container filesystem is
in-memory and per-instance.** Everything under `data/` (scans, screenshots, e-mail
analyses, submissions, quarantine) is charged against the instance memory limit and
vanishes on the next revision, restart, or scale-down. Set
`STORAGE_BACKEND=gcs` + `GCS_BUCKET` (see `.env.example`).

---

## 1. Prerequisites

```bash
gcloud auth login
gcloud config set project PROJECT_ID
gcloud config set run/region REGION          # e.g. us-central1

gcloud services enable \
    run.googleapis.com \
    artifactregistry.googleapis.com \
    secretmanager.googleapis.com \
    cloudbuild.googleapis.com \
    storage.googleapis.com
```

Pick a region close to your analysts; the scanner's latency is dominated by the
target site, but the UI round-trip is not.

---

## 2. `SECRET_KEY`: do this first

`app/__init__.py` falls back to `os.urandom(32).hex()` when `SECRET_KEY` is unset or
still the `your-secret-key-here` placeholder. That fallback is survivable on a
single long-lived VM. On Cloud Run it is a defect generator:

* every new revision is a new process, so all outstanding CSRF tokens and sessions
  break at deploy time;
* with more than one instance, a token minted by instance A is rejected by instance
  B, so form POSTs fail **intermittently**: the analyst sees
  "Your session expired. Please try again." on a random subset of submissions, and
  the pattern does not reproduce on demand;
* `WTF_CSRF_TIME_LIMIT` is 3600s, so the breakage outlives any single page load.

A fixed, Secret Manager-backed `SECRET_KEY` is therefore a **hard prerequisite**,
not a hardening step. `service.yaml` will not deploy without the secret existing.

```bash
python3 -c "import secrets; print(secrets.token_hex(32))" \
  | gcloud secrets create nexustrace-secret-key --data-file=-
```

Rotating it logs everyone out and invalidates in-flight forms; do it deliberately,
not on a schedule, and expect the "session expired" flash for one page load.

---

## 3. Secrets, Artifact Registry, and the image

### 3a. Secret Manager entries

One secret per key in `.env.example`. All of them are optional to the *app* (a
service whose key is missing is skipped and its card does not render), but a
`secretKeyRef` in `service.yaml` pointing at a secret that does not exist is a hard
deploy failure, so create the ones you have and **delete the unused blocks from
`service.yaml`** rather than creating empty secrets.

| Secret name | Env var | Purpose |
|---|---|---|
| `nexustrace-secret-key` | `SECRET_KEY` | **Required.** Flask session / CSRF signing (§2) |
| `nexustrace-vpnapi-key` | `VPNAPI_KEY` | VPN/proxy detection (primary IP source) |
| `nexustrace-ipinfo-token` | `IPINFO_TOKEN` | IP geolocation |
| `nexustrace-shodan-key` | `SHODAN_KEY` | Ports / banners |
| `nexustrace-abuseipdb-key` | `ABUSEIPDB_KEY` | Abuse reporting |
| `nexustrace-proxycheck-key` | `PROXYCHECK_KEY` | Proxy detection |
| `nexustrace-ip2location-key` | `IP2LOCATION_KEY` | Geolocation |
| `nexustrace-ip2whois-key` | `IP2WHOIS_KEY` | WHOIS |
| `nexustrace-urlscan-api-key` | `URLSCAN_API_KEY` | urlscan.io submissions |
| `nexustrace-virustotal-api-key` | `VIRUSTOTAL_API_KEY` | Hash reputation (4 req/**min** free tier) |
| `nexustrace-alienvault-key` | `ALIENVAULT_KEY` | OTX threat intel |
| `nexustrace-abusech-auth-key` | `ABUSECH_AUTH_KEY` | **One** key for MalwareBazaar, ThreatFox, URLhaus and the Hunting API. Mandatory as of 2026: without it those endpoints return 401 and the sources report as *unavailable*, not as "nothing known", a silent loss of coverage. |

```bash
# repeat per key; --data-file=- avoids the value landing in shell history
printf 'THE-KEY-VALUE' | gcloud secrets create nexustrace-vpnapi-key --data-file=-

# updating a key later adds a new version; service.yaml pins `latest`
printf 'THE-NEW-VALUE' | gcloud secrets versions add nexustrace-vpnapi-key --data-file=-
```

Not secrets, and deliberately plain env vars in `service.yaml`: `SECURE_COOKIES`,
`STORAGE_BACKEND`, `GCS_BUCKET`. `CF_*` (Cloudflare admin) and `MMDB_PATH` are
host-tooling variables and are not needed by the service.

### 3b. Service account

```bash
gcloud iam service-accounts create nexustrace-run \
    --display-name="NexusTrace Cloud Run runtime"

SA=nexustrace-run@PROJECT_ID.iam.gserviceaccount.com

# per-secret access, NOT project-wide secretAccessor
for s in nexustrace-secret-key nexustrace-vpnapi-key nexustrace-abusech-auth-key ...; do
  gcloud secrets add-iam-policy-binding "$s" \
      --member="serviceAccount:$SA" \
      --role=roles/secretmanager.secretAccessor
done

# bucket-scoped object access, NOT project-wide storage.admin
gcloud storage buckets add-iam-policy-binding gs://BUCKET_NAME \
    --member="serviceAccount:$SA" \
    --role=roles/storage.objectUser
```

Do **not** run the service as the default compute service account: it holds project
Editor, and §7a explains exactly why that matters for this application in
particular.

### 3c. Storage bucket

```bash
gcloud storage buckets create gs://BUCKET_NAME \
    --location=REGION \
    --uniform-bucket-level-access \
    --public-access-prevention
```

Uniform access + public access prevention are not optional here: the bucket holds
screenshots of attacker-controlled pages, e-mail findings (sender addresses,
subjects, Received-chain IPs), and (if you enable the submission queue) malware
samples (§7b).

Add a lifecycle rule instead of running `scripts/purge_data.py`, which has no cron
hook on Cloud Run:

```bash
cat > /tmp/lifecycle.json <<'JSON'
{"rule": [{"action": {"type": "Delete"}, "condition": {"age": 30}}]}
JSON
gcloud storage buckets update gs://BUCKET_NAME --lifecycle-file=/tmp/lifecycle.json
```

### 3d. Build and push

```bash
gcloud artifacts repositories create nexustrace \
    --repository-format=docker --location=REGION

IMAGE=REGION-docker.pkg.dev/PROJECT_ID/nexustrace/nexustrace:$(git rev-parse --short HEAD)
```

**The Cloud Run image needs one build arg.** `google-cloud-storage` is an optional
extra that `app/utils/storage.py` imports lazily, so it is deliberately absent from
`requirements.txt` (`uv export` does not emit extras) and the default image does not
carry it. `STORAGE_BACKEND=gcs` without it fails at the first write. Build with
`INSTALL_GCS=true`.

Build on Cloud Build, not locally. A local build of this image installs a 307 MB
venv and a Chromium download; on a 2-core VM that is ~40 minutes.

`gcloud builds submit --tag` does not accept build args, so use a two-line build
config:

```bash
cat > cloudbuild.yaml <<'YAML'
steps:
  - name: gcr.io/cloud-builders/docker
    args: ['build', '--build-arg', 'INSTALL_GCS=true', '-t', '$_IMAGE', '.']
images: ['$_IMAGE']
YAML
gcloud builds submit --config cloudbuild.yaml --substitutions=_IMAGE="$IMAGE" .
```

Confirm the extra actually landed before deploying; this is the failure that only
shows up when an analyst runs the first scan:

```bash
docker run --rm --entrypoint python "$IMAGE" -c "import google.cloud.storage; print('gcs ok')"
```

If you must build locally (`docker build --build-arg INSTALL_GCS=true -t "$IMAGE" .
&& docker push "$IMAGE"`), note
the constraints the `Dockerfile` is written around and do not "optimise" them away:

* **No `RUN --mount=type=cache`.** The production host runs docker-compose v1 with
  the legacy builder and no buildx, where a cache mount is a hard build failure.
* **No recursive `chown`.** `appuser` is created before anything is copied and the
  ownership is set by `COPY --chown`. A `chown -R` over the venv rewrites 7,300
  files into a new layer: that was the step that looked like a 20-minute hang.
* **`--only-binary` on the expensive packages.** A missing wheel must fail loudly
  rather than silently compile `cryptography` (Rust, ~15 min) or `numpy`/`pandas`
  (~25 min). Nothing needs a compiler, which is why `build-essential` and
  `libpq-dev` are absent.
* **The build-time Chromium assertion.** `run_scan()` resolves the browser lazily on
  the first scan, long after any healthcheck goes green, so the build asserts the
  binary exists and is executable **as `appuser`**. Without it, a wrong
  `PLAYWRIGHT_BROWSERS_PATH` ships a container that looks healthy and dies on the
  first analyst request.

Also remember the `requirements.txt` gotcha: `uv` drives local dev but the image
installs with pip, so after `uv add <package>` run
`uv export --no-dev --no-hashes -o requirements.txt` or the build silently misses it.

---

## 4. Deploy

Edit `service.yaml` and replace `PROJECT_ID`, `REGION`, `TAG`, and `BUCKET_NAME`,
then:

```bash
gcloud run services replace service.yaml --region REGION
gcloud run services describe nexustrace --region REGION --format='value(status.url)'
```

`services replace` is declarative and authoritative: it removes anything not in the
file. Do not mix it with `gcloud run deploy --set-env-vars`; change the file and
re-apply, so the manifest stays the source of truth.

Access is IAM-restricted by default. Either publish it:

```bash
gcloud run services add-iam-policy-binding nexustrace \
    --region REGION --member=allUsers --role=roles/run.invoker
```

...or, preferably for an analyst tool, keep it private and front it with IAP or an
identity-aware load balancer. NexusTrace has **no application-level authentication**
of its own; anything that can reach the URL can drive the scanner (§7a).

### Concurrency, CPU and memory: the numbers and why

| Setting | Value | Reason |
|---|---|---|
| `containerConcurrency` | **8** | Exactly gunicorn's `--threads 8`. At the default 80, 72 requests would queue in the socket backlog behind 8 threads that each hold a live Chromium process for ~30s+, so queued requests exceed both `--timeout 120` and `timeoutSeconds`. Pinning it moves the waiting into Cloud Run's queue, where it is visible in metrics instead of appearing as random 504s. |
| `cpu` | **2** | Chromium rendering is CPU-bound, and Cloud Run's CPU/memory minimums require ≥2 vCPU at 4Gi. At 1 vCPU two concurrent scans serialize and both approach the timeout. |
| `memory` | **4Gi** | ~250 MB base (Python + Flask + MMDB reader) + ~350 MB per in-flight scan (Chromium browser + renderer on a script-heavy page; `--disable-dev-shm-usage` means it is all heap) + ~100 MB of full-page PNG and text buffers. Worst case 8 concurrent scans ≈ 2.8 GB, leaving ~700 MB headroom, which the in-memory filesystem also draws on when `STORAGE_BACKEND=local`. |
| `timeoutSeconds` | **180** | Must exceed gunicorn's `--timeout 120` so a hung worker is killed and logged by gunicorn (502) rather than truncated by the platform (an unattributable 504). |
| `maxScale` | **1** | Rate limiters are per-process module-level singletons, so N instances multiply the real provider rate; VirusTotal's free tier is 4 req/**minute**. And with `STORAGE_BACKEND=local`, instances cannot see each other's scans. Raise only after GCS storage is in place and you accept the multiplied rate. |
| `minScale` | **1** | Large image + Chromium launch makes cold start tens of seconds; also keeps the cache thread alive. |
| `cpu-throttling` | **false** | See below. |
| execution environment | **gen2** | Full syscall surface for Chromium, real `/tmp`, network mounts. |

**The CPU allocation tradeoff.** With the default (CPU only during requests), the
daemon thread `app/utils/cache.py` starts (which sleeps 1800s then calls
`clear_caches()`) is frozen between requests and will not fire on any predictable
schedule. Same for any straggler enrichment thread that outlives its request
(`email_service`'s `ENRICH_DEADLINE` detaches futures, it cannot cancel the
threads). Setting `run.googleapis.com/cpu-throttling: "false"` fixes both but bills
the instance for its whole lifetime rather than per request, roughly 3-4x an idle
request-billed instance at `minScale: 1`. If that cost is unacceptable, set it back
to `"true"` and accept the pre-existing fallback: each cached function still expires
lazily on its own TTL, so the only loss is the proactive sweep. Do not instead move
the sweep to Cloud Scheduler; it clears in-process caches and cannot be triggered
over HTTP.

Scaling up later, in order: raise `--threads` in the `Dockerfile` **and**
`containerConcurrency` **and** `memory` together (they are one decision, not three),
or switch to `STORAGE_BACKEND=gcs` and raise `maxScale` while accepting the provider
rate multiplication.

---

## 5. Request size: a real mismatch, not a rounding error

`app/__init__.py` sets `MAX_CONTENT_LENGTH = 50 * 1024 * 1024`. **Cloud Run rejects
HTTP/1 request bodies larger than 32 MiB at the front end**, before the request ever
reaches gunicorn. So on Cloud Run:

* an upload between **32 MiB and 50 MB** is rejected by the platform with a 413 that
  the app never logs and cannot flash a message about;
* affected paths: `POST /api/file/analyze_file` (file malware analysis),
  `POST /api/ip/check_ips` (batch CSV/XLSX), and `POST /email_analysis` with pasted
  raw source (separately capped at 10 MB, so pasting is only affected above that);
* `nginx.conf`'s `client_max_body_size 50M` is not in the path and does not help.

The app limit is deliberately left at 50 MB; lowering it would silently change the
VM deployment, where 50 MB genuinely works. Choose one of these instead:

1. **Recommended:** tell analysts the effective ceiling on Cloud Run is **32 MiB**,
   and treat larger samples as an out-of-band workflow. Real `.eml` files and IP
   batches are orders of magnitude below this; the limit only bites on large binary
   samples, which are exactly the ones §7b says to think twice about uploading.
2. If you need the app's error message rather than the platform's, set
   `MAX_CONTENT_LENGTH` to 32 MiB **for the Cloud Run deployment only**: that means
   an env-var-driven override in `app/__init__.py`, which does not exist today.
   Don't hard-code it; it would regress the VM.
3. Cloud Run documents the 32 MiB cap as applying to HTTP/1 requests, with
   HTTP/2 end-to-end exempt. If you want to rely on that, enable HTTP/2 on the
   service and **verify with a real >32 MiB upload** before telling analysts it
   works; this is a platform detail, not something this codebase controls.

---

## 6. nginx, `ProxyFix`, and client IPs

`docker-compose.yml`'s nginx container is not deployed here. Cloud Run terminates
TLS and routes straight to the container, so nothing in `nginx.conf` applies: the
50 MB body limit (§5), the 300s proxy timeouts (the platform's `timeoutSeconds`
governs instead), the buffer sizes, and the wildcard CORS headers all disappear. The
wildcard `Access-Control-Allow-Origin: *` disappearing is a small improvement, not a
regression.

`app/__init__.py` wraps the app in `ProxyFix(x_for=1, x_proto=1, x_host=1,
x_prefix=1)`: trust exactly one upstream hop. What is correct on Cloud Run:

* **Direct Cloud Run URL (`*.run.app`): `x_for=1` is correct, leave it alone.**
  Google's front end appends the real client IP to any client-supplied
  `X-Forwarded-For`, so the rightmost entry (which is what ProxyFix's one-hop
  setting reads) is the trustworthy one. `X-Forwarded-Proto` is `https`, which is
  what makes `SECURE_COOKIES=true` and any future `force_https` behave.
* **Behind a Google external Application Load Balancer**, the last two `XFF` entries
  are supplied by Google, so the trusted hop count is **2**. Add another proxy
  (Cloudflare in front of the LB) and it is 3.
* **Getting this number wrong is not cosmetic**: too low and every request appears
  to come from the load balancer, so per-client attribution in logs collapses onto
  one address; too high and a client can spoof its own source IP by sending its own
  `X-Forwarded-For`.

`ProxyFix`'s hop count is not currently configurable by env var. If you deploy
behind a load balancer, that override is the change to make: one line in
`app/__init__.py`, defaulting to 1 so the VM is unaffected.

---

## 7. Security

### 7a. The metadata server and the URL scanner

This is the single most important item in this document.

Cloud Run instances can reach the GCE metadata server at **`169.254.169.254`**
(alias `metadata.google.internal`), and it issues **OAuth access tokens for the
attached service account** to anything that can make an HTTP request from inside
the container, with no credential required beyond the request itself.

NexusTrace's URL scanner makes outbound HTTP requests to URLs an untrusted party
influences: the submitted target, everything in its redirect chain, and every
subresource the page loads. That is the exact shape of an SSRF-to-credential-theft
chain on GCP.

The guard is real and it does block this:

* `app/utils/url_guard.py` blocks `metadata` and `metadata.google.internal` by
  hostname outright, and rejects any IP literal or resolved address outside the
  globally-routable ranges. `169.254.169.254` is link-local, so it is rejected on
  that basis as well as by name.
* `validate_target()` is called before Chromium is launched, on **every hop** of the
  pre-flighted redirect chain, on every subresource via the `context.route`
  backstop, and on `ws(s)://` via a separate `route_web_socket` guard.
* `transactions` / `domains` / `ips` are filtered through the guard a **second**
  time before persistence, so a blocked internal host cannot become a port or
  liveness oracle in the rendered report.

And the module states its own residual gaps rather than papering over them: a
subresource that redirects is not re-validated on that hop (the connection has
already happened), and **DNS rebinding is not closed**: validation and Chromium's
own later resolution are separate lookups, so an attacker who wins that race is not
stopped. Closing it needs resolve-and-pin at the network layer or egress control.

Therefore, on GCP, defence in depth is mandatory, because the consequence of a
bypass is not "a leaked internal status code"; it is **theft of the service
account's credentials**:

1. **Grant the runtime service account nothing beyond what it needs.** Concretely:
   per-secret `roles/secretmanager.secretAccessor` on the specific secrets in §3a,
   and `roles/storage.objectUser` on the specific bucket in §3c. Nothing else. No
   project-level roles, and **never** the default compute service account, whose
   project Editor role turns a scanner SSRF into full project compromise.
2. **Do not attach anything else to this identity**: no Cloud SQL, no BigQuery, no
   Pub/Sub, no `iam.serviceAccountTokenCreator` (which would let a stolen token mint
   tokens for other identities and defeat the whole point of item 1).
3. **Prefer egress control.** Route egress through a VPC connector /
   Direct VPC egress with Cloud NAT and firewall rules that permit only outbound
   80/443 to the internet. That is what actually closes the DNS-rebinding gap the
   guard cannot close in a stdlib-only leaf module.
4. **Keep the service private** (IAP or an identity-aware LB, §4). NexusTrace has no
   authentication of its own; a public URL means anyone on the internet can aim the
   scanner, which is the same as handing them the SSRF primitive.
5. **Review `url_guard.py` changes as security changes.** Every branch of
   `_blocked_ip` closed a real bypass. `tasks/lessons.md` is the postmortem log and
   should be read first; the unit tests (`test_url_guard.py`, `test_nav_gate.py`,
   `test_ws_guard.py`) are the regression net.
6. **Alert on it.** A log-based alert on `blocked_requests` entries with
   `kind: 'blocked'` naming a link-local or metadata target is a high-signal
   indicator that someone is probing this specific path.

### 7b. `data/quarantine/` holds live malware, an acceptable-use decision

The abuse.ch submission queue (`app/services/submissions.py`) writes sample bytes to
`data/quarantine/` while a submission waits for operator approval. Those are **live
malware samples**. The module is careful with them (`0600`, filenames derived from a
digest the module computes itself, deleted as soon as the record reaches a terminal
state, never returned by any accessor), but that is local hygiene, not a hosting
decision.

On Cloud Run this becomes an explicit choice the operator must make, for two
reasons:

1. **Google Cloud's Acceptable Use Policy and Terms of Service restrict storing and
   distributing malware.** Security research and incident response are common,
   legitimate uses and are generally accommodated, but the boundary depends on your
   agreement (and whether you are on a paid support plan). Read your own terms and,
   if you intend to run the submission queue in production, get it confirmed in
   writing rather than inferring it from this document. Nothing here is legal
   advice, and a suspension takes the whole analyst tool offline, not just the
   queue.
2. **`STORAGE_BACKEND=gcs` changes the blast radius.** With `local`, samples live in
   an in-memory filesystem that dies with the instance. With `gcs`, they become
   durable objects in your bucket, subject to your retention and your organisation's
   data-handling rules, and reachable by anything that gains the service account's
   token (§7a). Cloud Storage may also scan or act on stored content per your
   agreement.

Options, in decreasing order of caution:

* **Leave the submission queue unused on Cloud Run.** Nothing else in the app writes
  quarantine, so an unused queue means no samples at rest.
* **Keep quarantine ephemeral while everything else goes to GCS.** There is no
  per-store override today: `STORAGE_BACKEND` selects the backend for all five
  stores at once (`scans`, `screenshots`, `analyses`, `submissions`, `quarantine`),
  so with `gcs` the samples follow the scans into the bucket. Splitting them would be
  a change to `app/utils/storage.py`, not a configuration choice.
* **Use GCS with a short lifecycle rule** (hours, not the 30 days in §3c), a
  dedicated bucket with its own IAM, CMEK if your policy requires it, and an
  operator process that approves or rejects promptly so records reach a terminal
  state and the bytes are deleted.

Whatever you choose, decide it before enabling the queue, not after the first
sample is uploaded.

### 7c. Everything else

* `SECURE_COOKIES=true` is set in `service.yaml` and is correct: HTTPS is terminated
  by Google's front end.
* Enrichment API keys live in `data/api_keys.json`, created by
  `scripts/manage_api_keys.py`. On Cloud Run that path is in the ephemeral
  filesystem, so keys created on one instance are unknown to the next revision. Move
  the file to the storage backend or hold the enrichment API to a single stable
  deployment.
* `FLASK_DEBUG` must stay false/unset. It is not referenced by `create_app()` today,
  but do not introduce it here.
* Cloud Run's own request logs record full URLs. Analysts paste indicators into
  `GET /i/<indicator>`, so those indicators (including URLs from phishing mails)
  land in Cloud Logging. Set a retention policy that matches how you treat the rest
  of your analyst data.

---

## 8. Verify a deployment

```bash
URL=$(gcloud run services describe nexustrace --region REGION --format='value(status.url)')

curl -s "$URL/api/health" | python3 -m json.tool     # status + which keys are configured
curl -s -o /dev/null -w '%{http_code}\n' "$URL/"     # 200, HTML shell renders
```

Then, in a browser (the scanner is the part that most often breaks in a new
environment, and it is the only path that needs Chromium):

1. Submit a benign URL at `/url_scan` and confirm a screenshot renders. A Chromium
   launch failure shows up here as a scan with `status='error'`.
2. Submit an IP at `/` and confirm the provider cards you have keys for appear;
   a missing card means a missing or unreadable secret.
3. Upload a small `.eml` at `/email_analysis` and confirm the result page loads on a
   **second** request (that is what catches per-instance storage: with
   `STORAGE_BACKEND=local` and `maxScale > 1` it 404s intermittently).

```bash
gcloud run services logs read nexustrace --region REGION --limit 50
```

## 9. Rollback

Revisions are immutable, so rollback is a traffic change and takes effect in
seconds:

```bash
gcloud run revisions list --service nexustrace --region REGION
gcloud run services update-traffic nexustrace --region REGION --to-revisions REVISION=100
```

Remember to update `service.yaml`'s image tag afterwards, or the next
`services replace` re-deploys the bad build.
