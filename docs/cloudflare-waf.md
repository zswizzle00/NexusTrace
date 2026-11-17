# Cloudflare edge rules for nexustrace.net

The in-app guard (`app/utils/abuse_guard.py`) is a backstop. Dropping junk at Cloudflare is
cheaper: it never crosses the tunnel and never reaches Flask. Dashboard: **Security > WAF >
Custom rules** (free plan allows 5 rules). Put them in this order.

Traffic is low (about 1.5k requests a day, no 5xx), so these rules are hygiene, not incident
response.

## 1. Block secret and config scanners

Action: Block.

```
(lower(http.request.uri.path) contains "/.env") or
(lower(http.request.uri.path) contains "/.git") or
(lower(http.request.uri.path) contains "/.aws") or
(lower(http.request.uri.path) contains "/.ssh") or
(http.request.uri.path contains "/wp-") or
(http.request.uri.path contains "xmlrpc.php") or
(http.request.uri.path contains "phpmyadmin") or
(http.request.uri.path contains "/cgi-bin") or
(lower(http.request.uri.path) in {"/cred.txt" "/creds.txt" "/credentials.json" "/secrets.json" "/config.json" "/backup.sql" "/dump.sql"})
```

## 2. Block repeat offenders

Action: Block.

Review these before keeping them: they are hosting-provider ranges, so prefer the /24 only if the
logs show the neighbours doing the same.

```
(ip.src in {185.202.236.187 185.194.178.73 185.194.178.83})
```

## 3. Challenge the expensive endpoints

Action: Managed Challenge.

`/analyze` and `/url_scan` drive provider APIs and a real Chromium; a human clears the
challenge once, a script does not.

```
(http.request.uri.path in {"/analyze" "/url_scan"} and http.request.method eq "POST" and not cf.client.bot)
```

## 4. Rate limit

Go to Security > WAF > Rate limiting rules.

Free plan: one rule, 10 s period. Match `(http.host eq "cloud.nexustrace.net")`, same IP,
**60 requests / 10 s**, action Block for 10 minutes. A normal page load is about 20
requests, so this only catches clients well beyond it. The nginx limit (10 req/s, burst 40)
and the in-app ceiling (240 req/min) are independent backstops behind it.

## 5. Challenge headless browsers

Action: Managed Challenge.

The analytics showed `ChromeHeadless` (48 requests). Real analysts do not use it.

```
(http.user_agent contains "HeadlessChrome") and not cf.client.bot
```

## Other findings from the export

- **731 x 301.** About 460 landed in one hour from a single IP. Check whether this is
  http -> https (turn on *SSL/TLS > Edge Certificates > Always Use HTTPS* so it is answered
  at the edge) or a trailing-slash redirect loop against the origin.
- **Cache hit 4.15%.** Mostly dynamic pages, expected. `/static/*` can get a cache rule
  (Cache Rules > Eligible, Edge TTL 1 month) since the app already versions it with `?v=`.
- **Googlebot / Bingbot (56 requests).** Legitimate; rule 5 and rule 3 exempt verified bots
  via `cf.client.bot`. Add `Disallow: /analyze` and `/url_scan` to robots.txt if crawl load
  matters.
- **Bot Fight Mode** (Security > Bots) is free and worth enabling.

## App-side knobs

| Env | Default | Meaning |
| --- | --- | --- |
| `ABUSE_GUARD` | `on` | `off` disables the in-app guard |

Thresholds (`PROBE_STRIKES`, `BAN_SECONDS`, `MAX_REQUESTS_PER_WINDOW`, ...) are constants at
the top of `app/utils/abuse_guard.py`. Bans are in memory and clear on restart.
