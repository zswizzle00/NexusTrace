# Operator console

The operator console at `/admin` shows who uses the site, manages accounts, and reports
how the deployment is configured. It runs in its own `admin` container, separate from
the public `web` process, and it is reachable only from your LAN or Tailscale.

## What it shows

| Section | Contents |
|---|---|
| Activity | Requests in the last 24 hours (totals, errors, hourly chart, top paths, IPs and countries), and every request in a window of 1 to 30 days. |
| Accounts | Account settings, and every account with its provider, last sign-in and saved keys. You can disable, enable or delete an account. |
| Sources | Which intelligence providers have an API key. Key values are never shown. |
| System | The deployment's settings, the networks the console accepts, and how much each data store holds. |

## Open the console

1. Set `ADMIN_TOKEN` in `.env` to a long random value:

   ```sh
   python3 -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

1. Restart the stack:

   ```sh
   docker compose up -d
   ```

1. From a device on your LAN or Tailscale, open `http://<host>:5051/admin` and sign in
   with the token.

Without `ADMIN_TOKEN`, every console path returns 404.

## Who can reach it

The public site has no route to the console: nginx forwards nothing under `/admin`, so
`https://<your domain>/admin` is an ordinary 404.

The console also checks every request itself. It answers only a direct connection from
an address in `ADMIN_NETWORKS`, and returns 404 for anything that arrived through
Cloudflare or a reverse proxy. By default `ADMIN_NETWORKS` covers the private ranges,
loopback and Tailscale. To narrow it, list the networks you use:

```sh
ADMIN_NETWORKS=192.168.1.0/24,100.64.0.0/10
```

The console has its own session cookie, so signing in or out of an account on the
public site never signs you out of the console. Because the console is reached over
plain HTTP, its cookie is not HTTPS-only. If you put the console behind HTTPS, set
`ADMIN_SECURE_COOKIES=true`.

## Manage accounts

On the **Accounts** page:

- **Disable** signs the account out on its next request and blocks sign-in. Its saved
  keys stay in place.
- **Enable** reverses a disable.
- **Delete** removes the account and every key it saved. Type the account ID to confirm.

The same actions are available from the command line with `scripts/manage_accounts.py`;
see [Accounts](accounts.md).
