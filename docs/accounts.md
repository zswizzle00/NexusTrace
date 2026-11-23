# Accounts and personal API keys

Users can sign in with GitHub or Google and save their own VirusTotal API key. Hash, file
and e-mail lookups then run on that user's key and quota instead of the deployment's
shared `VIRUSTOTAL_API_KEY`.

Accounts are off until you configure them. While they are off, NexusTrace behaves exactly
as it did before: there is no sign-in link, and every `/account` path returns 404.

## What is stored

Sign-in is handled entirely by GitHub or Google. NexusTrace stores:

- The provider name and the provider's permanent user ID.
- A display name (the GitHub login or the Google profile name).
- Each saved API key, encrypted with Fernet, plus its last four characters.

NexusTrace never asks for or receives a password or an e-mail address. GitHub is asked for
no scopes, and Google only for `openid profile`.

The data lives in `data/accounts.db` (SQLite, mode `0600`). Users can delete their own
account and keys from the account page.

## Set up accounts

1. Generate an encryption key:

   ```sh
   python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

   Set it as `ACCOUNTS_ENCRYPTION_KEY` in `.env`. Back it up somewhere other than the
   server, because a backup of `data/accounts.db` is useless without it.

1. Set `OAUTH_REDIRECT_BASE` to the public origin, for example
   `https://nexustrace.example`, with no trailing slash.

1. Register an OAuth app with at least one provider:

   - **GitHub:** go to **Settings > Developer settings > OAuth Apps > New OAuth App**. Set
     the callback URL to `<origin>/account/callback/github`. Copy the client ID and a new
     client secret into `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`.
   - **Google:** in the Google Cloud console, open **APIs & Services > Credentials**, then
     create an **OAuth client ID** of type **Web application**. Add
     `<origin>/account/callback/google` as an authorized redirect URI. Copy the values into
     `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`. The consent screen needs no sensitive
     scopes.

1. Set `SECURE_COOKIES=true` so the session cookie is only sent over HTTPS.

1. Restart the stack:

   ```sh
   docker compose up -d
   ```

## Control who uses the shared key

`VIRUSTOTAL_SHARED_KEY` decides who may spend the deployment's own
`VIRUSTOTAL_API_KEY`:

| Value | Anonymous visitors | Signed-in users without a key |
|---|---|---|
| `everyone` (default) | Shared key | Shared key |
| `accounts` | No VirusTotal lookup | Shared key |
| `nobody` | No VirusTotal lookup | No VirusTotal lookup |

A signed-in user who saved a key always uses their own. When a lookup runs without a key,
the result page shows VirusTotal as not queried, with a link to sign in.

## Limits

- **Sign-ups:** `ACCOUNTS_MAX_USERS` (default 50) caps the number of accounts. Past the cap,
  new identities are refused and existing accounts can still sign in.
- **Rate limits:** each user key gets its own limit of 4 lookups a minute, the VirusTotal
  free tier. One user's lookups never use another user's quota or the shared key's.
- **Cache:** results are cached for 30 minutes per key, so a user without a key never sees
  a VirusTotal answer that another user's key paid for.

## Rotate the encryption key

Put the new key first and keep the old one after a comma:

```sh
ACCOUNTS_ENCRYPTION_KEY=<new key>,<old key>
```

Saved keys stay readable, and new saves use the new key. Once every user has saved their
key again, you can remove the old key. Any key still encrypted only with a removed key is
treated as not saved.

## Disable an account

Use the **Accounts** page of the [operator console](admin.md), or the operator tool from
the deployment directory. Pick the account by its ID, because a display name is not
unique.

```sh
python3 scripts/manage_accounts.py list
python3 scripts/manage_accounts.py disable <id>
python3 scripts/manage_accounts.py enable <id>
python3 scripts/manage_accounts.py delete <id>
```

A disabled account is signed out on its next request and cannot sign in again, and its
saved keys stay in place. `delete` removes the account and every key it saved. In Docker,
run it inside the container (`docker compose exec web python scripts/manage_accounts.py list`).
