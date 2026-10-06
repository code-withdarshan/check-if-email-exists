# Single-server deployment

Runs the verification backend and a account-protected "Email Checker" web page with Docker Compose. The page does single checks and bulk runs (paste a list or upload a CSV). Bulk runs are queued on the server (RabbitMQ, results in PostgreSQL), so they keep going after the page is closed.

## Requirements

- Docker with the Compose plugin.
- Outbound TCP port 25 allowed by the host and its provider. Test before deploying:
  `nc -vz -w 5 gmail-smtp-in.l.google.com 25` (Linux) or
  `Test-NetConnection gmail-smtp-in.l.google.com -Port 25` (Windows).
  Without port 25 most results are `unknown`.
- About 1 GB of RAM. The backend runs Chrome for Outlook/Yahoo checks.

## Setup

Run these from the `deploy/` directory.

1. Create the settings file and set a random secret:

   ```sh
   cp .env.example .env
   # then set REACHER_SECRET and ACCOUNT_ENCRYPTION_KEY (openssl rand -hex 32 each),
   # PUBLIC_ORIGIN to your exact HTTPS origin (no trailing slash), and
   # QUEUE_PASSWORD and DB_PASSWORD (openssl rand -hex 24 each)
   ```

2. Configure HTTPS forwarding to this server and set `PUBLIC_ORIGIN` to the browser origin.
   Keep `SECURE_COOKIES=true`. For local development only, use
   `PUBLIC_ORIGIN=http://localhost:8090` and `SECURE_COOKIES=false`.

3. Build and start:

   ```sh
   docker compose up -d --build
   ```

   The page listens at `http://127.0.0.1:8090` behind your HTTPS proxy. Open the
   configured public origin and choose **Create an account**. Anyone can register.
   Use **Account & security** to add an authenticator by QR code or manual setup
   key, save recovery codes, change your password, and sign out other sessions.

   Existing Basic Auth/htpasswd credentials are not migrated. Back up the database
   before upgrading. Preserve `ACCOUNT_ENCRYPTION_KEY` across restarts and deploys.
   See [account configuration and security](../docs/self-hosting/accounts.md).

## Making it reachable

The page only listens on `127.0.0.1` by default. Put HTTPS in front of it to protect passwords and session cookies:

- **Cloudflare quick tunnel** (no account, URL changes on restart):
  `docker compose --profile tunnel up -d`, then read the URL with
  `docker compose logs tunnel | grep trycloudflare.com`. Set that URL as
  `PUBLIC_ORIGIN` and recreate the backend before signing in. A stable named
  tunnel/domain avoids updating the origin when the quick-tunnel URL changes.
- **Your own domain:** a Cloudflare named tunnel, or a reverse proxy with TLS
  (Caddy, nginx, Traefik) forwarding to `127.0.0.1:8090`.

Only set `UI_BIND=0.0.0.0` if HTTPS is already handled in front of the server.

## Operating

- Update after pulling new code: `docker compose up -d --build`.
- Logs: `docker compose logs -f backend`.
- Health: `docker compose ps` shows the backend as `healthy` once `GET /health` succeeds.
- Stop: `docker compose down`.
- Rate limits: `MAX_PER_MINUTE` and `MAX_PER_DAY` in `.env`. Keep them low on a single IP. They cover single checks and bulk runs together; bulk jobs over the daily limit wait in the queue and resume when it resets. The page shows how much of the day's limit is used (`GET /v1/usage`).
- Bulk runs: the list of runs is kept per account in each browser; job ownership, accounts and results are stored in the `db-data` volume. `docker compose down -v` deletes them.

## Known limitations

- Outlook, Hotmail and Yahoo are checked over SMTP. Microsoft refuses IPs on the Spamhaus blocklist (which includes most home and many cloud IPs), and Yahoo requires the server's reverse DNS to match; otherwise these addresses come back `unknown`. The older browser-based checks are off by default because those pages changed.
- The daily-limit window starts when the backend starts (not at midnight) and resets if the backend restarts.
- A running bulk job cannot be cancelled from the page.
- If other people use this service, the AGPL-3.0 license requires publishing your modified source code.
