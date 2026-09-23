# Single-server deployment

Runs the verification backend and a login-protected "Email Checker" web page with Docker Compose. Single checks only (no RabbitMQ/PostgreSQL).

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
   # then set REACHER_SECRET, e.g. to the output of: openssl rand -hex 32
   ```

2. Create the login for the web page (replace `admin` and the password):

   ```sh
   docker run --rm httpd:alpine htpasswd -nbB admin 'choose-a-strong-password' > htpasswd
   ```

   Add more users by appending more lines. `.env` and `htpasswd` are ignored by git.

3. Build and start:

   ```sh
   docker compose up -d --build
   ```

   The page is at `http://127.0.0.1:8090` on the server and asks for the login.

## Making it reachable

The page only listens on `127.0.0.1` by default. Put HTTPS in front of it, because basic-auth passwords travel in every request:

- **Cloudflare quick tunnel** (no account, URL changes on restart):
  `docker compose --profile tunnel up -d`, then read the URL with
  `docker compose logs tunnel | grep trycloudflare.com`.
- **Your own domain:** a Cloudflare named tunnel, or a reverse proxy with TLS
  (Caddy, nginx, Traefik) forwarding to `127.0.0.1:8090`.

Only set `UI_BIND=0.0.0.0` if HTTPS is already handled in front of the server.

## Operating

- Update after pulling new code: `docker compose up -d --build`.
- Logs: `docker compose logs -f backend`.
- Stop: `docker compose down`.
- Rate limits: `MAX_PER_MINUTE` and `MAX_PER_DAY` in `.env`. Keep them low on a single IP.

## Known limitations

- Outlook, Hotmail and Yahoo checks currently time out (HTTP 504) and can leave Chrome processes running. Watch memory until that is fixed.
- If other people use this service, the AGPL-3.0 license requires publishing your modified source code.
