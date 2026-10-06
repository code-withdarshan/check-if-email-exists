# Accounts and authenticator security

Anyone can register a username and password when accounts are enabled. Usernames are case-insensitive, 3–64 ASCII letters, numbers, dots, underscores or hyphens. Passwords require at least 12 characters and at most 256 UTF-8 bytes. Accounts are local to this installation; no email delivery service is required.

## Configuration

Docker Compose in [deploy](../../deploy/README.md) enables accounts. For a standalone backend set:

```sh
RCH__ACCOUNTS__ENABLED=true
RCH__ACCOUNTS__PUBLIC_ORIGIN=https://verifier-app.iqonicdesign.net
RCH__ACCOUNTS__ENCRYPTION_KEY=<output of openssl rand -hex 32>
RCH__ACCOUNTS__SECURE_COOKIES=true
RCH__STORAGE__POSTGRES__DB_URL=postgres://user:password@db:5432/reacher
```

Use the exact browser origin, including any nonstandard port, without a trailing slash or path. HTTPS and secure cookies are required except for explicit localhost development: use an HTTP localhost/127.0.0.1 origin and set secure cookies to false. Accounts default to disabled for existing standalone API installations. Database migrations run at startup.

Keep the encryption key stable and back it up separately from the database. Changing or losing it makes existing authenticator secrets unreadable. There is no automatic key rotation or password-reset flow. Back up the PostgreSQL volume before upgrading; it stores accounts, sessions, encrypted authenticator secrets, recovery-code hashes and job ownership.

## Using two-factor authentication

1. Register or sign in, then open **Account & security**.
2. Enter your current password under authenticator setup.
3. Scan the QR code with a TOTP authenticator app, or enter the displayed setup key manually. Choose time-based codes (SHA-1, six digits, 30 seconds).
4. Enter a current six-digit code to enable protection. Until this succeeds, 2FA remains off. Setup expires after ten minutes and belongs to the initiating browser session.
5. Save the ten recovery codes somewhere private. Each works once and can replace an authenticator code after entering your password. They are only displayed when created.

Every sign-in with 2FA requires a password and an authenticator/recovery code. A consumed authenticator code cannot be used again: wait for the next code if making consecutive security changes. Keep server and phone clocks synchronized. Hardware security keys/passkeys (WebAuthn) are not implemented; the manual key is a TOTP setup secret.

Security settings also provide password changes, recovery-code replacement, disabling 2FA and signing out other sessions. These require your current password plus an authenticator/recovery code when 2FA is enabled. Enabling/disabling 2FA, changing a password and replacing recovery codes revoke other sessions. Generating replacement recovery codes invalidates the previous set.

## Access boundaries

- Browser sessions use HttpOnly, SameSite=Strict cookies, expire after 12 hours, and are stored as token hashes. A pending 2FA sign-in lasts five minutes and cannot access verification APIs.
- Mutations require a CSRF header; supplied origins must match the configured origin. The UI keeps CSRF and enrollment secrets in memory, not local storage.
- Bulk jobs belong to the creating account. Other accounts cannot read their progress or download their results. Historical unowned jobs remain accessible only through the trusted machine API. Browser run history is namespaced by account.
- Account sessions use v1 only. Public account requests cannot supply SMTP/proxy/provider overrides or webhooks. SMTP destinations are resolved, filtered to public IPs and pinned before connecting, including through configured SOCKS proxies.
- The machine API secret retains integration access to all jobs. Keep it private. The included nginx proxy strips client-supplied machine secrets and forwards cookies; it never grants machine access to a browser. Its separate proxy-secret header authenticates client-IP metadata only.
- Password hashing uses salted PBKDF2-HMAC-SHA256 with 600,000 iterations. Authenticator seeds use AES-256-GCM bound to the user ID; recovery codes are random, hashed and atomically consumed. Password work is concurrency-limited. See [OWASP password storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
- Authentication is rate-limited across backend replicas via PostgreSQL: 240 mutations/minute globally, 60/15 minutes per source IP, 10 registration attempts/hour/IP, 10 login/signup attempts/15 minutes/username, and 10 security attempts/15 minutes/account. Failed attempts count. Behind another proxy, the included nginx sees that proxy's IP; configure a trusted real-IP policy if individual client limits are needed.

Verification quotas remain shared across the installation, and run-history listings remain browser-local. Public registration does not include email verification, password reset, admin user management, per-user billing or anti-bot registration challenges.

## Tests

Run ordinary Rust tests plus `node ci/audit-ui.cjs` and `node --test ci/account-ui.test.cjs`. To exercise migrations and the full account lifecycle, point the following at a **disposable database** (the test creates accounts and jobs):

```sh
TEST_ACCOUNT_DATABASE_URL=postgres://user:password@127.0.0.1/accounts_test \
  cargo test -p reacher_backend --lib account_lifecycle_and_access_boundaries -- --ignored
```

The integration test uses a temporary local HTTP listener and covers signup, login, CSRF/origin checks, QR/manual enrollment, pending-session restrictions, OTP/recovery replay, recovery regeneration, password change, logout, expiry, session revocation, machine access and cross-account bulk isolation. It requires PostgreSQL but no RabbitMQ or external email traffic.
