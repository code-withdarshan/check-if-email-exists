# Independent SMTP recipient probes

This update puts the requested recipient on a fresh SMTP connection after a
negative catch-all check. Both checks used to share a connection. That could
produce a misleading result if a server validates the first recipient differently
from later recipients in the same session.

The domain is still checked for catch-all behavior. A failed check remains
`unknown`; an accepted random address remains `risky`. Provider rules that
intentionally skip catch-all probing keep their single recipient connection.

## Deploy

Update these files in the **Rust backend** checkout on the VPS:

- `core/src/smtp/connect.rs`
- `core/src/smtp/mod.rs`
- `core/src/smtp/connect/tests.rs`

Run from that backend checkout, stopping if either command fails:

```bash
cargo test -p check-if-email-exists --lib smtp::connect::tests --locked
SQLX_OFFLINE=true cargo build --release --bin reacher_backend --locked
```

Restart the existing engine process using its service manager. For the standard
systemd installation, use `sudo systemctl restart verifier-engine`. For PM2, use
`pm2 restart <actual-engine-process-name>`. Check that this process points at the
binary you just built. A Docker installation must rebuild and replace its engine
image instead.

This update requires no frontend build or database migration.

## Confirm the new behavior

Run a fresh verification; previously saved results do not change. In
`debug.smtp.probes`, each entry now has a `connection` number within its
`attempt`. For a domain that rejects the random address, expect:

```json
[
  { "attempt": 1, "connection": 1, "stage": "catch_all" },
  { "attempt": 1, "connection": 2, "stage": "recipient" }
]
```

The actual entries also include the server reply or transport error. A reconnect
after an interrupted recipient probe uses connection 3. Domains with an explicit
catch-all skip rule check the recipient on connection 1.

Each ordinary non-catch-all verification now uses two SMTP connections instead
of one. This adds connection and greeting overhead. The existing per-attempt
timeout still bounds the complete operation, including both sessions. Closing the
first connection waits at most two seconds for QUIT before dropping the socket.

A fresh recipient rejection such as `550 5.1.1` is classified as `invalid`.
A temporary or policy refusal stays `unknown`. A fresh `250` may still produce
`safe`: SMTP acceptance does not establish final delivery. This change prevents
session-dependent acceptance from contaminating the recipient check; whether it
explains a particular live false positive needs a fresh result from that VPS.
Confirmed delivery bounces remain stronger evidence than an SMTP-only probe.
