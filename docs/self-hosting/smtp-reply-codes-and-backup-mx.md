# SMTP reply codes and backup MX hosts

This update turns more `unknown` results into definite answers. It changes how
recipient replies are read and which mail server is asked:

- **Status codes decide first.** The engine reads the RFC 3463 enhanced status
  code on every reply line, not only the first. `5.1.1`, `5.1.6` and `5.1.10`
  mean the mailbox does not exist (`invalid`). `5.2.1` means a disabled mailbox
  (`invalid`, `is_disabled: true`). `4.2.2` and `5.2.2` mean a full inbox
  (`risky`). A code now outranks broad wording such as "blocked" or "access
  denied". The exception is a reply that blames the sending IP's reputation
  (Spamhaus, blacklist, DNSBL and similar), which stays `unknown`.
- **Microsoft 365 business domains.** With directory-based edge blocking, Microsoft
  rejects unknown recipients with
  `550 5.4.1 Recipient address rejected: Access denied. AS(201806281)`. That reply
  was read as an IP block. The random catch-all address gets it first, so these
  domains returned `unknown`. It now counts as "no such recipient".
- **Stricter "disabled" wording.** Without a status code, "disabled", "discontinued"
  or "inactive" must refer to an account, mailbox, user or recipient.
  `550 Relaying disabled` is no longer a disabled mailbox.
- **Replies about our sender.** Postfix checks the sender when the recipient is
  given, so a refusal of `RCH__FROM_EMAIL` arrives as the RCPT reply, often with
  recipient-like words: `550 5.1.0 <check@…>: Sender address rejected: User unknown`.
  Such replies ("sender address", "sender verify", "sender domain"…) now stay
  `unknown` with `description: "SenderRejected"`, instead of `invalid`. If they're
  common, `RCH__FROM_EMAIL` isn't a real, deliverable mailbox.
- **Null MX.** A domain whose only MX is `.` (RFC 7505) or `localhost` accepts no
  email: `invalid` with `accepts_mail: false`, and no connection is made. A null MX
  among real hosts is skipped.
- **Backup MX hosts.** Hosts are tried in MX preference order, up to three. The next
  host is tried only when the current one refused or reset the connection, or gave
  a temporary refusal before answering any recipient probe. Replies that name the
  sending IP's reputation do not trigger a fallback, because every host would
  repeat them. Neither do timeouts, which would add a full SMTP timeout per host.
- **Connection timeout.** Opening the TCP connection now times out after 10 seconds,
  inside the existing `smtp_timeout`. An unreachable host therefore fails fast and
  leaves time for the next one. This applies to direct connections; SOCKS5 proxies
  keep their own `proxy.timeout_ms`.

A backup MX that accepts every recipient shows up as a catch-all domain (`risky`),
not `safe`. Its catch-all probe runs as usual.

## Deploy

Pull the commit into the **Rust backend** checkout on the VPS. It changes
`core/src/lib.rs`, `core/src/smtp/connect.rs`, `core/src/smtp/mod.rs`,
`core/src/smtp/parser.rs` and `core/src/smtp/connect/tests.rs`.

Run from that backend checkout, stopping if either command fails:

```bash
cargo test -p check-if-email-exists --lib --locked -- smtp::
SQLX_OFFLINE=true cargo build --release --bin reacher_backend --locked
```

Restart the existing engine process using its service manager. For the standard
systemd installation, use `sudo systemctl restart verifier-engine`. For PM2, use
`pm2 restart <actual-engine-process-name>`. Check that this process points at the
binary you just built. A Docker installation must rebuild and replace its engine
image instead.

The engine update needs no frontend build or database migration. The verifier
website's matching dispatcher update, which retries "try again later" results
after a wait, is deployed separately with its own migration.

## Confirm the new behavior

Run a fresh verification; previously saved results do not change. Each entry in
`debug.smtp.probes` now has an `mx_host`, and `debug.smtp.verif_method.host` names
the host that produced the final answer. When the preferred host could not be
reached, expect its failed entry first:

```json
[
  { "attempt": 1, "connection": 1, "mx_host": "mx1.example.com.", "stage": "catch_all", "error": "I/O error: ..." },
  { "attempt": 1, "connection": 1, "mx_host": "mx2.example.com.", "stage": "catch_all" },
  { "attempt": 1, "connection": 2, "mx_host": "mx2.example.com.", "stage": "recipient" }
]
```

The actual entries also include each server reply. A failed first connection now
keeps its entry, with the stage that was due, instead of leaving no trace.

For a Microsoft 365 business domain (MX ending in `.mail.protection.outlook.com.`),
a made-up address should now return `invalid` with a `5.4.1` recipient reply,
and a real mailbox `safe`. Microsoft tenants without edge blocking accept every
recipient and stay `risky` (catch-all). SMTP cannot tell those mailboxes apart.
