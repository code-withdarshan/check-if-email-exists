# Sending-setup self-check and IPv4 preference

Most `unknown` results come from the server's setup, not the addresses: a
missing reverse DNS name, a blocklisted IP or a blocked port 25. The engine
now checks these itself.

## Self-check

At start-up, and then every hour, the backend checks:

| Check | Fails or warns when |
| --- | --- |
| `ipv4` | The server has no IPv4 route. Behind NAT (a home PC), the remaining IP checks are skipped. |
| `reverse_dns` | The sending IPv4 has no PTR name, or the name doesn't resolve back to the IP. |
| `helo_name` | `RCH__HELLO_NAME` isn't a real host name, or differs from the PTR name. |
| `blocklist` | The IP is listed on Spamhaus ZEN or SpamCop. A list that refuses the query (public resolvers are blocked by Spamhaus) shows `skipped`. |
| `sender` | `RCH__FROM_EMAIL` is a placeholder, or its domain has no mail server. |
| `port_25` | Outgoing port 25 can't be opened to a Gmail mail server within 10 seconds. |

Problems are logged as warnings (`Self-check: …`). The latest report is served
at `GET /v1/self_check`, with the same `x-reacher-secret` header as the other
endpoints:

```json
{ "checked_at": 1790853526, "ip": "<server-ip>", "status": "warn",
  "findings": [ { "name": "reverse_dns", "status": "ok", "detail": "…" } ] }
```

`status` is the worst finding: `ok`, `skipped`, `warn` or `fail`. The response
is `null` for a few seconds after start-up.

## IPv4 first

The engine now resolves each mail server itself and tries its IPv4 addresses
before IPv6. Gmail, Microsoft and others are much stricter with IPv6 senders,
and a VPS's IPv6 address rarely has reverse DNS, so checks over IPv6 were often
refused. IPv6 is still tried when no IPv4 address answers.

## Deploy

Pull and rebuild the engine, then restart it:

```bash
SQLX_OFFLINE=true cargo build --release --bin reacher_backend --locked
sudo systemctl restart verifier-engine
journalctl -u verifier-engine -n 50 | grep Self-check
```

Fix anything reported as `fail` first; `warn` items cost some providers' answers.

## Catch-all domain cache

A domain whose server accepted the made-up catch-all address is remembered for
24 hours. Further checks on it return `risky` (catch-all) at once, without an
SMTP conversation, and carry `debug.smtp.catch_all_cached: true`. Lists with
many addresses at one catch-all domain finish faster, and that domain's server
sees one connection instead of hundreds. The cache lives in the engine's memory
(up to 100,000 domains) and is emptied by a restart.
