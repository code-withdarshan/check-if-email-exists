# Email providers: Yandex, AOL, Zoho, IONOS, OVHcloud, Hostinger, GoDaddy

All of these are checked over SMTP, like any other domain. What differs is how
each one says "no such mailbox", and what it expects from the checker's server.

| Provider | MX hosts | Missing mailbox reply | Result |
| --- | --- | --- | --- |
| Yandex (yandex.ru/.com, Yandex 360) | `mx.yandex.ru`, `mx.yandex.net` | `550 5.7.1 No such user!` | `invalid` (fixed, was `unknown`) |
| AOL, AIM, Yahoo | `*.yahoodns.net` | `554 delivery error: dd This user doesn't have a aol.com account` | `invalid` (fixed, was `unknown`) |
| Zoho Mail | `mx.zoho.*`, `smtpin.zoho.*` | `550 5.1.1 User does not exist` | `invalid` |
| IONOS (1&1) | `mx00.ionos.*`, `mx01.ionos.*` | `550 Requested action not taken: mailbox unavailable` | `invalid` |
| OVHcloud MX Plan | `mx*.mail.ovh.net` | `550 5.1.1 … Recipient address rejected: User unknown in virtual mailbox table` | `invalid` |
| Hostinger | `mx1.hostinger.com`, `mx2.hostinger.com` | `550 5.1.1 … Recipient address rejected: User unknown` | `invalid` |
| GoDaddy Workspace | `smtp.secureserver.net`, `mailstore1.secureserver.net` | `550 5.1.1 … Recipient not found` | `invalid` |
| GoDaddy Microsoft 365 | `*.mail.protection.outlook.com` | `550 5.4.1 Recipient address rejected: Access denied` | `invalid` |

The Yandex, Zoho and GoDaddy Microsoft 365 replies were seen live from their
servers. The others come from each provider's documentation and bounce reports, and
are covered by tests.

## What changed

- **Yandex.** It reports a missing mailbox under the policy code `5.7.1`. Every
  `5.7.x` reply used to count as a policy refusal, and the random catch-all address
  gets this reply first, so every Yandex address came back `unknown`, real or not.
  A `5.7.x` reply whose wording only ever means "no such mailbox" ("no such user",
  "user unknown", "email doesn't exist"…) now counts as a missing mailbox, unless it
  also blames the checker's IP. Gmail's `5.7.1 Email doesn't exist` uses the same rule.
- **AOL and Yahoo.** The "doesn't have a aol.com account" wording now means `invalid`.
  Yahoo's servers, which host aol.com, aim.com, ymail.com and rocketmail.com, are never
  catch-all, so they skip the catch-all probe (rule on the MX suffix `.yahoodns.net.`).
  That halves the connections to Yahoo.
- **Dispatcher pacing** (verifier website). Customer domains hosted by Zoho, IONOS,
  OVHcloud, Hostinger, GoDaddy, Yandex 360, Google Workspace and Microsoft 365 now
  share their provider's pace, found from the domain's MX hosts. A list of 500 small
  businesses on Zoho is checked at Zoho's pace, not 500 separate ones.

## What each provider needs from the checker's server

- **Reverse DNS matching `RCH__HELLO_NAME`.** OVHcloud answers
  `450 4.7.1 Client host rejected: cannot find your reverse hostname`, and AOL/Yahoo
  `450 4.7.25 Forward-confirmed reverse DNS failed`, until it's set. IPv6 too.
- **A clean IP.** IONOS and GoDaddy (Microsoft 365) refuse IPs on Spamhaus lists.
- **GoDaddy's EU data centre.** Domains whose mailboxes live in Europe must use the
  `*.europe.secureserver.net` MX hosts; with US hosts, every address is rejected.
  That is the domain owner's setup, not something the checker can fix.

Catch-all domains (common on IONOS, OVHcloud and Hostinger when the owner turns on
"catch-all") stay `risky`: SMTP can't tell their mailboxes apart.

## Deploy

Engine (from its checkout on the server):

```bash
git pull
cargo test -p check-if-email-exists --lib --locked -- smtp:: rules::
SQLX_OFFLINE=true cargo build --release --bin reacher_backend --locked
sudo systemctl restart verifier-engine
```

The dispatcher change is in the verifier website repository and needs no migration:
pull, then restart the dispatcher service.

## Confirm

From the server, check one made-up and one real address for a Yandex and an AOL
domain. Made-up ones should be `invalid` with the provider's reply in
`debug.smtp.probes`, and an AOL check should show `catch_all_skipped: true`. The
dispatcher's start-up log lists the hosting providers it paces:
`zoho/ovh/ionos/hostinger/godaddy every 15s`. Previously saved results don't
change; recheck old `unknown` rows.
