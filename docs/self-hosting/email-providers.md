# Email providers

All of these are checked over SMTP, like any other domain. What differs is how
each one says "no such mailbox", and what it expects from the checker's server.

| Provider | MX hosts | Missing mailbox reply | Result |
| --- | --- | --- | --- |
| Yandex (yandex.ru/.com, Yandex 360) | `mx.yandex.ru`, `mx.yandex.net` | `550 5.7.1 No such user!` | `invalid` (fixed, was `unknown`) |
| AOL, AIM, Yahoo | `*.yahoodns.net` | None: `250 recipient ok` for every address | `risky` (can't be confirmed over SMTP) |
| Zoho Mail | `mx.zoho.*`, `smtpin.zoho.*` | `550 5.1.1 User does not exist` | `invalid` |
| IONOS (1&1) | `mx00.ionos.*`, `mx01.ionos.*` | `550 Requested action not taken: mailbox unavailable` | `invalid` |
| OVHcloud MX Plan | `mx*.mail.ovh.net` | `550 5.1.1 … Recipient address rejected: User unknown in virtual mailbox table` | `invalid` |
| Hostinger | `mx1.hostinger.com`, `mx2.hostinger.com` | `550 5.1.1 … Recipient address rejected: User unknown` | `invalid` |
| GoDaddy Workspace | `smtp.secureserver.net`, `mailstore1.secureserver.net` | `550 5.1.1 … Recipient not found` | `invalid` |
| GoDaddy Microsoft 365 | `*.mail.protection.outlook.com` | `550 5.4.1 Recipient address rejected: Access denied` | `invalid` |
| Proton Mail | `mail.protonmail.ch`, `mailsec.protonmail.ch` | `550 5.1.1 … Recipient address rejected: Address does not exist` | `invalid` |
| Namecheap Private Email | `mx1.privateemail.com`, `mx1.jellyfish.systems` | `450 4.1.1 … unverified address: Mailbox might be disabled, full, or may not exist` | `invalid` (fixed, was `unknown`) |
| Fastmail | `in1-smtp.messagingengine.com` | `550 5.1.1 … User unknown in local recipient table` | `invalid` |
| Rackspace Email | `mx1.emailsrvr.com`, `mx2.emailsrvr.com` | `550 5.1.1 … User unknown in relay recipient table` | `invalid` |
| GMX, web.de, mail.com | `mx00.gmx.net`, `mx00.mail.com` | `550 Requested action not taken: mailbox unavailable` | `invalid` |
| Migadu | `aspmx1.migadu.com`, `mx.migadu.com` | `550 5.1.1 … User unknown` | `invalid` |
| Purelymail | `mailserver.purelymail.com` | Greylists first (`451 4.7.1 Try again later`), then `550 5.1.1` | `invalid` after a retry (fixed) |

The Yandex, Zoho, GoDaddy Microsoft 365, Proton, Namecheap and Purelymail replies
were seen live from their servers. The others come from each provider's documentation and bounce reports, and
are covered by tests.

## What changed

- **Yandex.** It reports a missing mailbox under the policy code `5.7.1`. Every
  `5.7.x` reply used to count as a policy refusal, and the random catch-all address
  gets this reply first, so every Yandex address came back `unknown`, real or not.
  A `5.7.x` reply whose wording only ever means "no such mailbox" ("no such user",
  "user unknown", "email doesn't exist"…) now counts as a missing mailbox, unless it
  also blames the checker's IP. Gmail's `5.7.1 Email doesn't exist` uses the same rule.
- **AOL and Yahoo.** Yahoo's servers, which also host aol.com, aim.com, ymail.com and
  rocketmail.com, answer `250 recipient ok` for any address. They reject unknown
  mailboxes only after a message is sent (`554 … This user doesn't have a aol.com
  account`), which the checker never does. The catch-all probe therefore runs for
  them, sees a made-up address accepted, and marks every address `risky`.
  An earlier version skipped that probe for Yahoo's servers (and the original
  project for yahoo.com and yahoo.fr), so every AOL and Yahoo address showed `safe`,
  real or not. Recheck AOL and Yahoo rows saved as `safe` while that version ran.
  The "doesn't have a … account" wording is still read as `invalid` if a server
  ever sends it at `RCPT TO`.
- **Namecheap Private Email.** Its servers use Postfix's recipient verification,
  which refuses an address its mailbox server rejected with a *temporary* `450 4.1.1
  … unverified address`. The catch-all probe got that reply first and stopped, so
  every Namecheap address came back `unknown`. That reply now means the probed
  address can't receive mail: the made-up address shows the domain isn't catch-all,
  and the real one is `invalid` if it gets the same reply. "Address verification in
  progress" still counts as "try again later".
- **Greylisting (Purelymail and many small servers).** A greylisting server turns
  away each new sender/recipient pair until it's retried a few minutes later. The
  catch-all probe used a new random address every time, so it never got through.
  The made-up address is now the same for a domain every time, so the dispatcher's
  retries after 10 and 30 minutes get an answer.
- **Dispatcher pacing** (verifier website). Customer domains hosted by Zoho, IONOS,
  OVHcloud, Hostinger, GoDaddy, Yandex 360, Google Workspace and Microsoft 365 now
  share their provider's pace, found from the domain's MX hosts. A list of 500 small
  businesses on Zoho is checked at Zoho's pace, not 500 separate ones.

## What each provider needs from the checker's server

- **Reverse DNS matching `RCH__HELLO_NAME`.** OVHcloud answers
  `450 4.7.1 Client host rejected: cannot find your reverse hostname`, and AOL/Yahoo
  `450 4.7.25 Forward-confirmed reverse DNS failed`, until it's set. IPv6 too.
- **A clean IP.** IONOS, GoDaddy (Microsoft 365), Fastmail and Rackspace refuse IPs on
  Spamhaus lists (`554 5.7.1 … blocked using xbl.spamhaus.org` or `Spamhaus PBL`), and
  GMX refuses them at connection (`421 … Service not available`). Migadu also needs
  reverse DNS, over IPv6 too.
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

From the server, check one made-up and one real Yandex address: the made-up one
should be `invalid` with `550 5.7.1 No such user!` in `debug.smtp.probes`. Any AOL
address should be `risky`, with `is_catch_all: true` and `catch_all_skipped: false`. The
dispatcher's start-up log lists the hosting providers it paces:
`zoho/ovh/ionos/hostinger/godaddy every 15s`. Previously saved results don't
change; recheck old `unknown` rows.
