# Project audit — 6 October 2026

Reviewed commit: `e839ba18d43eaba0f4664907bf9adab2d4fa307b`.

Scope: Rust core, v0/v1 HTTP API, CLI, RabbitMQ workers, PostgreSQL storage,
SQS/Lambda, deployment configuration, and the web UI. This is a source review
plus local tests, not certification that every feature or deployment is safe.
The findings below describe that commit; fixes applied afterwards are listed
under "Remediation status".

## Remediation status (applied after the audit)

The three backend security regressions are no longer ignored and pass, as do all
seven UI checks. Workspace suite: core 62 passed / 4 ignored, backend 24 unit +
6 audit + 6 HTTP integration + 1 doc test, all passing.

| # | Status | Change |
| --- | --- | --- |
| 1 | Fixed | `smtp::is_valid_hello_name` (hostname or address literal). The API returns 400; the request conversion ignores unsafe values; core refuses to open SMTP with one. |
| 2 | Partly fixed | Webhooks: http(s) only, every resolved address must be public, connection pinned to the checked addresses (no DNS rebinding), redirects off. Opt-in `worker.allow_private_webhooks`. **Open:** MX addresses and caller proxy/port overrides are still not range-checked. |
| 3 | Fixed | v0 now applies the throttle, concurrency semaphore and request deadline. |
| 4 | Partly fixed | Bulk tasks are persistent (delivery mode 2); the channel uses publisher confirms; publishes are `mandatory` and a Nack/return is an error; a partial submission is logged and reported with the job ID. **Open:** no transactional outbox/reconciliation. |
| 5 | Fixed | Worker wraps `check_email` in `request_timeout`; a timeout is stored as a terminal error (not requeued). Caller `smtp_timeout` is capped at `request_timeout`. Single-shot messages expire after `request_timeout`. **Open:** headless-browser session cleanup on cancel not verified. |
| 6 | Fixed | SQS loads and `connect()`s the config once at start-up and reuses it. |
| 7 | Fixed | Config debug logging removed; Lambda `RUST_LOG` is `info`. Rotate any credentials that may already be in CloudWatch. |
| 8 | Fixed | Backend CSV export prefixes `'` to cells starting with `= + - @`, tab or CR. |
| 9 | Fixed | UI keeps the full RFC 5322 local part, matches only at separators, and strips only wrappers (`mailto:`, `<>`, matching quotes, trailing punctuation). |
| 10 | Fixed | UI reports `mx.error` as an inconclusive DNS failure; only `accepts_mail: false` means no mail server. |
| 11 | Fixed | Catch-all cache is keyed by domain plus route (proxy, port, HELO name, sender). |

None of this has been exercised against live RabbitMQ, PostgreSQL, AWS or a browser.

## Verification

| Check | Result |
| --- | --- |
| Existing workspace suite, all features, locked/offline | 88 reported passed, 0 failed, 4 ignored |
| New backend audit suite, explicitly including known failures | 3 passed, 3 failed |
| New UI pure-function tests | 4 passed, 3 failed |
| CLI `--help` and invalid-address JSON output | Passed |
| Rust formatting of the new regression file | Passed |

The existing suite includes 60 core tests, 21 backend unit tests, 6 HTTP integration
tests and 1 documentation test. **One of those 88 reported passes is a database
test that returns early:** `TEST_DATABASE_URL` is unset, so actual PostgreSQL
idempotency was not tested. Four provider/network tests are explicitly ignored.
CLI and SQS targets compile under the workspace test command but contain no tests.
The CLI was also built and run separately: `--help` exits successfully and
`not-an-email` returns parseable JSON with `is_reachable: "invalid"`.
The workspace run started before the new audit target was added; that target was
built and executed separately.

The three backend failures establish findings 1–3: the formatter emits
`EHLO audit.example\r\nNOOP\r\n`; the local HTTP receiver records one webhook;
and the exhausted-quota v0 request returns HTTP 200 instead of 429. The three UI
failures establish findings 9–10. Remaining findings are based on source inspection,
with runtime limitations stated individually.

Raw evidence is in `target/audit-2026-10-06/workspace-tests.log`,
`target/audit-2026-10-06/security-regressions.log`, and
`target/audit-2026-10-06/ui-tests.log` (local build artifacts, not tracked by Git).
CLI outputs are saved as `cli-help.log` and `cli-invalid.log` in the same directory.

| Feature area | Coverage achieved |
| --- | --- |
| Syntax, normalization, typo suggestions, role/disposable/free-provider flags | Existing unit tests passed |
| MX validation and sending-setup diagnostics | Unit tests passed; one existing DNS-dependent API integration passed; production sending setup not tested |
| SMTP delivery, full/disabled inboxes, catch-all, reply codes, retries, backup MX, timeout and connection isolation | Existing local scripted SMTP tests passed |
| Proxy/provider configuration | Configuration tests passed; live proxy routing not exercised |
| v0/v1 auth, payload limits, v1 concurrency quota | New local Warp route tests passed; legacy bypass reproduced |
| Health/version/configuration/usage | Existing unit tests passed |
| RabbitMQ bulk creation, progress, JSON/CSV export and recovery | Source review and helper tests; complete service integration blocked |
| Webhooks | Existing retry test passed; localhost access reproduced |
| CLI | Built; help and invalid-input smoke checks passed |
| SQS/Lambda | Compiled and source-reviewed; live invocation not tested |
| UI CSV parsing, metadata, escaping, formula guard and explanations | Seven pure-function tests; four passed, three failed |
| Browser flows, deployment, Gravatar, HIBP and provider headless flows | Source-reviewed; end-to-end runtime verification incomplete |

Reproduce the local checks from the repository root on Windows:

```powershell
# Use a process-scoped script policy if required by your local PowerShell setup.
. ./ci/windows-build-env.ps1
cargo test --workspace --all-features --locked --offline --no-fail-fast
cargo test -p reacher_backend --test audit_regressions --locked --offline -- --include-ignored
node --test ci/audit-ui.cjs
```

Known security regression tests are ignored during ordinary Cargo runs. Explicitly
including them is expected to fail until the corresponding protections are added.
The UI checks execute pure functions extracted from the actual HTML source; they
do not simulate or verify browser interaction.

## Findings, in priority order

### 1. High — Request-controlled `hello_name` injects SMTP commands

- Evidence: `backend/src/http/v0/check_email/post.rs:81` copies the request's
  `hello_name` without validating control characters. Both API versions use this
  conversion. `core/src/smtp/connect.rs:98` supplies it to `ClientId::Domain`.
  The installed async-smtp 0.9.2 `EhloCommand` formatter writes this string verbatim.
- Local regression: `security_request_hello_name_must_not_inject_smtp_commands`.
  The harmless input `audit.example\r\nNOOP` produces two SMTP command lines.
  This test checks request deserialization, configuration conversion and the actual
  dependency formatter; it does not send commands to a real mail server.
- Impact: an API caller can insert additional protocol commands into the backend's
  SMTP connection. Exposure depends on access to the API and outbound network.
- Fix: reject CR/LF and invalid EHLO hostnames at the API and core boundaries;
  consider restricting identity overrides to trusted administrative configuration.

### 2. High — Caller-controlled outbound destinations permit SSRF

- Evidence: `backend/src/worker/do_work.rs:305` sends POST requests to arbitrary
  webhook URLs with caller-supplied headers. There is no destination allowlist or
  restriction on private, loopback or link-local addresses, or redirected targets.
- Local regression: `security_webhook_must_not_reach_loopback_by_default` runs a
  disposable loopback HTTP service and checks whether the webhook reaches it.
- Related source path: `core/src/smtp/connect.rs:54` connects to every resolved MX
  address without checking its network range. The API accepts arbitrary proxy
  hosts and SMTP ports (`backend/src/http/v0/check_email/post.rs:31`). Filtering
  the literal MX name `localhost` does not filter other names resolving internally.
  These SMTP/proxy paths were reviewed, not reproduced through a DNS-controlled domain.
- Impact: callers can make requests from the verifier's network to internal
  services; SMTP connections can also reach internal addresses. Authentication
  restricts who can invoke this capability but does not restrict destinations.
- Fix: allowlist webhook destinations, validate resolved addresses and redirects,
  restrict request proxy/port overrides, and enforce outbound network policy.
  Permit private destinations only through explicit trusted configuration.

### 3. High — v0 bypasses quotas, concurrency controls and the request deadline

- Evidence: `backend/src/http/v0/check_email/post.rs:140` calls `check_email`
  directly. The quota, semaphore and overall deadline exist only in the v1 path.
  `backend/src/http/mod.rs:45` always registers the legacy endpoint.
- Local regression: exhaust a one-request quota, then POST an invalid address
  to v0. The desired response is 429; the current handler accepts the request.
- Impact: anyone with backend API access can sidestep v1 limits by changing the
  URL. The supplied nginx UI exposes only selected v1 routes, which reduces
  exposure for deployments where the backend is inaccessible directly.
- Fix: apply shared safeguards to both versions or disable v0 explicitly.
  The configuration documents the old throttle exception, but the resource risk remains.

### 4. High — Accepted bulk jobs can lose tasks across broker failures

- Source-confirmed, broker restart not exercised here.
- Evidence: `backend/src/http/v1/bulk/post.rs:89` constructs properties without
  persistent delivery mode. `backend/src/worker/consume.rs:63` declares a durable
  queue, but queue durability does not make its individual messages persistent.
  No `confirm_select` call exists in backend code. `publish_task` awaits and
  discards the confirmation value, and uses default non-mandatory publishing.
- The job row is inserted before publishing (`post.rs:79`). A failure partway
  through the concurrent publishes leaves `total_records` counting unpublished
  tasks; there is no outbox/reconciliation or failed-submission state.
- Impact: a job can remain Running indefinitely with missing results, or tasks
  can continue after an HTTP submission fails and the client loses its job ID.
- Fix: persistent messages, enabled publisher confirms with ACK/NACK handling,
  unroutable-message handling, and a transactional outbox with idempotent dispatch.

### 5. High — HTTP timeout does not bound queued worker execution

- Source-confirmed, saturation test blocked by unavailable RabbitMQ/PostgreSQL.
- Evidence: `backend/src/http/v1/check_email/post.rs:222` times out the HTTP wait.
  `backend/src/worker/do_work.rs:156` independently awaits `check_email` with no
  total deadline. `backend/src/http/v0/check_email/post.rs:84` accepts a caller's
  SMTP timeout without a maximum. Legacy headless methods can also be requested.
- Impact: slow or malicious destinations can occupy all worker slots long after
  the client receives 504. A completed HTTP timeout does not cancel its queue task.
- Fix: clamp caller timeouts, add a worker-level total deadline, store a terminal
  timeout result, and expire stale single-shot tasks. Ensure browser sessions close
  when headless work is cancelled.

### 6. High — SQS ignores configured PostgreSQL result storage

- Source-confirmed; no AWS invocation or live database was used.
- Evidence: `sqs/src/main.rs:99` calls `load_config` and immediately wraps the
  result in `Arc`. It never calls `BackendConfig::connect`, unlike the backend
  executable. The skipped storage-adapter field defaults to Noop; the call to
  `store` at line 120 therefore succeeds without storing anything.
- Impact: a Lambda configured for PostgreSQL can report successful processing
  while silently dropping result persistence.
- Fix: initialize and reuse the required database adapter before processing;
  add an integration assertion that successful SQS processing creates a row.

### 7. High — Default SQS debug logging exposes configuration credentials

- Source-confirmed; no real credentials were printed during this audit.
- Evidence: `sqs/src/main.rs:100` logs `backend_config` with derived `Debug`.
  `sqs/main.tf:136` sets `RUST_LOG = "debug"`, and that template supplies proxy
  username/password. The configuration also supports header secrets, database
  URLs and trial tokens.
- Impact: configured credentials enter CloudWatch logs accessible to log readers.
- Fix: remove full configuration logging and redact secret-bearing types. Review
  existing logs and rotate exposed credentials if this configuration was deployed.

### 8. Medium — Backend CSV exports do not neutralize formulas

- Source-confirmed; no spreadsheet application was opened.
- Evidence: `backend/src/http/csv.rs:43` copies arbitrary input to the exported
  field unchanged. `backend/src/http/v1/bulk/get_results/mod.rs:169` serializes it
  directly. v0 shares this CSV representation. Bulk inputs need not have valid
  email syntax, so an input such as `=1+1` can survive into a results export.
- Impact: spreadsheet software may evaluate formula-like input or other text
  fields when a downloaded CSV is opened. CSV quoting alone is not neutralization.
  The web UI has a separate formula guard, which does not protect API exports.
- Fix: neutralize dangerous leading characters in every untrusted exported text
  cell; verify the resulting behavior in the supported spreadsheet applications.

### 9. Medium — UI import silently changes email addresses

- Reproduced by two tests in `ci/audit-ui.cjs`.
- Evidence: `deploy/ui/index.html:483` strips leading hyphens and apostrophes
  from mailbox names. `-sales@example.org` becomes `sales@example.org`.
  The extraction regex at line 481 is not a full-address parser:
  `alice!tag@example.org` becomes `tag@example.org`.
- Impact: the application verifies and exports a different mailbox from the one
  supplied, potentially creating false positives and contacting the wrong address
  when exported results are used downstream.
- Fix: preserve the original address; remove only unambiguous display wrappers.
  Parse complete tokens and flag unsupported syntax instead of taking substrings.

### 10. Medium — UI reports temporary DNS failures as nonexistent mail service

- Reproduced by `ci/audit-ui.cjs`.
- Evidence: `deploy/ui/index.html:371` treats every `mx.error` as proof the domain
  has no mail server. A response classified Unknown with a DNS timeout gets the
  explanation “The domain has no mail server, so it cannot receive email.”
- Impact: users can discard valid contacts because the explanation contradicts
  the uncertainty of the actual result; the same explanation is exported to CSV.
- Fix: distinguish lookup errors from a successful lookup establishing no MX;
  describe transient failures as inconclusive and retryable.

### 11. Medium — Catch-all cache is shared across verification configurations

- Source-confirmed; end-to-end cache poisoning was not reproduced.
- Evidence: `core/src/smtp/catch_all_cache.rs:47` keys entries only by domain for
  24 hours. `core/src/smtp/mod.rs:232` returns a cached result without using the
  current SMTP host, proxy, sender or port; line 264 records results from all
  configurations into that same cache. The HTTP API accepts caller-selected proxies.
- Impact: a catch-all answer obtained through one route affects other clients
  checking that domain through different routes. A caller-controlled proxy can
  supply misleading acceptance responses that influence subsequent checks.
- Fix: scope caching to trusted verification configuration and mail-server
  identity; do not populate a shared trusted cache from arbitrary caller proxies.

## Coverage limits and operational observations

- Docker CLI is available, but no Docker daemon is running. RabbitMQ/PostgreSQL
  integration, broker restarts, migrations against a live database, nginx auth,
  TLS deployment and complete UI-to-worker flows were not exercised.
- The Browser runtime reports no available browser. Upload/click/download,
  responsive layout and accessibility remain unverified in an actual browser.
- No live AWS deployment, paid HIBP request or headless provider account-recovery
  flow was exercised. Local mocked SMTP coverage is not evidence of live mailbox
  deliverability or sending-IP reputation.
- `cargo audit` is not installed. No dependency advisory clearance is claimed.
- `backend/backend_config.toml` binds localhost and leaves `header_secret`
  unset. The Dockerfile changes the bind address to all interfaces, while the
  deployment compose file supplies a required secret. Keep those different
  deployment conditions in mind when assessing API exposure.
- The selected `hello_name` value alone cannot establish that reverse DNS, sender
  DNS and the actual deployment IP agree. Those operational checks require the
  sending server; changing the value locally does not validate production DNS.

## Recommended remediation order

1. Validate SMTP identity strings and restrict outbound destinations.
2. Close the v0 resource-limit bypass and bound worker task duration.
3. Make bulk publishing durable/recoverable; initialize SQS storage and remove
   credential logging.
4. Correct CSV handling, UI address preservation, DNS explanations and cache scope.
5. Rerun the opt-in regressions, then execute the isolated broker/database harness
   and browser workflows before claiming full feature coverage.
