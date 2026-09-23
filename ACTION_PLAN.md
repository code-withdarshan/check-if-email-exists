# Project review and basic action plan

Reviewed on 2026-09-23 against fork commit `81da93e`.

Working assumption: first get the existing email-verification service running reliably, then decide whether to build a user-facing product around it.

## What the project contains

This is Reacher's Rust email-verification engine. The workspace has four crates:

| Component | Purpose | Main entry point |
| --- | --- | --- |
| `core` | Syntax, DNS/MX, provider checks, SMTP probing, and result classification | [core/src/lib.rs](core/src/lib.rs) |
| `backend` | Warp HTTP API, configuration, storage, throttling, and RabbitMQ workers | [backend/src/main.rs](backend/src/main.rs) |
| `cli` | Checks one address directly from the machine and prints JSON | [cli/src/main.rs](cli/src/main.rs) |
| `sqs` | Alternative AWS Lambda/SQS execution path, with Terraform and container setup | [sqs/src/main.rs](sqs/src/main.rs) |

The core, backend, and CLI declare version `0.11.7`; SQS declares `0.11.6`. There is no application frontend, user-account system, billing system, or tenant authorization layer in this workspace. The hosted dashboards mentioned in the docs are separate products.

The repository includes SQL migrations, cached SQLx query metadata, Docker definitions, CI workflows, and API documentation. Its [license file](LICENSE.md) describes an AGPL/commercial dual-license model.

## How verification works

1. Parse the email, extract its domain, and calculate a normalized address.
2. Look up MX records. Invalid syntax and absent MX records return early; DNS failures can produce `unknown`.
3. Gather disposable, role-account, and consumer-provider flags. Gravatar and breach checks are optional core/CLI capabilities; the HTTP request type does not expose them.
4. Select the lowest-preference-number MX and choose the verification method by provider. Gmail and most domains use SMTP; consumer Outlook and Yahoo default to browser-based account-recovery checks through ChromeDriver. Yahoo also has an optional HTTP method.
5. For SMTP, inspect `MAIL FROM`/`RCPT TO` responses and optionally probe a random recipient for catch-all behavior. The SMTP path does not send a message body.
6. Return `safe`, `risky`, `invalid`, or `unknown`, with detailed syntax, MX, SMTP, miscellaneous, and timing fields.

These results are estimates based on provider responses. Live accuracy, provider-page compatibility, and performance were not established by this review. Browser-based checks interact with recovery pages and should be validated separately using controlled accounts.

## API and runtime map

| Interface | Behavior | Requirements |
| --- | --- | --- |
| `POST /v0/check_email` | Legacy immediate verification, bypassing the newer throttle/storage workflow | Backend and verification dependencies |
| `POST /v1/check_email` | Direct check, or high-priority queue request when workers are enabled | Backend; RabbitMQ and PostgreSQL in worker mode |
| `POST /v1/bulk` | Creates a job and publishes one task per input address | Worker mode, RabbitMQ, PostgreSQL |
| `GET /v1/bulk/{id}` | Progress and outcome counts | Worker mode and PostgreSQL |
| `GET /v1/bulk/{id}/results` | JSON or CSV results after completion | Worker mode and PostgreSQL |
| `/v0/bulk...` | Separate legacy queue implementation using `sqlxmq` | PostgreSQL; `RCH_ENABLE_BULK=1` starts its consumer |

Configuration comes from [backend/backend_config.toml](backend/backend_config.toml), overridden by `RCH__...` environment variables. Source runs must locate that configuration file; the Makefile runs from `backend/`. PostgreSQL migrations run when the storage connection is initialized. Storage is optional for direct checks.

Direct SMTP needs usable outbound SMTP connectivity, normally port 25. SOCKS5 proxies are supported for SMTP. Default Outlook/Yahoo browser checks also need Chrome and ChromeDriver. The Docker backend includes a browser startup script. Worker mode uses a shared RabbitMQ queue with configurable concurrency; throttling is held in each process's memory.

## Original findings (before implementation)

These are source-review findings, not runtime reproductions.

| Priority | Finding and consequence | Evidence |
| --- | --- | --- |
| High | Bulk progress/results GET routes in both API versions omit the shared-secret filter. Configuring a secret therefore does not protect all job reads. | [v1 progress](backend/src/http/v1/bulk/get_progress.rs), [v1 results](backend/src/http/v1/bulk/get_results/mod.rs), [v0 progress](backend/src/http/v0/bulk/get.rs), [v0 results](backend/src/http/v0/bulk/results/mod.rs) |
| High | Workers acknowledge messages before saving results. A later database or reply failure can leave a job incomplete without a queued task to recover. | [worker/do_work.rs](backend/src/worker/do_work.rs), `do_check_email_work` |
| High | CSV conversion reads `mx.accepts_email`, while the core emits `mx.accepts_mail`. Normal results therefore fail this conversion. | [CSV helper](backend/src/http/v1/bulk/get_results/csv_helper.rs), [MX serialization](core/src/mx/mod.rs) |
| High | Default SMTP timeout and throttle limits are unset. Direct checks increment counters after verification, allowing concurrent requests to pass the same limit check. Queue-backed single checks also have no explicit reply deadline. | [configuration](backend/backend_config.toml), [single-check handler](backend/src/http/v1/check_email/post.rs), [throttle manager](backend/src/throttle.rs) |
| Medium | The RabbitMQ consumer runs in a detached task; decoding/consumer errors can end that task without stopping the HTTP server. Throttled bulk tasks immediately requeue without a delay. | [worker/consume.rs](backend/src/worker/consume.rs) |
| Medium | Bulk job creation and queue publication are separate operations, with no task identifier used to deduplicate stored results. Webhooks run before final retry decisions and do not reject non-success HTTP status codes. | [bulk submission](backend/src/http/v1/bulk/post.rs), [worker/do_work.rs](backend/src/worker/do_work.rs), [schema](backend/migrations/20240929230957_v1_worker_results.up.sql) |
| Medium | Failed tasks are stored with a nullable `result` and an `error`, but result export reads only `result` as a non-null JSON value. Failure outcomes need an explicit export representation. | [PostgreSQL storage](backend/src/storage/postgres.rs), [result export](backend/src/http/v1/bulk/get_results/mod.rs) |
| Medium | The HTTP input conversion does not forward the configured WebDriver address. Several per-request SMTP overrides are ignored unless a proxy is supplied. | [request conversion](backend/src/http/v0/check_email/post.rs), `to_check_email_input` |
| Medium | Syntax validation and disposable detection both call `mailchecker::is_valid`; test whether disposable addresses are incorrectly rejected as malformed. Classification also gives role/catch-all flags precedence over an undeliverable result, so its intended precedence needs explicit tests. | [syntax](core/src/syntax/mod.rs), [miscellaneous checks](core/src/misc/mod.rs), [classification](core/src/lib.rs) |
| Medium | Setup examples have drifted: README uses an older library API; Compose uses `RCH__WORKER__THROTTLE__...` although throttle settings are top-level. Config comments describe limits that are commented out. | [README](README.md), [Compose](rabbitmq/docker-compose.yaml), [configuration](backend/src/config.rs) |

Additional follow-up: redact database/proxy secrets from debug logs and stored task payloads; bound job size and export size; review browser cleanup and blocking sleeps. The SQS handler loads configuration without calling `connect()`, leaving its storage adapter uninitialized, and assumes a one-message batch. The current database-pruning utility targets legacy tables, and its deletes use the pool rather than the transaction it opens.

## Basic action plan

| Order | Work | Completion check |
| --- | --- | --- |
| 1. Establish a runnable baseline | Use a Linux container environment for the first baseline; document the Rust/toolchain setup, SQLX offline mode, configuration location, and ChromeDriver requirement. Build the local source and start only the direct API first. Set an explicit secret and finite timeout. | A clean build, passing applicable checks, an invalid-syntax request, and a controlled verification request all work through `/v1/check_email`. |
| 2. Fix access and correctness | Protect all bulk reads; repair CSV field mapping and failed-task exports; forward WebDriver configuration; define request-override and classification behavior. Correct the README and Compose environment variables. | Regression tests cover missing/wrong secrets, JSON-to-CSV conversion, failure exports, configuration overrides, and result classification. |
| 3. Make queued processing reliable | Add task IDs and idempotent storage; persist results before acknowledging tasks; recover partial publication; supervise the consumer; add deadlines, delayed retries, and terminal failure handling. Separate webhook delivery retries from verification retries. | Broker/worker restarts, malformed messages, database failures, and webhook failures do not silently lose tasks or double-count completed work. |
| 4. Validate bulk operation | Run backend, PostgreSQL, RabbitMQ, and browser dependencies together. Use atomic throttle admission, bounded concurrency, and explicit batch/export limits. Separate deterministic tests from live provider smoke tests. | A small mixed batch completes with correct progress, one terminal outcome per input, working JSON/CSV downloads, and demonstrated rate limits. |
| 5. Prepare deployment and integration | Add dependency health checks, graceful shutdown, persistent service volumes, backup/retention procedures, and metrics for latency, unknown results, queue depth, and failures. Pin tested build/runtime versions. Integrate the API into the intended application after these checks pass. | A repeatable deployment and recovery checklist exists, and a consumer application can use the API without exposing its shared secret. |

The first implementation milestone should be a reproducible local `/v1/check_email` service with a tested request/response contract. RabbitMQ bulk processing follows once the direct path and the high-priority fixes are verified. Work on the SQS alternative can follow separately if AWS Lambda is part of the intended deployment.

## Implementation progress recorded on 2026-09-23

Step 2 code changes are committed on `fix/step2-access-correctness`:

- Bulk progress/results GET routes (v0 and v1) now require the shared secret.
- One CSV exporter ([backend/src/http/csv.rs](backend/src/http/csv.rs)) reads `mx.accepts_mail`, leaves missing checks empty, and exports failed tasks with their error. v1 result export no longer reads NULL `result` rows as values, and `limit` is capped at 10,000.
- The WebDriver address and per-request SMTP overrides (`from_email`, `hello_name`, `smtp_timeout`, `smtp_port`) are forwarded without a proxy.
- `POST /v1/check_email` reserves throttle capacity atomically (`ThrottleManager::try_acquire`), caps concurrent direct checks (`max_concurrency`), and applies `request_timeout` to direct and queue-reply paths (504 on expiry). Defaults: `smtp_timeout = 45`, 60/minute, 10,000/day.
- Classification: explicit SMTP rejection now outranks role/disposable/catch-all flags; a full inbox stays `risky`.
- Syntax validation no longer rejects disposable domains, so `is_disposable` can be reported.
- Database URLs are no longer logged. The Compose throttle variable and README library example are corrected.

Verification: `cargo test -p check-if-email-exists --lib` passes (20 passed, 4 ignored). The initial Windows backend check was blocked by missing Perl modules. That dependency blocker and a Unix-only reactor compile error are now fixed; see "Windows OpenSSL build setup" below. Docker verification is recorded separately below.

Still open from step 2: the worker path (`worker/consume.rs`) keeps the non-atomic `check_throttle` + `increment_counters` pair, and `/v0/check_email` bypasses throttling. Both belong with step 3/4.

Local toolchain notes: `target/dev-tools` has Rust 1.85.1 (GNU) and MinGW. Set `CARGO_HOME`/`RUSTUP_HOME` to it and `CMAKE_POLICY_VERSION_MINIMUM=3.5` (bundled CMake 4.4 rejects `aws-lc-sys`).

## Remaining work (re-audit of `5c3626f`)

The current branch is `fix/step2-access-correctness`. The earlier progress notes described a draft; those changes are now committed. This section supersedes the original findings for current status.

Implemented in code: bulk-read authentication, shared CSV conversion and failure export, request configuration forwarding, disposable-address syntax handling, classification precedence, atomic direct-request admission, direct concurrency limits, HTTP deadlines, default SMTP limits, and the README/Compose configuration corrections.

Still required, in priority order:

| Priority | Remaining work | Evidence / completion condition |
| --- | --- | --- |
| Done | Build and test the backend, then start the local API. | Done 2026-09-23 via Docker Desktop, see "Backend verification" below. Worker mode remains untested. |
| Done | Fix worker-mode throttle accounting. | The HTTP handler reserves only in direct mode; the [consumer](backend/src/worker/consume.rs) reserves atomically with `try_acquire`. The non-atomic `check_throttle`/`increment_counters` API is removed. See "Worker-mode verification". |
| Done | Persist results before acknowledging queue messages, with stable task IDs and idempotent inserts. | [do_check_email_work](backend/src/worker/do_work.rs) stores, then acks; on storage failure bulk tasks are requeued and single-shot callers still get a reply. Tasks carry an optional `task_id` (UUID; absent on older messages); migration `20260923120000_v1_task_result_task_id` adds a unique `task_id` column and inserts use `ON CONFLICT (task_id) DO NOTHING`. See "Worker-mode verification". |
| P1 | Make bulk submission recoverable and message delivery durable. | [bulk submission](backend/src/http/v1/bulk/post.rs) creates the job before publishing tasks, and message properties do not set persistent delivery. Add a database outbox or equivalent recovery, publisher confirmation handling, and stable task identity. Test interruption midway through submission and broker restart. |
| P1 | Supervise workers, handle malformed messages, and back off retries. | [consumer](backend/src/worker/consume.rs) has detached tasks, propagation of decode errors, and immediate requeue during throttling. Surface worker death in readiness, bound retry attempts, and retain terminal failures. |
| P1 | Apply deadlines to worker execution and webhooks, with cleanup on cancellation. | The new HTTP timeout does not bound a queued task's lifetime. [Worker execution](backend/src/worker/do_work.rs) needs its own deadline; temporary RPC consumers/queues and browser sessions need cleanup after timeout or disconnect. |
| P1 | Separate webhook delivery from verification retries. | [Webhook helper](backend/src/worker/do_work.rs) sends before the retry decision, has no explicit request timeout, and does not reject HTTP failure statuses. Persist a final verification result and retry delivery independently with an idempotency key. |
| P1 | Complete bulk limits and result accounting. | Submission still accepts up to a 50 MB JSON body without an address-count limit. Failed-task rows count toward processed totals but are omitted from outcome counts in [progress](backend/src/http/v1/bulk/get_progress.rs). Define failed/unknown accounting, cap input counts, and document paginated CSV exports. Legacy v0 exports remain unbounded. |
| P1 | Add and run route and failure-path regression tests. | Current backend integration tests exercise v0 single checks. Add all bulk-read missing/wrong/correct-secret cases, v1 429/504/concurrency tests, database-backed failed-result exports, and broker/database/webhook interruption tests. Separate deterministic tests from live provider tests. |
| P1 | Make the deployment definition run this fork's code. | [Compose](rabbitmq/docker-compose.yaml) still uses upstream `reacherhq/backend:beta`, so starting it will not exercise these fixes. Build the local Dockerfile or use an image built from this fork; add readiness checks, explicit named data volumes, supplied secrets, and controlled service exposure. |
| P2 | Finish production operations. | Add graceful shutdown, queue/error/latency metrics, backup and recovery steps, v1 result retention, pinned tested toolchains/images, and a verified deployment runbook. |
| P2 | Finish secret handling, browser lifecycle, and legacy maintenance. | Full task payloads, including configured credentials, are still serialized by [PostgreSQL storage](backend/src/storage/postgres.rs). Browser paths retain blocking sleeps and only close sessions on successful completion. [prune_db](backend/src/bin/prune_db.rs) targets legacy tables and executes deletes outside its opened transaction. Decide whether to restrict or retire unthrottled v0 checks. |
| Optional | Repair and validate the AWS SQS alternative if it is selected for deployment. | [SQS handler](sqs/src/main.rs) still omits storage initialization, logs full configuration, assumes a one-message batch, and lacks shared throttle handling. |

Recommended next milestone: a successful backend build plus regression tests for worker throttle accounting and storage-before-ack behavior. Run a small controlled batch through this fork's own container image before considering deployment complete.

Initial audit verification: `cargo fmt --all -- --check` and `git diff --check` passed. The first Windows backend check failed while building vendored OpenSSL because Git for Windows Perl could not load `Locale::Maketext::Simple`; its historical log is in `target/remaining-backend-check.log`. The Windows build blocker is now resolved as documented below. No live mailbox checks or deployed-service changes were made during this re-audit.

## Backend verification (2026-09-23, Docker Desktop)

- `docker build -f backend/Dockerfile -t reacher-backend:local .` builds this fork's backend (musl release) with no warnings in changed files.
- Backend unit tests in `messense/rust-musl-cross:x86_64-musl` (`SQLX_OFFLINE=true`, `cargo test -p reacher_backend --lib`): 13 passed, 0 failed, including the CSV, failed-export, override-forwarding and concurrent-throttle tests.
- Local smoke test (`docker run -p 8080:8080 -e RCH__HEADER_SECRET=... reacher-backend:local`, direct mode): requests without the secret to `/v1/check_email` and `/v1/bulk/1` were rejected (400). With the secret: `not-an-email` → `invalid` (0.5 s); a nonexistent Gmail address → `invalid` via a live Gmail SMTP rejection (2.4 s); `someone@mailinator.com` → `is_disposable: true`, `unknown` (Mailinator refuses SMTP probes).
- The host network allows outbound port 25 over IPv4 and IPv6. Outlook/Yahoo browser checks, catch-all domains, the 429/504 paths, and worker mode were not exercised.

## Worker-mode verification (2026-09-23, Docker Desktop)

Backend image rebuilt from this branch and run in worker mode against `rabbitmq:3.13-alpine` and `postgres:16-alpine` on a private Docker network.

- Backend unit tests: 15 passed, including `redelivered_task_stores_one_result` run against real PostgreSQL (`TEST_DATABASE_URL` set) and `decodes_messages_published_without_task_id`. `reacher_sqs` still compiles.
- Throttle accounting: with 2 requests/minute, two single-shot `/v1/check_email` requests returned 200 and the third returned 429. Previously the HTTP handler and the worker each counted a request.
- Bulk flow: a 3-address job reached `Completed` (3/3, 3 invalid); the CSV export returned 3 rows; the database held 3 rows with 3 distinct task IDs.
- Store-before-ack: with 1 request/minute, PostgreSQL was stopped after the first task. The next task logged "Requeued message after storage failure" and the queue kept 2 messages. After PostgreSQL restarted, the job completed with exactly one row per address and an empty queue.
- Observed, not fixed (P1 retry/backoff item): throttled and storage-failed bulk tasks are requeued immediately, so the consumer spins while waiting, and each failed storage attempt consumes throttle capacity.

## Windows OpenSSL build setup

The missing Perl dependencies are installed under the ignored `target/dev-tools/perl-modules` directory. [ci/windows-build-env.ps1](ci/windows-build-env.ps1) restores the six pinned CPAN modules with SHA-256 checks, configures Git for Windows' Perl, preserves its module paths across native `make`, and supplies the `make.exe` name OpenSSL requires. It uses the existing project-local Rust/MinGW tools; it does not install those tools or change the system PATH.

Run from the repository root in each new PowerShell session:

```powershell
. .\ci\windows-build-env.ps1
cargo check -p reacher_backend --locked --offline
```

The script also sets SQLx offline mode and the CMake compatibility option required by the installed toolchain. Restoring absent Perl modules requires internet access; cached modules work offline.

Verified on Windows (2026-09-23): `cargo check -p reacher_backend --locked --offline` and `cargo fmt --all -- --check` pass. OpenSSL builds successfully. The check exposed an additional Unix-only Tokio reactor override in [worker/consume.rs](backend/src/worker/consume.rs); it is now conditional on Unix, allowing Windows to use Lapin's default reactor. Existing compiler warnings remain. This verifies compilation, not RabbitMQ runtime behavior or Windows backend tests. Build output: `target/backend-check-perl.log`.

## Review limits and Git connection

- The source inventory contains 66 Rust files and approximately 9,063 Rust lines. The review traced the main engine, API versions, worker/storage flows, CLI/SQS entry points, configuration, tests, and deployment definitions.
- The OpenAPI JSON and 15 SQLx cache JSON files parsed successfully. This checks their JSON syntax, not their consistency with a running database or API.
- At the initial review, Rust/Cargo and Docker were not available on PATH. A project-local toolchain was subsequently installed and core tests were recorded as passing; backend and deployment verification remain incomplete.
- Existing integration tests mainly cover `/v0/check_email`; browser tests are ignored by default. The v1 worker/export failure cases need dedicated coverage.
- The folder originally had no Git metadata. It is now connected to `https://github.com/code-withdarshan/check-if-email-exists.git`, with local `master` tracking `origin/master`. No source changes were required to attach the fork.
