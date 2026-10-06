//! Local audit checks, including regression tests for the `security_` findings
//! in AUDIT_REPORT.md. No real mailbox or external service is contacted.
use std::collections::HashMap;
use std::sync::{
	atomic::{AtomicUsize, Ordering},
	Arc,
};

use check_if_email_exists::{CheckEmailInput, CheckEmailOutput};
use reacher_backend::config::BackendConfig;
use reacher_backend::http::create_routes;
use reacher_backend::worker::do_work::{
	send_webhook, CheckEmailJobId, CheckEmailTask, TaskWebhook, Webhook,
};
use warp::{http::StatusCode, test::request, Filter};

async fn config() -> Arc<BackendConfig> {
	let mut cfg = BackendConfig::empty();
	cfg.header_secret = Some("audit-secret".into());
	cfg.throttle.max_requests_per_minute = Some(1);
	cfg.connect().await.unwrap();
	Arc::new(cfg)
}

#[tokio::test]
async fn protected_routes_reject_missing_and_wrong_secrets() {
	let routes = create_routes(config().await);
	for (path, method) in [
		("/v0/check_email", "POST"),
		("/v1/check_email", "POST"),
		("/v0/bulk", "POST"),
		("/v1/bulk", "POST"),
		("/v1/bulk/1", "GET"),
		("/v1/bulk/1/results", "GET"),
		("/v1/usage", "GET"),
		("/v1/self_check", "GET"),
	] {
		for secret in [None, Some("wrong")] {
			let mut req = request().method(method).path(path);
			if let Some(secret) = secret {
				req = req.header("x-reacher-secret", secret);
			}
			let response = req
				.json(&serde_json::json!({"to_email":"invalid"}))
				.reply(&routes)
				.await;
			assert!(
				response.status().is_client_error(),
				"{method} {path}: {}",
				response.status()
			);
		}
	}
}

#[tokio::test]
async fn v1_quota_is_atomic_under_concurrent_requests() {
	let routes = create_routes(config().await);
	let responses = futures::future::join_all((0..10).map(|_| {
		request()
			.method("POST")
			.path("/v1/check_email")
			.header("x-reacher-secret", "audit-secret")
			.json(&serde_json::json!({"to_email":"invalid"}))
			.reply(&routes)
	}))
	.await;
	assert_eq!(
		responses
			.iter()
			.filter(|r| r.status() == StatusCode::OK)
			.count(),
		1
	);
	assert_eq!(
		responses
			.iter()
			.filter(|r| r.status() == StatusCode::TOO_MANY_REQUESTS)
			.count(),
		9
	);
}

#[tokio::test]
async fn empty_and_oversized_requests_are_rejected() {
	for path in ["/v0/check_email", "/v1/check_email"] {
		let routes = create_routes(config().await);
		let empty = request()
			.method("POST")
			.path(path)
			.header("x-reacher-secret", "audit-secret")
			.json(&serde_json::json!({"to_email":""}))
			.reply(&routes)
			.await;
		assert_eq!(empty.status(), StatusCode::BAD_REQUEST);
		let large = request()
			.method("POST")
			.path(path)
			.header("x-reacher-secret", "audit-secret")
			.json(&serde_json::json!({"to_email":"x".repeat(17000)}))
			.reply(&routes)
			.await;
		assert_eq!(large.status(), StatusCode::PAYLOAD_TOO_LARGE);
	}
}

#[tokio::test]
async fn security_legacy_endpoint_must_not_bypass_exhausted_quota() {
	let cfg = config().await;
	cfg.get_throttle_manager().try_acquire().await.unwrap();
	let response = request()
		.method("POST")
		.path("/v0/check_email")
		.header("x-reacher-secret", "audit-secret")
		.json(&serde_json::json!({"to_email":"invalid"}))
		.reply(&create_routes(cfg))
		.await;
	assert_eq!(
		response.status(),
		StatusCode::TOO_MANY_REQUESTS,
		"The legacy endpoint accepted a request after the configured quota was exhausted"
	);
}

#[tokio::test]
async fn security_webhook_must_not_reach_loopback_by_default() {
	let hits = Arc::new(AtomicUsize::new(0));
	let received = hits.clone();
	let route = warp::post().map(move || {
		received.fetch_add(1, Ordering::SeqCst);
		"ok"
	});
	let (addr, server) = warp::serve(route).bind_ephemeral(([127, 0, 0, 1], 0));
	let server_task = tokio::spawn(server);
	let task = CheckEmailTask {
		input: CheckEmailInput::default(),
		job_id: CheckEmailJobId::Bulk(1),
		task_id: None,
		webhook: Some(TaskWebhook {
			on_each_email: Some(Webhook {
				url: format!("http://{addr}/internal"),
				headers: HashMap::new(),
				extra: None,
			}),
		}),
	};
	let result = send_webhook(&task, &CheckEmailOutput::default()).await;
	server_task.abort();
	assert_eq!(
		hits.load(Ordering::SeqCst),
		0,
		"User-supplied webhook URL reached a loopback-only HTTP service; result: {result:?}"
	);
}

#[test]
fn security_request_hello_name_must_not_inject_smtp_commands() {
	use async_smtp::{commands::EhloCommand, extension::ClientId};
	use check_if_email_exists::smtp::verif_method::GmailVerifMethod;
	use reacher_backend::http::CheckEmailRequest;
	let request: CheckEmailRequest = serde_json::from_value(serde_json::json!({
		"to_email": "audit@example.org",
		"hello_name": "audit.example\r\nNOOP"
	}))
	.unwrap();
	let input = request.to_check_email_input(Arc::new(BackendConfig::empty()));
	let GmailVerifMethod::Smtp(smtp) = input.verif_method.gmail;
	let wire = EhloCommand::new(ClientId::Domain(smtp.hello_name)).to_string();
	assert_eq!(
		wire.matches("\r\n").count(),
		1,
		"The actual SMTP command formatter emits an injected command: {wire:?}"
	);
}
