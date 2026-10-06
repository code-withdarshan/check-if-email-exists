//! Run against a disposable PostgreSQL database with TEST_ACCOUNT_DATABASE_URL.
use super::*;
use crate::config::{PostgresConfig, StorageConfig};

#[derive(Clone)]
struct Browser {
	cookie: String,
	csrf: String,
}
impl Default for Browser {
	fn default() -> Self {
		Self {
			cookie: String::new(),
			csrf: "1".into(),
		}
	}
}
async fn call(
	client: &reqwest::Client,
	base: &str,
	browser: &mut Browser,
	path: &str,
	body: Option<Value>,
	expected: u16,
) -> Value {
	let mut req = client
		.request(
			if body.is_some() {
				reqwest::Method::POST
			} else {
				reqwest::Method::GET
			},
			format!("{base}{path}"),
		)
		.header("cookie", &browser.cookie)
		.header(CSRF, &browser.csrf);
	if let Some(body) = body {
		req = req.json(&body);
	}
	let res = req.send().await.unwrap();
	assert_eq!(res.status().as_u16(), expected, "{path}: {res:?}");
	if let Some(cookie) = res.headers().get("set-cookie") {
		browser.cookie = cookie.to_str().unwrap().split(';').next().unwrap().into();
	}
	let bytes = res.bytes().await.unwrap();
	let data: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
	if let Some(csrf) = data["csrf_token"].as_str() {
		browser.csrf = csrf.into();
	}
	data
}
async fn reset_security(pool: &PgPool, id: Uuid) {
	sqlx::query("DELETE FROM account_rate_limit WHERE key=$1")
		.bind(format!("security:{id}"))
		.execute(pool)
		.await
		.unwrap();
}

#[tokio::test]
#[ignore = "requires a disposable TEST_ACCOUNT_DATABASE_URL PostgreSQL database"]
async fn account_lifecycle_and_access_boundaries() {
	let db_url = std::env::var("TEST_ACCOUNT_DATABASE_URL")
		.expect("Set a disposable TEST_ACCOUNT_DATABASE_URL");
	let mut config = BackendConfig::empty();
	config.accounts = AccountConfig {
		enabled: true,
		public_origin: "http://localhost:8090".into(),
		secure_cookies: false,
		encryption_key: "ab".repeat(32),
	};
	config.header_secret = Some("synthetic-machine-secret".into());
	config.storage = Some(StorageConfig::Postgres(PostgresConfig {
		db_url,
		extra: None,
	}));
	config.connect().await.unwrap();
	let pool = config.get_pg_pool().unwrap();
	// Read-only bulk endpoints need the worker flag, but do not need RabbitMQ.
	config.worker.enable = true;
	let routes = crate::http::create_routes(Arc::new(config));
	let (addr, server) = warp::serve(routes).bind_ephemeral(([127, 0, 0, 1], 0));
	let server = tokio::spawn(server);
	let base = format!("http://{addr}");
	let mut proxy_headers = reqwest::header::HeaderMap::new();
	proxy_headers.insert(
		"x-reacher-proxy-secret",
		"synthetic-machine-secret".parse().unwrap(),
	);
	proxy_headers.insert(
		"x-reacher-client-ip",
		format!("2001:db8::{:x}", addr.port()).parse().unwrap(),
	);
	let client = reqwest::Client::builder()
		.no_proxy()
		.default_headers(proxy_headers)
		.build()
		.unwrap();
	let mut anon = Browser::default();
	let name = format!("test_{}", Uuid::new_v4().simple());
	let credentials = json!({"username":name,"password":"a correct horse password"});
	let status = call(&client, &base, &mut anon, "/v1/account/status", None, 200).await;
	assert_eq!(status["registration_open"], true);
	call(&client, &base, &mut anon, "/v1/usage", None, 401).await;
	let res = client
		.post(format!("{base}/v1/account/register"))
		.json(&credentials)
		.send()
		.await
		.unwrap();
	assert_eq!(res.status().as_u16(), 403);
	let res = client
		.post(format!("{base}/v1/account/register"))
		.header(CSRF, "1")
		.header("origin", "https://attacker.example")
		.json(&credentials)
		.send()
		.await
		.unwrap();
	assert_eq!(res.status().as_u16(), 403);
	call(
		&client,
		&base,
		&mut anon,
		"/v1/account/register",
		Some(json!({"username":name,"password":"short"})),
		400,
	)
	.await;
	let mut alice = Browser::default();
	call(
		&client,
		&base,
		&mut alice,
		"/v1/account/register",
		Some(credentials.clone()),
		200,
	)
	.await;
	let me = call(&client, &base, &mut alice, "/v1/account/me", None, 200).await;
	let id = Uuid::parse_str(me["id"].as_str().unwrap()).unwrap();
	assert_eq!(me["two_factor_enabled"], false);
	assert_eq!(me["username"], name);
	let mut tampered = alice.clone();
	tampered.csrf = "wrong".into();
	call(
		&client,
		&base,
		&mut tampered,
		"/v1/account/logout",
		Some(json!({})),
		403,
	)
	.await;
	call(
		&client,
		&base,
		&mut anon,
		"/v1/account/register",
		Some(credentials.clone()),
		409,
	)
	.await;
	call(
		&client,
		&base,
		&mut anon,
		"/v1/account/login",
		Some(json!({"username":name,"password":"incorrect password"})),
		401,
	)
	.await;
	let mut second = Browser::default();
	call(
		&client,
		&base,
		&mut second,
		"/v1/account/login",
		Some(credentials.clone()),
		200,
	)
	.await;
	// Missing enrollment must be a client error, not a NULL decoding / 500 error.
	call(
		&client,
		&base,
		&mut alice,
		"/v1/account/2fa-enable",
		Some(json!({"code":"000000"})),
		400,
	)
	.await;
	call(
		&client,
		&base,
		&mut alice,
		"/v1/account/2fa-start",
		Some(json!({"password":"wrong"})),
		401,
	)
	.await;
	let setup = call(
		&client,
		&base,
		&mut alice,
		"/v1/account/2fa-start",
		Some(json!({"password":"a correct horse password"})),
		200,
	)
	.await;
	assert!(setup["qr_svg"].as_str().unwrap().contains("<svg"));
	let secret = data_encoding::BASE32_NOPAD
		.decode(setup["secret"].as_str().unwrap().as_bytes())
		.unwrap();
	let blob: Vec<u8> = sqlx::query_scalar("SELECT pending_secret FROM account_user WHERE id=$1")
		.bind(id)
		.fetch_one(&pool)
		.await
		.unwrap();
	assert_ne!(secret, blob);
	let totp = crypto::authenticator(secret, &name).unwrap();
	let code = totp.generate_current().unwrap();
	// Enrollment belongs to the session that requested it.
	call(
		&client,
		&base,
		&mut second,
		"/v1/account/2fa-enable",
		Some(json!({"code":code})),
		400,
	)
	.await;
	call(
		&client,
		&base,
		&mut alice,
		"/v1/account/2fa-enable",
		Some(json!({"code":"bad"})),
		401,
	)
	.await;
	let enabled = call(
		&client,
		&base,
		&mut alice,
		"/v1/account/2fa-enable",
		Some(json!({"code":code})),
		200,
	)
	.await;
	let codes = enabled["recovery_codes"].as_array().unwrap();
	assert_eq!(codes.len(), 10);
	call(&client, &base, &mut second, "/v1/account/me", None, 401).await;
	let mut pending = Browser::default();
	let login = call(
		&client,
		&base,
		&mut pending,
		"/v1/account/login",
		Some(credentials.clone()),
		200,
	)
	.await;
	assert_eq!(login["mfa_required"], true);
	call(&client, &base, &mut pending, "/v1/account/me", None, 401).await;
	call(&client, &base, &mut pending, "/v1/usage", None, 401).await;
	call(
		&client,
		&base,
		&mut pending,
		"/v1/account/verify",
		Some(json!({"code":code})),
		401,
	)
	.await;
	let old_pending = pending.clone();
	call(
		&client,
		&base,
		&mut pending,
		"/v1/account/verify",
		Some(json!({"code":codes[0]})),
		200,
	)
	.await;
	assert_ne!(pending.cookie, old_pending.cookie);
	call(
		&client,
		&base,
		&mut old_pending.clone(),
		"/v1/account/me",
		None,
		401,
	)
	.await;
	let me = call(&client, &base, &mut pending, "/v1/account/me", None, 200).await;
	assert_eq!(me["recovery_codes_remaining"], 9);
	reset_security(&pool, id).await;
	// A fresh authenticator code completes login; the enrollment code above
	// was deliberately rejected as a replay. Use the allowed +1 clock step.
	call(
		&client,
		&base,
		&mut second,
		"/v1/account/login",
		Some(credentials.clone()),
		200,
	)
	.await;
	let next_code = totp.generate(
		SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap()
			.as_secs()
			+ 30,
	);
	call(
		&client,
		&base,
		&mut second,
		"/v1/account/verify",
		Some(json!({"code":next_code})),
		200,
	)
	.await;
	call(&client, &base, &mut second, "/v1/account/me", None, 200).await;
	call(
		&client,
		&base,
		&mut alice,
		"/v1/account/sessions-revoke",
		Some(json!({"password":"a correct horse password","code":next_code})),
		401,
	)
	.await;
	call(
		&client,
		&base,
		&mut alice,
		"/v1/account/sessions-revoke",
		Some(json!({"password":"a correct horse password","code":codes[0]})),
		401,
	)
	.await;
	call(
		&client,
		&base,
		&mut alice,
		"/v1/account/2fa-disable",
		Some(json!({"password":"a correct horse password"})),
		401,
	)
	.await;
	call(
		&client,
		&base,
		&mut alice,
		"/v1/account/sessions-revoke",
		Some(json!({"password":"a correct horse password","code":codes[1]})),
		200,
	)
	.await;
	call(&client, &base, &mut pending, "/v1/account/me", None, 401).await;
	let mut bob = Browser::default();
	call(&client,&base,&mut bob,"/v1/account/register",Some(json!({"username":format!("other_{}",Uuid::new_v4().simple()),"password":"another good password"})),200).await;
	let job: i32 = sqlx::query_scalar(
		"INSERT INTO v1_bulk_job(total_records,owner_id) VALUES(1,$1) RETURNING id",
	)
	.bind(id)
	.fetch_one(&pool)
	.await
	.unwrap();
	for suffix in [
		"",
		"/results?partial=true",
		"/results?partial=true&format=csv",
	] {
		let path = format!("/v1/bulk/{job}{suffix}");
		call(&client, &base, &mut alice, &path, None, 200).await;
		call(&client, &base, &mut bob, &path, None, 404).await;
		call(&client, &base, &mut anon, &path, None, 401).await;
	}
	let machine = client
		.get(format!("{base}/v1/bulk/{job}"))
		.header("x-reacher-secret", "synthetic-machine-secret")
		.send()
		.await
		.unwrap();
	assert_eq!(machine.status().as_u16(), 200);
	call(
		&client,
		&base,
		&mut alice,
		"/v0/check_email",
		Some(json!({"to_email":"invalid"})),
		403,
	)
	.await;
	call(
		&client,
		&base,
		&mut alice,
		"/v1/check_email",
		Some(json!({"to_email":"invalid","smtp_port":123})),
		403,
	)
	.await;
	call(
		&client,
		&base,
		&mut alice,
		"/v1/bulk",
		Some(json!({"input":["invalid"],"webhook":{"on_each_email":null}})),
		403,
	)
	.await;
	let regenerated = call(
		&client,
		&base,
		&mut alice,
		"/v1/account/recovery-codes",
		Some(json!({"password":"a correct horse password","code":codes[2]})),
		200,
	)
	.await;
	call(&client,&base,&mut alice,"/v1/account/password",Some(json!({"password":"a correct horse password","new_password":"a different long password","code":codes[3]})),401).await;
	call(&client,&base,&mut alice,"/v1/account/password",Some(json!({"password":"a correct horse password","new_password":"a different long password","code":regenerated["recovery_codes"][0]})),200).await;
	call(
		&client,
		&base,
		&mut anon,
		"/v1/account/login",
		Some(credentials),
		401,
	)
	.await;
	call(
		&client,
		&base,
		&mut alice,
		"/v1/account/2fa-disable",
		Some(
			json!({"password":"a different long password","code":regenerated["recovery_codes"][1]}),
		),
		200,
	)
	.await;
	let me = call(&client, &base, &mut alice, "/v1/account/me", None, 200).await;
	assert_eq!(me["two_factor_enabled"], false);
	assert_eq!(me["recovery_codes_remaining"], 0);
	let before_logout = alice.clone();
	call(
		&client,
		&base,
		&mut alice,
		"/v1/account/logout",
		Some(json!({})),
		200,
	)
	.await;
	call(
		&client,
		&base,
		&mut before_logout.clone(),
		"/v1/account/me",
		None,
		401,
	)
	.await;
	let login = call(
		&client,
		&base,
		&mut alice,
		"/v1/account/login",
		Some(json!({"username":name,"password":"a different long password"})),
		200,
	)
	.await;
	assert_eq!(login["mfa_required"], false);
	sqlx::query("UPDATE account_session SET expires_at=now()-interval '1 second' WHERE user_id=$1")
		.bind(id)
		.execute(&pool)
		.await
		.unwrap();
	call(&client, &base, &mut alice, "/v1/account/me", None, 401).await;
	// Failed attempts persist even though the credential transaction rolls back.
	reset_security(&pool, id).await;
	let key = format!("test-rate:{}", Uuid::new_v4());
	for _ in 0..3 {
		limit(&pool, &key, 3, 900).await.unwrap();
	}
	assert_eq!(
		limit(&pool, &key, 3, 900)
			.await
			.unwrap_err()
			.find::<ReacherResponseError>()
			.unwrap()
			.code,
		StatusCode::TOO_MANY_REQUESTS
	);
	server.abort();
	pool.close().await;
}
