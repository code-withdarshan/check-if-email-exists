//! Account login and authenticator enrollment. Secrets never leave this module
//! except the one-time enrollment response and newly generated recovery codes.
mod crypto;

use crate::config::BackendConfig;
use crate::http::ReacherResponseError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::{
	net::SocketAddr,
	sync::{Arc, LazyLock},
	time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;
use uuid::Uuid;
use warp::{
	http::{HeaderMap, StatusCode},
	Filter, Rejection, Reply,
};

const COOKIE: &str = "reacher_session";
const CSRF: &str = "x-reacher-csrf";
static PASSWORD_SLOTS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(2)));

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AccountConfig {
	pub enabled: bool,
	pub public_origin: String,
	pub secure_cookies: bool,
	pub encryption_key: String,
}
impl Default for AccountConfig {
	fn default() -> Self {
		Self {
			enabled: false,
			public_origin: String::new(),
			secure_cookies: true,
			encryption_key: String::new(),
		}
	}
}
impl std::fmt::Debug for AccountConfig {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("AccountConfig")
			.field("enabled", &self.enabled)
			.field("public_origin", &self.public_origin)
			.field("encryption_key", &"[REDACTED]")
			.finish()
	}
}
impl AccountConfig {
	pub fn validate(&self) -> anyhow::Result<()> {
		if !self.enabled {
			return Ok(());
		}
		crypto::encryption_key(&self.encryption_key)?;
		let url = reqwest::Url::parse(&self.public_origin)?;
		anyhow::ensure!(
			url.origin().ascii_serialization() == self.public_origin
				&& url.username().is_empty()
				&& url.password().is_none(),
			"accounts.public_origin must be an origin without a path or trailing slash"
		);
		let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
		anyhow::ensure!((url.scheme() == "https" && self.secure_cookies) || (url.scheme() == "http" && local && !self.secure_cookies), "Accounts require HTTPS and secure cookies; HTTP is allowed only for explicit localhost development");
		Ok(())
	}
}

fn reject(status: StatusCode, message: &str) -> Rejection {
	ReacherResponseError::new(status, message.to_owned()).into()
}
fn internal(_: impl std::fmt::Display) -> Rejection {
	reject(
		StatusCode::INTERNAL_SERVER_ERROR,
		"Account operation failed. Please try again.",
	)
}
fn unauthorized() -> Rejection {
	reject(StatusCode::UNAUTHORIZED, "Sign in to continue.")
}
fn invalid_credentials() -> Rejection {
	reject(
		StatusCode::UNAUTHORIZED,
		"Invalid username, password or verification code.",
	)
}
fn pool(config: &BackendConfig) -> Result<PgPool, Rejection> {
	if !config.accounts.enabled {
		return Err(reject(StatusCode::NOT_FOUND, "Accounts are not enabled."));
	}
	config.get_pg_pool().ok_or_else(|| {
		reject(
			StatusCode::SERVICE_UNAVAILABLE,
			"Account storage is unavailable.",
		)
	})
}
fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
	headers.get(name)?.to_str().ok()
}
fn cookie_token(headers: &HeaderMap) -> Option<String> {
	let value = header(headers, "cookie")?
		.split(';')
		.find_map(|part| part.trim().strip_prefix(&format!("{COOKIE}=")))?;
	if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
		return None;
	}
	Some(value.to_owned())
}
fn check_origin(config: &BackendConfig, headers: &HeaderMap) -> Result<(), Rejection> {
	if header(headers, "origin").is_some_and(|origin| origin != config.accounts.public_origin) {
		return Err(reject(
			StatusCode::FORBIDDEN,
			"Request origin is not allowed.",
		));
	}
	Ok(())
}
fn check_csrf(config: &BackendConfig, headers: &HeaderMap, token: &str) -> Result<(), Rejection> {
	check_origin(config, headers)?;
	if !header(headers, CSRF).is_some_and(|value| crypto::equal(value, &crypto::csrf(token))) {
		return Err(reject(
			StatusCode::FORBIDDEN,
			"Security token is missing or expired. Refresh and try again.",
		));
	}
	Ok(())
}
fn response(
	config: &BackendConfig,
	body: Value,
	token: Option<(&str, u64)>,
) -> warp::reply::Response {
	let mut reply = warp::reply::json(&body).into_response();
	reply
		.headers_mut()
		.insert("cache-control", "no-store".parse().unwrap());
	if let Some((token, seconds)) = token {
		let secure = if config.accounts.secure_cookies {
			"; Secure"
		} else {
			""
		};
		let cookie = format!(
			"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={seconds}{secure}"
		);
		reply
			.headers_mut()
			.insert("set-cookie", cookie.parse().unwrap());
	}
	reply
}

/// A machine secret retains existing integration access. Cookies grant only
/// authenticated, MFA-complete v1 access and never bypass CSRF on mutations.
pub fn identity(config: Arc<BackendConfig>) -> warp::filters::BoxedFilter<(Option<Uuid>,)> {
	warp::header::headers_cloned().and(warp::method()).and(warp::path::full())
        .and_then(move |headers: HeaderMap, method: warp::http::Method, path: warp::path::FullPath| {
            let config = config.clone();
            async move {
                if let Some(secret) = config.header_secret.as_deref().filter(|s| !s.is_empty()) {
                    if header(&headers, "x-reacher-secret").is_some_and(|s| crypto::equal(s, secret)) { return Ok(None); }
                }
                if !config.accounts.enabled {
                    return if config.header_secret.as_deref().unwrap_or("").is_empty() { Ok(None) }
                    else { Err(reject(StatusCode::BAD_REQUEST, "Missing or invalid x-reacher-secret header.")) };
                }
                let token = cookie_token(&headers).ok_or_else(unauthorized)?;
                if method != warp::http::Method::GET && method != warp::http::Method::HEAD { check_csrf(&config, &headers, &token)?; }
                if path.as_str().starts_with("/v0/") { return Err(reject(StatusCode::FORBIDDEN, "Account sessions use the v1 API.")); }
                let id: Option<Uuid> = sqlx::query_scalar("SELECT user_id FROM account_session WHERE token_hash=$1 AND verified AND expires_at > now()")
                    .bind(crypto::digest(&token)).fetch_optional(&pool(&config)?).await.map_err(internal)?;
                id.map(Some).ok_or_else(unauthorized)
            }
        }).boxed()
}

pub async fn require_job_owner(
	pool: &PgPool,
	job: i32,
	owner: Option<Uuid>,
) -> Result<(), Rejection> {
	if let Some(owner) = owner {
		let exists: bool = sqlx::query_scalar(
			"SELECT EXISTS(SELECT 1 FROM v1_bulk_job WHERE id=$1 AND owner_id=$2)",
		)
		.bind(job)
		.bind(owner)
		.fetch_one(pool)
		.await
		.map_err(internal)?;
		if !exists {
			return Err(reject(StatusCode::NOT_FOUND, "Job not found."));
		}
	}
	Ok(())
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
	#[serde(default)]
	username: String,
	#[serde(default)]
	password: String,
	#[serde(default)]
	new_password: String,
	#[serde(default)]
	code: String,
}
fn username(value: &str) -> Result<String, Rejection> {
	let value = value.trim().to_ascii_lowercase();
	if !(3..=64).contains(&value.len())
		|| !value
			.bytes()
			.all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
	{
		return Err(reject(
			StatusCode::BAD_REQUEST,
			"Use a username of 3–64 letters, numbers, dots, underscores or hyphens.",
		));
	}
	Ok(value)
}
fn validate_password(value: &str) -> Result<(), Rejection> {
	if value.chars().count() < 12 || value.len() > 256 {
		return Err(reject(
			StatusCode::BAD_REQUEST,
			"Use a password of at least 12 characters and at most 256 bytes.",
		));
	}
	Ok(())
}
async fn hash_password(value: String) -> Result<String, Rejection> {
	let permit = PASSWORD_SLOTS.clone().try_acquire_owned().map_err(|_| {
		reject(
			StatusCode::TOO_MANY_REQUESTS,
			"Please wait before trying again.",
		)
	})?;
	let result = tokio::task::spawn_blocking(move || {
		let _permit = permit;
		crypto::password_hash(&value)
	})
	.await
	.map_err(internal)?
	.map_err(internal);
	result
}
async fn verify_password(value: String, hash: String) -> Result<(), Rejection> {
	if value.len() > 256 {
		return Err(invalid_credentials());
	}
	let permit = PASSWORD_SLOTS.clone().try_acquire_owned().map_err(|_| {
		reject(
			StatusCode::TOO_MANY_REQUESTS,
			"Please wait before trying again.",
		)
	})?;
	let ok = tokio::task::spawn_blocking(move || {
		let _permit = permit;
		crypto::verify_password(&value, &hash)
	})
	.await
	.map_err(internal)?
	.map_err(internal)?;
	if ok {
		Ok(())
	} else {
		Err(invalid_credentials())
	}
}

async fn limit(pool: &PgPool, key: &str, maximum: i32, seconds: i32) -> Result<(), Rejection> {
	let count: i32 = sqlx::query_scalar("INSERT INTO account_rate_limit(key,attempts,expires_at) VALUES($1,1,now()+$2::int*interval '1 second') ON CONFLICT(key) DO UPDATE SET attempts=CASE WHEN account_rate_limit.expires_at <= now() THEN 1 ELSE LEAST(account_rate_limit.attempts+1,100000) END, expires_at=CASE WHEN account_rate_limit.expires_at <= now() THEN excluded.expires_at ELSE account_rate_limit.expires_at END RETURNING attempts")
        .bind(key).bind(seconds).fetch_one(pool).await.map_err(internal)?;
	if count > maximum {
		return Err(reject(
			StatusCode::TOO_MANY_REQUESTS,
			"Too many attempts. Please try again later.",
		));
	}
	Ok(())
}

async fn new_session(
	tx: &mut Transaction<'_, Postgres>,
	user: Uuid,
	verified: bool,
) -> Result<(String, u64), Rejection> {
	let token = crypto::token(32).map_err(internal)?;
	let seconds = if verified { 43_200 } else { 300 };
	sqlx::query("DELETE FROM account_session WHERE expires_at <= now()")
		.execute(&mut **tx)
		.await
		.map_err(internal)?;
	sqlx::query("DELETE FROM account_session WHERE token_hash IN (SELECT token_hash FROM account_session WHERE user_id=$1 ORDER BY created_at DESC OFFSET 9)")
        .bind(user).execute(&mut **tx).await.map_err(internal)?;
	sqlx::query("INSERT INTO account_session(token_hash,user_id,verified,expires_at) VALUES($1,$2,$3,now()+$4::int*interval '1 second')")
        .bind(crypto::digest(&token)).bind(user).bind(verified).bind(seconds as i32).execute(&mut **tx).await.map_err(internal)?;
	Ok((token, seconds))
}

async fn recovery_codes(
	tx: &mut Transaction<'_, Postgres>,
	user: Uuid,
) -> Result<Vec<String>, Rejection> {
	sqlx::query("DELETE FROM account_recovery_code WHERE user_id=$1")
		.bind(user)
		.execute(&mut **tx)
		.await
		.map_err(internal)?;
	let mut codes = Vec::new();
	for _ in 0..10 {
		let value = crypto::token(10).map_err(internal)?;
		let code = value
			.as_bytes()
			.chunks(5)
			.map(|part| std::str::from_utf8(part).unwrap())
			.collect::<Vec<_>>()
			.join("-");
		sqlx::query("INSERT INTO account_recovery_code(user_id,code_hash) VALUES($1,$2)")
			.bind(user)
			.bind(crypto::digest(&value))
			.execute(&mut **tx)
			.await
			.map_err(internal)?;
		codes.push(code);
	}
	Ok(codes)
}

async fn factor(
	tx: &mut Transaction<'_, Postgres>,
	config: &BackendConfig,
	row: &sqlx::postgres::PgRow,
	code: &str,
) -> Result<(), Rejection> {
	let user: Uuid = row.get("id");
	let Some(blob) = row.get::<Option<Vec<u8>>, _>("totp_secret") else {
		return Ok(());
	};
	let secret = crypto::decrypt(
		&crypto::encryption_key(&config.accounts.encryption_key).map_err(internal)?,
		user,
		&blob,
	)
	.map_err(internal)?;
	let totp = crypto::authenticator(secret, row.get("username")).map_err(internal)?;
	let now = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map_err(internal)?
		.as_secs();
	if let Some(step) = crypto::matching_step(&totp, code.trim(), now, row.get("totp_last_step")) {
		sqlx::query("UPDATE account_user SET totp_last_step=$2 WHERE id=$1")
			.bind(user)
			.bind(step)
			.execute(&mut **tx)
			.await
			.map_err(internal)?;
		return Ok(());
	}
	let normalized = code.trim().to_ascii_lowercase().replace('-', "");
	if normalized.len() == 20 {
		let used =
			sqlx::query("DELETE FROM account_recovery_code WHERE user_id=$1 AND code_hash=$2")
				.bind(user)
				.bind(crypto::digest(&normalized))
				.execute(&mut **tx)
				.await
				.map_err(internal)?
				.rows_affected();
		if used == 1 {
			return Ok(());
		}
	}
	Err(invalid_credentials())
}

async fn get(
	endpoint: String,
	config: Arc<BackendConfig>,
	headers: HeaderMap,
) -> Result<warp::reply::Response, Rejection> {
	if endpoint == "status" {
		return Ok(response(
			&config,
			json!({"enabled":config.accounts.enabled,"registration_open":config.accounts.enabled}),
			None,
		));
	}
	if endpoint != "me" {
		return Err(warp::reject::not_found());
	}
	let pool = pool(&config)?;
	let token = cookie_token(&headers).ok_or_else(unauthorized)?;
	let row = sqlx::query("SELECT u.id,u.username,u.totp_secret IS NOT NULL AS two_factor_enabled,(SELECT count(*) FROM account_recovery_code r WHERE r.user_id=u.id) AS recovery_codes_remaining FROM account_user u JOIN account_session s ON s.user_id=u.id WHERE s.token_hash=$1 AND s.verified AND s.expires_at>now()")
        .bind(crypto::digest(&token)).fetch_optional(&pool).await.map_err(internal)?.ok_or_else(unauthorized)?;
	Ok(response(
		&config,
		json!({"id":row.get::<Uuid,_>("id"),"username":row.get::<String,_>("username"),"two_factor_enabled":row.get::<bool,_>("two_factor_enabled"),"recovery_codes_remaining":row.get::<i64,_>("recovery_codes_remaining"),"csrf_token":crypto::csrf(&token)}),
		None,
	))
}

async fn post(
	endpoint: String,
	config: Arc<BackendConfig>,
	headers: HeaderMap,
	remote: Option<SocketAddr>,
	body: Input,
) -> Result<warp::reply::Response, Rejection> {
	let pool = pool(&config)?;
	check_origin(&config, &headers)?;
	if header(&headers, CSRF).is_none() {
		return Err(reject(StatusCode::FORBIDDEN, "Security token required."));
	}
	let proxy_trusted = config
		.header_secret
		.as_deref()
		.filter(|s| !s.is_empty())
		.is_some_and(|s| {
			header(&headers, "x-reacher-proxy-secret").is_some_and(|v| crypto::equal(v, s))
		});
	let ip = if proxy_trusted {
		header(&headers, "x-reacher-client-ip").and_then(|v| v.parse::<std::net::IpAddr>().ok())
	} else {
		None
	}
	.or_else(|| remote.map(|v| v.ip()))
	.map(|v| v.to_string())
	.unwrap_or_else(|| "local-test".into());
	limit(&pool, "global", 240, 60).await?;
	limit(&pool, &format!("ip:{ip}"), 60, 900).await?;
	sqlx::query("DELETE FROM account_rate_limit WHERE expires_at < now()-interval '1 day'")
		.execute(&pool)
		.await
		.map_err(internal)?;

	if endpoint == "register" || endpoint == "login" {
		if body.password.len() > 256 {
			return Err(invalid_credentials());
		}
		let name = username(&body.username)?;
		limit(&pool, &format!("login:{}", crypto::digest(&name)), 10, 900).await?;
		if endpoint == "register" {
			limit(&pool, &format!("register:{ip}"), 10, 3600).await?;
			validate_password(&body.password)?;
			let hash = hash_password(body.password).await?;
			let user = Uuid::new_v4();
			let mut tx = pool.begin().await.map_err(internal)?;
			let inserted = sqlx::query("INSERT INTO account_user(id,username,password_hash) VALUES($1,$2,$3) ON CONFLICT(username) DO NOTHING")
                .bind(user).bind(name).bind(hash).execute(&mut *tx).await.map_err(internal)?.rows_affected();
			if inserted == 0 {
				return Err(reject(
					StatusCode::CONFLICT,
					"That username is unavailable.",
				));
			}
			let (token, seconds) = new_session(&mut tx, user, true).await?;
			tx.commit().await.map_err(internal)?;
			return Ok(response(
				&config,
				json!({"ok":true,"csrf_token":crypto::csrf(&token)}),
				Some((&token, seconds)),
			));
		}
		let mut tx = pool.begin().await.map_err(internal)?;
		let row = sqlx::query("SELECT * FROM account_user WHERE username=$1 FOR UPDATE")
			.bind(name)
			.fetch_optional(&mut *tx)
			.await
			.map_err(internal)?;
		let Some(row) = row else {
			// Spend the same KDF work even for an unknown username.
			let _ = hash_password(body.password).await?;
			return Err(invalid_credentials());
		};
		verify_password(body.password, row.get("password_hash")).await?;
		let user: Uuid = row.get("id");
		let required = row.get::<Option<Vec<u8>>, _>("totp_secret").is_some();
		if let Some(old) = cookie_token(&headers) {
			sqlx::query("DELETE FROM account_session WHERE token_hash=$1")
				.bind(crypto::digest(&old))
				.execute(&mut *tx)
				.await
				.map_err(internal)?;
		}
		let (token, seconds) = new_session(&mut tx, user, !required).await?;
		tx.commit().await.map_err(internal)?;
		return Ok(response(
			&config,
			json!({"mfa_required":required,"csrf_token":crypto::csrf(&token)}),
			Some((&token, seconds)),
		));
	}

	let token = cookie_token(&headers).ok_or_else(unauthorized)?;
	check_csrf(&config, &headers, &token)?;
	let token_hash = crypto::digest(&token);
	if endpoint == "logout" {
		sqlx::query("DELETE FROM account_session WHERE token_hash=$1")
			.bind(token_hash)
			.execute(&pool)
			.await
			.map_err(internal)?;
		return Ok(response(&config, json!({"ok":true}), Some(("", 0))));
	}
	// Charge attempts before taking a row lock; never wait for another pool
	// connection while holding a transaction (which could exhaust the pool).
	let security_user: Uuid = sqlx::query_scalar(
		"SELECT user_id FROM account_session WHERE token_hash=$1 AND expires_at>now()",
	)
	.bind(&token_hash)
	.fetch_optional(&pool)
	.await
	.map_err(internal)?
	.ok_or_else(unauthorized)?;
	limit(&pool, &format!("security:{security_user}"), 10, 900).await?;
	let mut tx = pool.begin().await.map_err(internal)?;
	let row = sqlx::query("SELECT u.*,s.verified FROM account_user u JOIN account_session s ON s.user_id=u.id WHERE s.token_hash=$1 AND s.expires_at>now() FOR UPDATE OF u")
        .bind(&token_hash).fetch_optional(&mut *tx).await.map_err(internal)?.ok_or_else(unauthorized)?;
	// Recheck after obtaining the user lock: a concurrent security change may
	// have revoked this session while this transaction was waiting.
	let active: bool = sqlx::query_scalar(
		"SELECT EXISTS(SELECT 1 FROM account_session WHERE token_hash=$1 AND expires_at>now())",
	)
	.bind(&token_hash)
	.fetch_one(&mut *tx)
	.await
	.map_err(internal)?;
	if !active {
		return Err(unauthorized());
	}
	let user: Uuid = row.get("id");
	if endpoint == "verify" {
		if row.get::<bool, _>("verified") || row.get::<Option<Vec<u8>>, _>("totp_secret").is_none()
		{
			return Err(invalid_credentials());
		}
		factor(&mut tx, &config, &row, &body.code).await?;
		sqlx::query("DELETE FROM account_session WHERE token_hash=$1")
			.bind(token_hash)
			.execute(&mut *tx)
			.await
			.map_err(internal)?;
		let (token, seconds) = new_session(&mut tx, user, true).await?;
		tx.commit().await.map_err(internal)?;
		return Ok(response(
			&config,
			json!({"ok":true,"csrf_token":crypto::csrf(&token)}),
			Some((&token, seconds)),
		));
	}
	if !row.get::<bool, _>("verified") {
		return Err(unauthorized());
	}
	let enabled = row.get::<Option<Vec<u8>>, _>("totp_secret").is_some();
	let key = crypto::encryption_key(&config.accounts.encryption_key).map_err(internal)?;
	let mut result = json!({"ok":true});
	match endpoint.as_str() {
		"2fa-start" => {
			if enabled {
				return Err(reject(
					StatusCode::CONFLICT,
					"Two-factor authentication is already enabled.",
				));
			}
			verify_password(body.password, row.get("password_hash")).await?;
			let secret = crypto::new_secret().map_err(internal)?;
			let totp =
				crypto::authenticator(secret.clone(), row.get("username")).map_err(internal)?;
			let uri = totp.get_url();
			let qr = qrcode::QrCode::new(uri.as_bytes())
				.map_err(internal)?
				.render::<qrcode::render::svg::Color>()
				.min_dimensions(256, 256)
				.build();
			sqlx::query("UPDATE account_user SET pending_secret=$2,pending_until=now()+interval '10 minutes',pending_session=$3 WHERE id=$1")
                .bind(user).bind(crypto::encrypt(&key,user,&secret).map_err(internal)?).bind(&token_hash).execute(&mut *tx).await.map_err(internal)?;
			result = json!({"secret":crypto::setup_key(&secret),"qr_svg":qr,"expires_in":600});
		}
		"2fa-enable" => {
			if enabled {
				return Err(reject(
					StatusCode::CONFLICT,
					"Two-factor authentication is already enabled.",
				));
			}
			let valid: bool = sqlx::query_scalar("SELECT COALESCE(pending_until>now() AND pending_session=$2,false) FROM account_user WHERE id=$1")
                .bind(user).bind(&token_hash).fetch_one(&mut *tx).await.map_err(internal)?;
			let blob = row
				.get::<Option<Vec<u8>>, _>("pending_secret")
				.filter(|_| valid)
				.ok_or_else(|| reject(StatusCode::BAD_REQUEST, "Setup expired. Start again."))?;
			let secret = crypto::decrypt(&key, user, &blob).map_err(internal)?;
			let totp = crypto::authenticator(secret, row.get("username")).map_err(internal)?;
			let now = SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.map_err(internal)?
				.as_secs();
			let step = crypto::matching_step(&totp, body.code.trim(), now, -1)
				.ok_or_else(invalid_credentials)?;
			sqlx::query("UPDATE account_user SET totp_secret=$2,totp_last_step=$3,pending_secret=NULL,pending_until=NULL,pending_session=NULL WHERE id=$1")
                .bind(user).bind(blob).bind(step).execute(&mut *tx).await.map_err(internal)?;
			result = json!({"ok":true,"recovery_codes":recovery_codes(&mut tx,user).await?});
			revoke_others(&mut tx, user, &token_hash).await?;
		}
		"2fa-disable" | "recovery-codes" | "password" | "sessions-revoke" => {
			verify_password(body.password, row.get("password_hash")).await?;
			factor(&mut tx, &config, &row, &body.code).await?;
			if endpoint == "2fa-disable" {
				sqlx::query("UPDATE account_user SET totp_secret=NULL,totp_last_step=-1,pending_secret=NULL,pending_until=NULL,pending_session=NULL WHERE id=$1")
                    .bind(user).execute(&mut *tx).await.map_err(internal)?;
				sqlx::query("DELETE FROM account_recovery_code WHERE user_id=$1")
					.bind(user)
					.execute(&mut *tx)
					.await
					.map_err(internal)?;
			} else if endpoint == "recovery-codes" {
				if !enabled {
					return Err(reject(
						StatusCode::BAD_REQUEST,
						"Enable two-factor authentication first.",
					));
				}
				result = json!({"ok":true,"recovery_codes":recovery_codes(&mut tx,user).await?});
			} else if endpoint == "password" {
				validate_password(&body.new_password)?;
				let hash = hash_password(body.new_password).await?;
				sqlx::query("UPDATE account_user SET password_hash=$2,pending_secret=NULL,pending_until=NULL,pending_session=NULL WHERE id=$1")
                    .bind(user).bind(hash).execute(&mut *tx).await.map_err(internal)?;
			}
			revoke_others(&mut tx, user, &token_hash).await?;
		}
		_ => return Err(warp::reject::not_found()),
	}
	tx.commit().await.map_err(internal)?;
	Ok(response(&config, result, None))
}

async fn revoke_others(
	tx: &mut Transaction<'_, Postgres>,
	user: Uuid,
	keep: &str,
) -> Result<(), Rejection> {
	sqlx::query("DELETE FROM account_session WHERE user_id=$1 AND token_hash<>$2")
		.bind(user)
		.bind(keep)
		.execute(&mut **tx)
		.await
		.map_err(internal)?;
	Ok(())
}

pub fn routes(config: Arc<BackendConfig>) -> warp::filters::BoxedFilter<(warp::reply::Response,)> {
	let get_config = config.clone();
	let get_route = warp::path!("v1" / "account" / String)
		.and(warp::get())
		.and(warp::any().map(move || get_config.clone()))
		.and(warp::header::headers_cloned())
		.and_then(get);
	let post_route = warp::path!("v1" / "account" / String)
		.and(warp::post())
		.and(warp::any().map(move || config.clone()))
		.and(warp::header::headers_cloned())
		.and(warp::addr::remote())
		.and(warp::body::content_length_limit(8192))
		.and(warp::body::json())
		.and_then(post);
	get_route.or(post_route).unify().boxed()
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn validates_origin_and_password_policy() {
		assert!(validate_password("short").is_err());
		assert!(validate_password("a long passphrase here").is_ok());
		assert_eq!(username(" Alice_1 ").unwrap(), "alice_1");
		assert!(username("<script>").is_err());
		let mut config = AccountConfig {
			enabled: true,
			public_origin: "http://example.org".into(),
			secure_cookies: false,
			encryption_key: "ab".repeat(32),
		};
		assert!(config.validate().is_err());
		config.public_origin = "http://localhost:8090".into();
		assert!(config.validate().is_ok());
		config.public_origin = "https://example.org".into();
		config.secure_cookies = true;
		assert!(config.validate().is_ok());
	}
	#[test]
	fn csrf_and_cookie_flags() {
		let mut config = BackendConfig::empty();
		config.accounts.public_origin = "https://example.org".into();
		let token = "ab".repeat(32);
		let mut headers = HeaderMap::new();
		assert!(check_csrf(&config, &headers, &token).is_err());
		headers.insert(CSRF, crypto::csrf(&token).parse().unwrap());
		assert!(check_csrf(&config, &headers, &token).is_ok());
		headers.insert("origin", "https://attacker.example".parse().unwrap());
		assert!(check_csrf(&config, &headers, &token).is_err());
		let reply = response(&config, json!({}), Some((&token, 300)));
		let cookie = reply.headers()["set-cookie"].to_str().unwrap();
		assert!(
			cookie.contains("HttpOnly")
				&& cookie.contains("SameSite=Strict")
				&& cookie.contains("Secure")
		);
	}
}

#[cfg(test)]
mod integration_tests;
