// Reacher - Email Verification
// Copyright (C) 2018-2023 Reacher

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! This file implements the `POST /v0/check_email` endpoint.

use check_if_email_exists::smtp::is_valid_hello_name;
use check_if_email_exists::smtp::verif_method::VerifMethod;
use check_if_email_exists::{check_email, CheckEmailInput, CheckEmailInputProxy, LOG_TARGET};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use warp::{http, Filter};

use super::backwardcompat::{BackwardCompatHotmailB2CVerifMethod, BackwardCompatYahooVerifMethod};
use crate::config::BackendConfig;
use crate::http::{check_header, ReacherResponseError};

/// The request body for the `POST /v0/check_email` endpoint.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct CheckEmailRequest {
	#[serde(skip)]
	pub public_network_only: bool,
	pub to_email: String,
	pub from_email: Option<String>,
	pub hello_name: Option<String>,
	pub proxy: Option<CheckEmailInputProxy>,
	pub smtp_timeout: Option<Duration>,
	pub smtp_port: Option<u16>,
	// The following fields are for backward compatibility.
	pub yahoo_verif_method: Option<BackwardCompatYahooVerifMethod>,
	pub hotmailb2c_verif_method: Option<BackwardCompatHotmailB2CVerifMethod>,
}

impl CheckEmailRequest {
	/// Rejects request fields that are unsafe to use, with a message for the
	/// caller. `to_check_email_input` also ignores them, as a second line.
	pub fn validate(&self) -> Result<(), ReacherResponseError> {
		if self.to_email.is_empty() {
			return Err(ReacherResponseError::new(
				http::StatusCode::BAD_REQUEST,
				"to_email field is required.",
			));
		}
		if let Some(name) = &self.hello_name {
			if !is_valid_hello_name(name) {
				return Err(ReacherResponseError::new(
					http::StatusCode::BAD_REQUEST,
					"hello_name must be a hostname or an address literal.",
				));
			}
		}
		Ok(())
	}

	/// Public accounts cannot control network destinations or provider methods.
	pub fn restrict_account(&mut self) -> Result<(), ReacherResponseError> {
		if self.proxy.is_some()
			|| self.smtp_port.is_some()
			|| self.smtp_timeout.is_some()
			|| self.hello_name.is_some()
			|| self.from_email.is_some()
			|| self.yahoo_verif_method.is_some()
			|| self.hotmailb2c_verif_method.is_some()
		{
			return Err(ReacherResponseError::new(
				http::StatusCode::FORBIDDEN,
				"Connection overrides require machine API access.",
			));
		}
		self.public_network_only = true;
		Ok(())
	}

	/// The request's `hello_name`, unless it is unsafe to send.
	fn safe_hello_name(&self) -> Option<&String> {
		self.hello_name.as_ref().filter(|n| is_valid_hello_name(n))
	}

	/// The request's SMTP timeout, capped so one verification cannot outlast
	/// the request deadline.
	fn capped_smtp_timeout(&self, config: &BackendConfig) -> Option<Duration> {
		self.smtp_timeout
			.map(|t| t.min(Duration::from_secs(config.request_timeout)))
	}

	pub fn to_check_email_input(&self, config: Arc<BackendConfig>) -> CheckEmailInput {
		let hello_name = self
			.safe_hello_name()
			.cloned()
			.unwrap_or_else(|| config.hello_name.clone());
		let from_email = self
			.from_email
			.clone()
			.unwrap_or_else(|| config.from_email.clone());
		let request_smtp_timeout = self.capped_smtp_timeout(&config);
		let smtp_timeout =
			request_smtp_timeout.or_else(|| config.smtp_timeout.map(Duration::from_secs));
		let smtp_port = self.smtp_port.unwrap_or(25);
		let retries = 1;

		// A request proxy replaces the default SMTP proxy. If the proxy field is present,
		// we force use the proxy for all the verifications. If the proxy field is
		// not present, we use the default configuration for all the verifications.
		//
		// Explicit SMTP fields override provider defaults independently of proxy selection.
		let mut verif_method = if let Some(proxy) = &self.proxy {
			VerifMethod::new_with_same_config_for_all(
				Some(proxy.clone()),
				hello_name.clone(),
				from_email.clone(),
				smtp_port,
				smtp_timeout,
				retries,
			)
		} else {
			config.get_verif_method()
		};

		for smtp in verif_method.smtp_configs_mut() {
			if let Some(value) = &self.from_email {
				smtp.from_email = value.clone();
			}
			if let Some(value) = self.safe_hello_name() {
				smtp.hello_name = value.clone();
			}
			if let Some(value) = request_smtp_timeout {
				smtp.smtp_timeout = Some(value);
			}
			if let Some(value) = self.smtp_port {
				smtp.smtp_port = value;
			}
		}
		// Also support backward compatibility of the *_verif_method fields, which
		// override the verif_method.
		if let Some(yahoo_verif_method) = &self.yahoo_verif_method {
			verif_method.yahoo = yahoo_verif_method.to_yahoo_verif_method(
				self.proxy.is_some(),
				hello_name.clone(),
				from_email.clone(),
				smtp_timeout,
				smtp_port,
				retries,
			);
		}
		if let Some(hotmailb2c_verif_method) = &self.hotmailb2c_verif_method {
			verif_method.hotmailb2c = hotmailb2c_verif_method.to_hotmailb2c_verif_method(
				self.proxy.is_some(),
				hello_name,
				from_email,
				smtp_timeout,
				smtp_port,
				retries,
			);
		}

		if self.public_network_only {
			for smtp in verif_method.smtp_configs_mut() {
				smtp.public_network_only = true;
			}
		}
		CheckEmailInput {
			to_email: self.to_email.clone(),
			verif_method,
			sentry_dsn: config.sentry_dsn.clone(),
			backend_name: config.backend_name.clone(),
			webdriver_config: config.webdriver.clone(),
			webdriver_addr: config.webdriver_addr.clone(),
			..Default::default()
		}
	}
}

/// The main endpoint handler that implements the logic of this route. It
/// applies the same quota, concurrency limit and deadline as v1 direct mode.
async fn http_handler(
	config: Arc<BackendConfig>,
	body: CheckEmailRequest,
) -> Result<impl warp::Reply, warp::Rejection> {
	body.validate()?;

	if let Err(throttle_result) = config.get_throttle_manager().try_acquire().await {
		return Err(ReacherResponseError::new(
			http::StatusCode::TOO_MANY_REQUESTS,
			format!(
				"Rate limit {} exceeded, please wait {:?}",
				throttle_result.limit_type, throttle_result.delay
			),
		)
		.into());
	}

	let deadline = Duration::from_secs(config.request_timeout);
	let work = async {
		let _permit = config
			.verification_slots()
			.acquire_owned()
			.await
			.map_err(|e| ReacherResponseError::new(http::StatusCode::SERVICE_UNAVAILABLE, e))?;
		Ok::<_, ReacherResponseError>(
			check_email(&body.to_check_email_input(Arc::clone(&config))).await,
		)
	};
	let output = tokio::time::timeout(deadline, work).await.map_err(|_| {
		ReacherResponseError::new(
			http::StatusCode::GATEWAY_TIMEOUT,
			format!("Verification did not complete within {:?}", deadline),
		)
	})??;

	Ok(warp::reply::json(&output))
}

/// Create the `POST /check_email` endpoint.
pub fn post_check_email<'a>(
	config: Arc<BackendConfig>,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone + 'a {
	warp::path!("v0" / "check_email")
		.and(warp::post())
		.and(check_header(Arc::clone(&config)))
		.and(with_config(config))
		// When accepting a body, we want a JSON body (and to reject huge
		// payloads)...
		.and(warp::body::content_length_limit(1024 * 16))
		.and(warp::body::json())
		.and_then(http_handler)
		// View access logs by setting `RUST_LOG=reacher`.
		.with(warp::log(LOG_TARGET))
}

/// Warp filter that adds the BackendConfig to the handler.
pub fn with_config(
	config: Arc<BackendConfig>,
) -> impl Filter<Extract = (Arc<BackendConfig>,), Error = std::convert::Infallible> + Clone {
	warp::any().map(move || Arc::clone(&config))
}

#[cfg(test)]
mod tests {
	use super::*;
	use check_if_email_exists::smtp::verif_method::{GmailVerifMethod, YahooVerifMethod};
	#[test]
	fn forwards_webdriver_and_smtp_overrides_without_proxy() {
		let mut config = BackendConfig::empty();
		config.webdriver_addr = "http://webdriver:9515".into();
		let request = CheckEmailRequest {
			to_email: "test@example.org".into(),
			smtp_port: Some(2525),
			smtp_timeout: Some(Duration::from_secs(9)),
			from_email: Some("sender@example.org".into()),
			hello_name: Some("example.org".into()),
			..Default::default()
		};
		let input = request.to_check_email_input(Arc::new(config));
		assert_eq!(input.webdriver_addr, "http://webdriver:9515");
		let GmailVerifMethod::Smtp(smtp) = input.verif_method.gmail;
		assert_eq!(smtp.smtp_port, 2525);
		assert_eq!(smtp.smtp_timeout, Some(Duration::from_secs(9)));
		assert_eq!(smtp.from_email, "sender@example.org");
		assert_eq!(smtp.hello_name, "example.org");
		// Yahoo defaults to SMTP, so the request overrides apply to it too.
		let YahooVerifMethod::Smtp(yahoo) = input.verif_method.yahoo else {
			panic!("Yahoo should default to SMTP");
		};
		assert_eq!(yahoo.smtp_port, 2525);
	}
}
