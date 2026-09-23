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
	pub fn to_check_email_input(&self, config: Arc<BackendConfig>) -> CheckEmailInput {
		let hello_name = self
			.hello_name
			.clone()
			.unwrap_or_else(|| config.hello_name.clone());
		let from_email = self
			.from_email
			.clone()
			.unwrap_or_else(|| config.from_email.clone());
		let smtp_timeout = self
			.smtp_timeout
			.or_else(|| config.smtp_timeout.map(Duration::from_secs));
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
				smtp_timeout.clone(),
				retries,
			)
		} else {
			config.get_verif_method()
		};

		for smtp in verif_method.smtp_configs_mut() {
			if let Some(value) = &self.from_email {
				smtp.from_email = value.clone();
			}
			if let Some(value) = &self.hello_name {
				smtp.hello_name = value.clone();
			}
			if let Some(value) = self.smtp_timeout {
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
				smtp_timeout.clone(),
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

/// The main endpoint handler that implements the logic of this route.
async fn http_handler(
	config: Arc<BackendConfig>,
	body: CheckEmailRequest,
) -> Result<impl warp::Reply, warp::Rejection> {
	// The to_email field must be present
	if body.to_email.is_empty() {
		Err(
			ReacherResponseError::new(http::StatusCode::BAD_REQUEST, "to_email field is required.")
				.into(),
		)
	} else {
		// Run the future to check an email.
		Ok(warp::reply::json(
			&check_email(&body.to_check_email_input(Arc::clone(&config))).await,
		))
	}
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
		assert!(matches!(
			input.verif_method.yahoo,
			YahooVerifMethod::Headless
		));
	}
}
