// check-if-email-exists
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

pub(crate) mod catch_all_cache;
mod connect;
mod error;
mod headless;
mod http_api;
mod outlook;
mod parser;
pub mod verif_method;
mod yahoo;

use crate::util::input_output::CheckEmailInput;
use crate::EmailAddress;
use connect::{check_smtp_with_retry, is_host_unreachable};
pub(crate) use connect::connect_tcp;
use hickory_proto::rr::Name;
use serde::{Deserialize, Serialize};
use std::default::Default;
use verif_method::{
	EmailProvider, EverythingElseVerifMethod, GmailVerifMethod, HotmailB2BVerifMethod,
	HotmailB2CVerifMethod, VerifMethodSmtp, VerifMethodSmtpConfig, YahooVerifMethod,
};

pub use crate::mx::{is_gmail, is_hotmail, is_hotmail_b2b, is_hotmail_b2c, is_yahoo};
pub use error::*;

/// Whether `name` is safe to send as the EHLO identity: a DNS hostname, or an
/// address literal such as `[192.0.2.1]`. The SMTP library writes it verbatim,
/// so anything else (CR/LF in particular) could inject extra SMTP commands.
pub fn is_valid_hello_name(name: &str) -> bool {
	if let Some(literal) = name.strip_prefix('[').and_then(|n| n.strip_suffix(']')) {
		let literal = literal.strip_prefix("IPv6:").unwrap_or(literal);
		return literal.parse::<std::net::IpAddr>().is_ok();
	}
	let name = name.strip_suffix('.').unwrap_or(name);
	!name.is_empty()
		&& name.len() <= 253
		&& name.split('.').all(|label| {
			!label.is_empty()
				&& label.len() <= 63
				&& !label.starts_with('-')
				&& !label.ends_with('-')
				&& label
					.bytes()
					.all(|b| b.is_ascii_alphanumeric() || b == b'-')
		})
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SmtpDebugVerifMethodSmtp {
	/// The host we connected to via SMTP.
	pub host: String,
	/// The proxy used for the SMTP connection.
	pub verif_method: VerifMethodSmtpConfig,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum SmtpDebugVerifMethod {
	/// Email verification was done via SMTP.
	Smtp(SmtpDebugVerifMethodSmtp),
	/// Email verification was done via an HTTP API.
	Api,
	/// Email verification was done via a headless browser.
	Headless,
	/// Email verification was skipped.
	#[default]
	Skipped,
}

/// Details that we gathered from connecting to this email via SMTP
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct SmtpDetails {
	/// Are we able to connect to the SMTP server?
	pub can_connect_smtp: bool,
	/// Is this email account's inbox full?
	pub has_full_inbox: bool,
	/// Does this domain have a catch-all email address?
	pub is_catch_all: bool,
	/// Can we send an email to this address?
	pub is_deliverable: bool,
	/// Is the email blocked or disabled by the provider?
	pub is_disabled: bool,
}

/// Which recipient was checked by an SMTP probe.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SmtpProbeStage {
	CatchAll,
	Recipient,
}

/// An SMTP reply, including its code and all message lines.
#[derive(Debug, Deserialize, Serialize)]
pub struct SmtpReply {
	pub code: String,
	pub messages: Vec<String>,
}

/// Evidence for a recipient probe, including connection failures.
/// No credentials or message body are recorded.
#[derive(Debug, Deserialize, Serialize)]
pub struct SmtpProbe {
	pub attempt: usize,
	/// Connection number within this attempt; absent in older saved results.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub connection: Option<usize>,
	/// MX host this probe was sent to; absent in older saved results.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub mx_host: Option<String>,
	pub stage: SmtpProbeStage,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub response: Option<SmtpReply>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub error: Option<String>,
}

/// Debug information on how the SMTP verification went.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct SmtpDebug {
	/// The verification method used for the email.
	pub verif_method: SmtpDebugVerifMethod,
	/// Whether provider rules intentionally omitted the catch-all probe.
	#[serde(default)]
	pub catch_all_skipped: bool,
	/// The domain was found to be catch-all in the last day, so no SMTP
	/// conversation took place for this address.
	#[serde(default, skip_serializing_if = "std::ops::Not::not")]
	pub catch_all_cached: bool,
	/// Replies from every recipient probe, including failed attempts.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub probes: Vec<SmtpProbe>,
}

/// How many MX hosts, in preference order, one check may try.
const MAX_MX_HOSTS: usize = 3;

/// Get all email details we can from one single `EmailAddress`. `hosts` are
/// the domain's MX hosts in preference order; the first one selects the
/// verification method, and later ones are tried only if an earlier host
/// could not be reached.
pub async fn check_smtp(
	to_email: &EmailAddress,
	hosts: &[Name],
	domain: &str,
	input: &CheckEmailInput,
) -> (Result<SmtpDetails, SmtpError>, SmtpDebug) {
	let host_str = hosts
		.first()
		.expect("There should be at least one MX host. qed.")
		.to_string();
	let to_email_str = to_email.to_string();
	let email_provider = EmailProvider::from_mx_host(&host_str);

	// Handle all non-SMTP verifications first, and return early. For the rest,
	// we'll use SMTP, and return the config.
	let smtp_verif_method_config = match &email_provider {
		EmailProvider::HotmailB2C => match &input.verif_method.hotmailb2c {
			HotmailB2CVerifMethod::Headless => {
				return (
					outlook::headless::check_password_recovery(
						&to_email_str,
						&input.webdriver_addr,
						&input.webdriver_config,
					)
					.await
					.map_err(Into::into),
					SmtpDebug {
						verif_method: SmtpDebugVerifMethod::Headless,
						..Default::default()
					},
				);
			}
			HotmailB2CVerifMethod::Smtp(c) => c,
		},
		EmailProvider::Yahoo => match &input.verif_method.yahoo {
			YahooVerifMethod::Api => {
				return (
					yahoo::check_api(&to_email_str, input)
						.await
						.map_err(Into::into),
					SmtpDebug {
						verif_method: SmtpDebugVerifMethod::Api,
						..Default::default()
					},
				);
			}
			YahooVerifMethod::Headless => {
				return (
					yahoo::check_headless(
						&to_email_str,
						&input.webdriver_addr,
						&input.webdriver_config,
					)
					.await
					.map_err(Into::into),
					SmtpDebug {
						verif_method: SmtpDebugVerifMethod::Headless,
						..Default::default()
					},
				);
			}
			YahooVerifMethod::Smtp(c) => c,
		},
		EmailProvider::Gmail => match &input.verif_method.gmail {
			GmailVerifMethod::Smtp(c) => c,
		},
		EmailProvider::HotmailB2B => match &input.verif_method.hotmailb2b {
			HotmailB2BVerifMethod::Smtp(c) => c,
		},
		EmailProvider::Mimecast => match &input.verif_method.mimecast {
			verif_method::MimecastVerifMethod::Smtp(c) => c,
		},
		EmailProvider::Proofpoint => match &input.verif_method.proofpoint {
			verif_method::ProofpointVerifMethod::Smtp(c) => c,
		},
		EmailProvider::EverythingElse => match &input.verif_method.everything_else {
			EverythingElseVerifMethod::Smtp(c) => c,
		},
	}
	.clone();

	// TODO: There's surely a way to not clone here.
	let verif_method = VerifMethodSmtp::new(
		smtp_verif_method_config.clone(),
		input.verif_method.get_proxy(email_provider).cloned(),
	);

	let mut debug = SmtpDebug {
		verif_method: SmtpDebugVerifMethod::Smtp(SmtpDebugVerifMethodSmtp {
			host: host_str.clone(),
			verif_method: smtp_verif_method_config,
		}),
		..Default::default()
	};
	let use_cache = catch_all_cache::enabled();
	let route = catch_all_cache::route(&verif_method);
	if use_cache && catch_all_cache::is_known_catch_all(domain, &route) {
		debug.catch_all_cached = true;
		return (Ok(catch_all_details()), debug);
	}
	let hosts = &hosts[..hosts.len().min(MAX_MX_HOSTS)];
	for (index, host) in hosts.iter().enumerate() {
		let host_str = host.to_string();
		let first_probe = debug.probes.len();
		let result = check_smtp_with_retry(
			to_email,
			&host_str,
			domain,
			&verif_method,
			verif_method.config.retries,
			&mut debug,
		)
		.await;
		let host_probes = &mut debug.probes[first_probe..];
		for probe in host_probes.iter_mut() {
			probe.mx_host = Some(host_str.clone());
		}
		if let SmtpDebugVerifMethod::Smtp(smtp) = &mut debug.verif_method {
			smtp.host = host_str;
		}
		// A host that replied to any RCPT has spoken for the domain.
		let answered = host_probes.iter().any(|probe| probe.response.is_some());
		match &result {
			Err(error) if index + 1 < hosts.len() && !answered && is_host_unreachable(error) => {
				continue
			}
			_ => {
				if use_cache && matches!(&result, Ok(details) if details.is_catch_all) {
					catch_all_cache::remember_catch_all(domain, &route);
				}
				return (result, debug);
			}
		}
	}
	unreachable!("The last host always returns. qed.")
}

/// What a check on a catch-all domain finds: the server accepts the address.
fn catch_all_details() -> SmtpDetails {
	SmtpDetails {
		can_connect_smtp: true,
		has_full_inbox: false,
		is_catch_all: true,
		is_deliverable: true,
		is_disabled: false,
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::smtp::verif_method::GmailVerifMethod;
	use crate::smtp::verif_method::VerifMethod;
	use crate::smtp::verif_method::VerifMethodSmtpConfig;
	use crate::CheckEmailInputBuilder;
	use crate::EmailAddress;
	use hickory_proto::rr::Name;
	use std::{str::FromStr, time::Duration};
	use tokio::runtime::Runtime;

	#[test]
	fn hello_name_rejects_command_injection() {
		for ok in [
			"localhost",
			"mail.example.org",
			"mail.example.org.",
			"[192.0.2.1]",
			"[IPv6:2001:db8::1]",
		] {
			assert!(is_valid_hello_name(ok), "{}", ok);
		}
		for bad in [
			"",
			"a.example\r\nNOOP",
			"a b",
			"-a.example",
			"a..example",
			"[not-an-ip]",
		] {
			assert!(!is_valid_hello_name(bad), "{:?}", bad);
		}
	}

	#[test]
	fn should_timeout() {
		let runtime = Runtime::new().unwrap();

		let to_email = EmailAddress::from_str("foo@gmail.com").unwrap();
		let host = Name::from_str("alt4.aspmx.l.google.com.").unwrap();
		let input = CheckEmailInputBuilder::default()
			.to_email("foo@gmail.com".into())
			.verif_method(VerifMethod {
				gmail: GmailVerifMethod::Smtp(VerifMethodSmtpConfig {
					smtp_timeout: Some(Duration::from_millis(1)),
					retries: 1,
					..Default::default()
				}),
				..Default::default()
			})
			.build()
			.unwrap();

		let (res, smtp_debug) =
			runtime.block_on(check_smtp(&to_email, &[host], "gmail.com", &input));
		match smtp_debug.verif_method {
			SmtpDebugVerifMethod::Smtp(SmtpDebugVerifMethodSmtp { host, verif_method }) => {
				assert_eq!(host, "alt4.aspmx.l.google.com.");
				assert_eq!(verif_method.smtp_port, 25);
				assert_eq!(verif_method.smtp_timeout, Some(Duration::from_millis(1)));
				assert_eq!(verif_method.retries, 1);
				assert_eq!(verif_method.proxy, None);
			}
			_ => panic!("Expected SmtpDebugVerifMethod::Smtp"),
		}

		match res {
			Err(SmtpError::Timeout(_)) => (), // ErrorKind == Timeout
			_ => panic!("check_smtp did not time out"),
		}
	}
}
