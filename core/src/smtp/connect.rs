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

use async_recursion::async_recursion;
use async_smtp::commands::{MailCommand, RcptCommand};
use async_smtp::error::Error as AsyncSmtpError;
use async_smtp::extension::ClientId;
use async_smtp::{SmtpClient, SmtpTransport};
use fast_socks5::client::Config;
use fast_socks5::{client::Socks5Stream, Result};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, BufStream};
use tokio::net::TcpStream;

use super::parser;
use super::verif_method::VerifMethodSmtp;
use super::{SmtpDebug, SmtpDetails, SmtpError, SmtpProbe, SmtpProbeStage, SmtpReply};
use crate::rules::{has_rule, Rule};
use crate::{EmailAddress, LOG_TARGET};

// Define a new trait that combines AsyncRead, AsyncWrite, and Unpin
trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

/// Time allowed to open the TCP connection, within the overall SMTP timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The addresses of a mail server in the order to try them: IPv4 first.
/// Large providers hold IPv6 senders to stricter rules (reverse DNS, SPF),
/// and a server's IPv6 address often has no reverse DNS, so IPv6 is a fallback.
fn ipv4_first(mut addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
	addrs.sort_by_key(SocketAddr::is_ipv6);
	addrs
}

/// Opens a TCP connection to a mail server, trying each of its addresses.
pub(crate) async fn connect_tcp(host: &str, port: u16) -> std::io::Result<TcpStream> {
	connect_tcp_restricted(host, port, false).await
}

fn public_destination(ip: std::net::IpAddr) -> bool {
	match ip {
		std::net::IpAddr::V4(ip) => crate::self_check::is_public_ipv4(ip),
		std::net::IpAddr::V6(ip) => {
			let s = ip.segments();
			// Only global unicast; exclude protocol assignments, documentation,
			// 6to4 and mapped/translation addresses that could reach private IPv4.
			s[0] & 0xe000 == 0x2000
				&& !(s[0] == 0x2001 && (s[1] < 0x200 || s[1] == 0xdb8))
				&& s[0] != 0x2002
				&& !(s[0] == 0x3fff && s[1] < 0x1000)
		}
	}
}

async fn connect_tcp_restricted(
	host: &str,
	port: u16,
	public_only: bool,
) -> std::io::Result<TcpStream> {
	let addrs = ipv4_first(tokio::net::lookup_host((host, port)).await?.collect());
	let mut last_error = std::io::Error::new(
		std::io::ErrorKind::NotFound,
		format!("{host} has no IP address"),
	);
	for addr in addrs {
		if public_only && !public_destination(addr.ip()) {
			last_error = std::io::Error::new(
				std::io::ErrorKind::PermissionDenied,
				"Private SMTP destination is not allowed",
			);
			continue;
		}
		match TcpStream::connect(addr).await {
			Ok(stream) => return Ok(stream),
			Err(err) => last_error = err,
		}
	}
	Err(last_error)
}

/// Try to send an smtp command, close and return Err if fails.
macro_rules! try_smtp (
    ($res: expr, $client: ident, $to_email: expr, $host: expr, $port: expr) => ({
		if let Err(err) = $res {
			tracing::debug!(
				target: LOG_TARGET,
				email=$to_email.to_string(),
				mx_host=$host,
				port=$port,
				error=?err,
				"Closing connection due to error"
			);
			// Try to close the connection, but ignore if there's an error.
			let _ = $client.quit().await;

			return Err(SmtpError::AsyncSmtpError(err));
		}
    })
);

/// Connect to an SMTP host and return the configured client transport.
async fn connect_to_smtp_host(
	to_email: &EmailAddress,
	mx_host: &str,
	verif_method: &VerifMethodSmtp,
) -> Result<SmtpTransport<BufStream<Box<dyn AsyncReadWrite>>>, SmtpError> {
	// hostname verification fails if it ends with '.', for example, using
	// SOCKS5 proxies we can `io: incomplete` error.
	let clean_host = mx_host.trim_end_matches('.').to_string();
	if !super::is_valid_hello_name(&verif_method.config.hello_name) {
		return Err(SmtpError::IOError(std::io::Error::new(
			std::io::ErrorKind::InvalidInput,
			"hello_name must be a hostname or an address literal",
		)));
	}
	let smtp_client = SmtpClient::new()
		.hello_name(ClientId::Domain(verif_method.config.hello_name.to_string()))
		// Sometimes, using socks5 proxy, we get an `io: incomplete` error
		// when using pipelining and sending two consecutive RCPT TO commands.
		.pipelining(false);

	let stream: BufStream<Box<dyn AsyncReadWrite>> = match &verif_method.proxy {
		Some(proxy) => {
			// Resolve and pin the destination before handing it to SOCKS, so
			// a second DNS lookup cannot redirect a public account to a private IP.
			let destination = if verif_method.config.public_network_only {
				let addrs = ipv4_first(
					tokio::net::lookup_host((clean_host.as_str(), verif_method.config.smtp_port))
						.await?
						.collect(),
				);
				addrs
					.into_iter()
					.find(|addr| public_destination(addr.ip()))
					.ok_or_else(|| {
						std::io::Error::new(
							std::io::ErrorKind::PermissionDenied,
							"No public SMTP destination",
						)
					})?
					.ip()
					.to_string()
			} else {
				clean_host.clone()
			};
			let mut config = Config::default();
			if let Some(timeout_ms) = proxy.timeout_ms {
				config.set_connect_timeout(timeout_ms / 1000);
			}

			let socks_stream =
				if let (Some(username), Some(password)) = (&proxy.username, &proxy.password) {
					Socks5Stream::connect_with_password(
						(proxy.host.as_ref(), proxy.port),
						destination.clone(),
						verif_method.config.smtp_port,
						username.clone(),
						password.clone(),
						config,
					)
					.await?
				} else {
					Socks5Stream::connect(
						(proxy.host.as_ref(), proxy.port),
						destination.clone(),
						verif_method.config.smtp_port,
						config,
					)
					.await?
				};
			BufStream::new(Box::new(socks_stream) as Box<dyn AsyncReadWrite>)
		}
		None => {
			// A dead host fails fast here, leaving time to try the next MX.
			let tcp_stream = tokio::time::timeout(
				CONNECT_TIMEOUT,
				connect_tcp_restricted(
					&clean_host,
					verif_method.config.smtp_port,
					verif_method.config.public_network_only,
				),
			)
			.await
			.map_err(|_| {
				std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP connect timed out")
			})??;
			BufStream::new(Box::new(tcp_stream) as Box<dyn AsyncReadWrite>)
		}
	};

	let mut smtp_transport = SmtpTransport::new(smtp_client, stream).await?;

	// Set "MAIL FROM"
	let from_email = EmailAddress::from_str(&verif_method.config.from_email).unwrap_or_else(|_| {
		tracing::warn!(
			target: LOG_TARGET,
			from_email=verif_method.config.from_email,
			"Invalid 'from_email' provided, using default: 'user@example.org'"
		);
		EmailAddress::from_str("user@example.org").expect("Default email is valid")
	});
	try_smtp!(
		smtp_transport
			.get_mut()
			.command(MailCommand::new(Some(from_email.into_inner()), vec![]))
			.await,
		smtp_transport,
		to_email,
		clean_host,
		verif_method.config.smtp_port
	);

	Ok(smtp_transport)
}

/// Description of the deliverability information we can gather from
/// communicating with the SMTP server.
struct Deliverability {
	/// Is this email account's inbox full?
	has_full_inbox: bool,
	/// Can we send an email to this address?
	is_deliverable: bool,
	/// Is the email blocked or disabled by the provider?
	is_disabled: bool,
}

/// Checks deliverability of a target email address using the provided SMTP transport.
async fn check_email_deliverability<S: AsyncBufRead + AsyncWrite + Unpin + Send>(
	smtp_transport: &mut SmtpTransport<S>,
	to_email: &EmailAddress,
	stage: SmtpProbeStage,
	attempt: usize,
	connection: usize,
	debug: &mut SmtpDebug,
) -> Result<Deliverability, SmtpError> {
	// Insert before awaiting so timeouts retain the stage that failed.
	debug.probes.push(SmtpProbe {
		attempt,
		connection: Some(connection),
		mx_host: None,
		stage,
		response: None,
		error: None,
	});
	let result = smtp_transport
		.get_mut()
		.command(RcptCommand::new(to_email.clone().into_inner(), vec![]))
		.await;
	let probe = debug.probes.last_mut().expect("Just inserted probe");
	let response = match &result {
		Ok(response) => Some(response),
		Err(AsyncSmtpError::Transient(response) | AsyncSmtpError::Permanent(response)) => {
			Some(response)
		}
		Err(error) => {
			probe.error = Some(error.to_string());
			None
		}
	};
	probe.response = response.map(|response| SmtpReply {
		code: response.code.to_string(),
		messages: response.message.clone(),
	});
	match result {
		// RCPT acceptance is evidence for this probe, not a delivery guarantee.
		Ok(response) if response.has_code(250) || response.has_code(251) => Ok(Deliverability {
			has_full_inbox: false,
			is_deliverable: true,
			is_disabled: false,
		}),
		Ok(response) => Err(SmtpError::AnyhowError(anyhow::anyhow!(
			"Inconclusive RCPT reply: {} {}",
			response.code,
			response.message.join("; ")
		))),
		Err(err) => {
			// We cast to lowercase, because our matched strings below are all
			// lowercase.
			let err_string = err.to_string().to_lowercase();
			let permanent = matches!(&err, AsyncSmtpError::Permanent(_));
			let error = SmtpError::AsyncSmtpError(err);
			// A reply about our sender says nothing about the recipient, even with a
			// mailbox-like code or wording ("Sender address rejected: User unknown").
			if parser::blames_sender(&err_string) {
				return Err(error);
			}
			// A mailbox status code outranks broad wording such as "blocked" or
			// "access denied", unless the reply blames our IP's reputation.
			let coded = probe
				.response
				.as_ref()
				.and_then(|response| parser::mailbox_status(&response.messages))
				.filter(|_| !parser::mentions_ip_reputation(&err_string));
			// A policy refusal concerns this probe/sender, not mailbox existence.
			// Gmail and Yandex are exceptions: they state a missing mailbox with 5.7.1.
			let policy_refusal = !parser::says_no_such_mailbox(&err_string)
				&& probe.response.as_ref().is_some_and(|response| {
					response.messages.iter().any(|line| {
						line.split_whitespace()
							.next()
							.is_some_and(|code| code.starts_with("5.7."))
					})
				});
			if coded.is_none() && (policy_refusal || error.get_description().is_some()) {
				return Err(error);
			}
			if probe.stage == SmtpProbeStage::CatchAll {
				// Only an explicit permanent recipient rejection establishes no catch-all.
				// Full/disabled/random recipients and temporary failures are inconclusive.
				let invalid = match coded {
					Some(status) => status == parser::MailboxStatus::Invalid,
					None => parser::is_invalid(&err_string, to_email),
				};
				let unverified = parser::is_unverified_recipient(&err_string);
				return if (permanent && invalid) || unverified {
					Ok(Deliverability {
						has_full_inbox: false,
						is_deliverable: false,
						is_disabled: false,
					})
				} else {
					Err(error)
				};
			}

			match coded {
				Some(parser::MailboxStatus::Invalid) => {
					return Ok(Deliverability {
						has_full_inbox: false,
						is_deliverable: false,
						is_disabled: false,
					})
				}
				Some(parser::MailboxStatus::Disabled) => {
					return Ok(Deliverability {
						has_full_inbox: false,
						is_deliverable: false,
						is_disabled: true,
					})
				}
				Some(parser::MailboxStatus::FullInbox) => {
					return Ok(Deliverability {
						has_full_inbox: true,
						is_deliverable: false,
						is_disabled: false,
					})
				}
				// No mailbox status code: fall back to the reply's wording.
				None => {}
			}

			// Check if the email account has been disabled or blocked.
			if permanent && parser::is_disabled_account(&err_string) {
				return Ok(Deliverability {
					has_full_inbox: false,
					is_deliverable: false,
					is_disabled: true,
				});
			}

			// Check if the email account has a full inbox.
			if parser::is_full_inbox(&err_string) {
				return Ok(Deliverability {
					has_full_inbox: true,
					is_deliverable: false,
					is_disabled: false,
				});
			}

			// A temporary code, but the server's own check of this mailbox failed.
			if parser::is_unverified_recipient(&err_string) {
				return Ok(Deliverability {
					has_full_inbox: false,
					is_deliverable: false,
					is_disabled: false,
				});
			}

			if !permanent {
				return Err(error);
			}

			// Check that the mailbox doesn't exist.
			if parser::is_invalid(&err_string, to_email) {
				return Ok(Deliverability {
					has_full_inbox: false,
					is_deliverable: false,
					is_disabled: false,
				});
			}

			// Return all unparsable errors,.
			Err(error)
		}
	}
}

/// The made-up 15-character mailbox used for the catch-all probe. It is the same
/// for a domain every time: greylisting servers turn away a new sender/recipient
/// pair until it is retried, so a fresh random address would never get through.
fn catch_all_local_part(domain: &str) -> String {
	const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
	let mut local = String::with_capacity(15);
	let mut round = 0u64;
	while local.len() < 15 {
		let mut hasher = DefaultHasher::new();
		("reacher-catch-all", domain.to_lowercase(), round).hash(&mut hasher);
		let mut n = hasher.finish();
		// Eight base-36 characters per 64-bit hash.
		for _ in 0..8 {
			if local.len() == 15 {
				break;
			}
			local.push(CHARS[(n % 36) as usize] as char);
			n /= 36;
		}
		round += 1;
	}
	local
}

/// Checks if the domain has a catch-all email setup.
async fn smtp_is_catch_all<S: AsyncBufRead + AsyncWrite + Unpin + Send>(
	smtp_transport: &mut SmtpTransport<S>,
	domain: &str,
	host: &str,
	to_email: &EmailAddress,
	attempt: usize,
	debug: &mut SmtpDebug,
) -> Result<bool, SmtpError> {
	if has_rule(domain, host, &Rule::SkipCatchAll) {
		debug.catch_all_skipped = true;
		tracing::debug!(
			target: LOG_TARGET,
			email=to_email.to_string(),
			domain=domain,
			"Skipping catch-all check"
		);
		return Ok(false);
	}

	let random_email = EmailAddress::new(format!("{}@{}", catch_all_local_part(domain), domain))?;

	check_email_deliverability(
		smtp_transport,
		&random_email,
		SmtpProbeStage::CatchAll,
		attempt,
		1,
		debug,
	)
	.await
	.map(|result| result.is_deliverable)
}

/// Open a clean recipient session, retaining its stage even if the handshake fails.
async fn connect_for_recipient(
	to_email: &EmailAddress,
	mx_host: &str,
	verif_method: &VerifMethodSmtp,
	attempt: usize,
	connection: usize,
	debug: &mut SmtpDebug,
) -> Result<SmtpTransport<BufStream<Box<dyn AsyncReadWrite>>>, SmtpError> {
	debug.probes.push(SmtpProbe {
		attempt,
		connection: Some(connection),
		mx_host: None,
		stage: SmtpProbeStage::Recipient,
		response: None,
		error: None,
	});
	let transport = connect_to_smtp_host(to_email, mx_host, verif_method).await?;
	// The RCPT check adds the actual reply record after a successful handshake.
	debug.probes.pop();
	Ok(transport)
}

/// Creates an SMTP future for email verification.
async fn create_smtp_future(
	to_email: &EmailAddress,
	mx_host: &str,
	domain: &str,
	verif_method: &VerifMethodSmtp,
	attempt: usize,
	debug: &mut SmtpDebug,
) -> Result<(bool, Deliverability), SmtpError> {
	// FIXME If the SMTP is not connectable, we should actually return an
	// Ok(SmtpDetails { can_connect_smtp: false, ... }).
	// Record the stage that was due, so a failed handshake keeps its evidence.
	debug.probes.push(SmtpProbe {
		attempt,
		connection: Some(1),
		mx_host: None,
		stage: if has_rule(domain, mx_host, &Rule::SkipCatchAll) {
			SmtpProbeStage::Recipient
		} else {
			SmtpProbeStage::CatchAll
		},
		response: None,
		error: None,
	});
	let mut smtp_transport = connect_to_smtp_host(to_email, mx_host, verif_method).await?;
	// The RCPT check adds the actual reply record after a successful handshake.
	debug.probes.pop();

	let is_catch_all = smtp_is_catch_all(
		&mut smtp_transport,
		domain,
		mx_host,
		to_email,
		attempt,
		debug,
	)
	.await?;
	let deliverability = if is_catch_all {
		Deliverability {
			has_full_inbox: false,
			is_deliverable: true,
			is_disabled: false,
		}
	} else {
		let mut connection = 1;
		if !debug.catch_all_skipped {
			// A recipient must be the first RCPT in its own TCP session. A server
			// may respond differently to subsequent recipients after the random
			// catch-all rejection. RSET alone would still share that session.
			let _ = tokio::time::timeout(Duration::from_secs(2), smtp_transport.quit()).await;
			drop(smtp_transport);
			connection += 1;
			smtp_transport =
				connect_for_recipient(to_email, mx_host, verif_method, attempt, connection, debug)
					.await?;
		}
		let mut result = check_email_deliverability(
			&mut smtp_transport,
			to_email,
			SmtpProbeStage::Recipient,
			attempt,
			connection,
			debug,
		)
		.await;

		// Retry an interrupted recipient probe once, in another fresh session.
		//
		// Unfortunately `smtp_transport.is_connected()` doesn't report about this,
		// so we can only check for "io: incomplete" SMTP error being returned.
		// https://github.com/async-email/async-smtp/issues/37
		if let Err(e) = &result {
			if parser::is_err_io_errors(e) {
				tracing::debug!(
					target: LOG_TARGET,
					email=to_email.to_string(),
					error=?e,
					"Got `io: incomplete` error, reconnecting"
				);

				let _ = tokio::time::timeout(Duration::from_secs(2), smtp_transport.quit()).await;
				drop(smtp_transport);
				connection += 1;
				smtp_transport = connect_for_recipient(
					to_email,
					mx_host,
					verif_method,
					attempt,
					connection,
					debug,
				)
				.await?;
				result = check_email_deliverability(
					&mut smtp_transport,
					to_email,
					SmtpProbeStage::Recipient,
					attempt,
					connection,
					debug,
				)
				.await;
			}
		}

		result?
	};

	// The result is already known; a server that hangs up after replying
	// must not turn it into an error.
	let _ = tokio::time::timeout(Duration::from_secs(2), smtp_transport.quit()).await;

	Ok((is_catch_all, deliverability))
}

/// Get all email details we can from one single `EmailAddress`, without
/// retries.
async fn check_smtp_without_retry(
	to_email: &EmailAddress,
	mx_host: &str,
	domain: &str,
	verif_method: &VerifMethodSmtp,
	attempt: usize,
	debug: &mut SmtpDebug,
) -> Result<SmtpDetails, SmtpError> {
	let fut = create_smtp_future(to_email, mx_host, domain, verif_method, attempt, debug);

	let (is_catch_all, deliverability) = match verif_method.config.smtp_timeout {
		Some(smtp_timeout) => {
			let timeout = tokio::time::timeout(smtp_timeout, fut);

			match timeout.await {
				Ok(result) => result?,
				Err(_) => return Err(SmtpError::Timeout(smtp_timeout)),
			}
		}
		None => fut.await?,
	};

	Ok(SmtpDetails {
		can_connect_smtp: true,
		has_full_inbox: deliverability.has_full_inbox,
		is_catch_all,
		is_deliverable: deliverability.is_deliverable,
		is_disabled: deliverability.is_disabled,
	})
}

/// Whether the host failed before any conversation that could concern the
/// mailbox, so a backup MX may still answer: refused/unreachable/reset
/// connections and temporary refusals. Timeouts are excluded because trying
/// another host would add a full SMTP timeout each, and refusals naming our IP
/// would be repeated by the other hosts.
pub fn is_host_unreachable(error: &SmtpError) -> bool {
	match error {
		SmtpError::IOError(_) => true,
		SmtpError::AsyncSmtpError(AsyncSmtpError::Io(_) | AsyncSmtpError::Transient(_)) => {
			error.get_description().is_none()
		}
		_ => false,
	}
}

/// Get all email details we can from one single `EmailAddress`.
/// Retry the SMTP connection on error, in particular to avoid greylisting.
#[async_recursion]
pub async fn check_smtp_with_retry(
	to_email: &EmailAddress,
	mx_host: &str,
	domain: &str,
	verif_method: &VerifMethodSmtp,
	// Number of remaining retries.
	count: usize,
	debug: &mut SmtpDebug,
) -> Result<SmtpDetails, SmtpError> {
	tracing::debug!(
		target: LOG_TARGET,
		email=to_email.to_string(),
		attempt=verif_method.config.retries - count + 1,
		mx_host=mx_host,
		port=verif_method.config.smtp_port,
		using_proxy=verif_method.proxy.is_some(),
		"Check SMTP"
	);

	let attempt = verif_method.config.retries - count + 1;
	let result =
		check_smtp_without_retry(to_email, mx_host, domain, verif_method, attempt, debug).await;
	if let Err(error) = &result {
		if let Some(probe) = debug.probes.last_mut() {
			if probe.attempt == attempt && probe.response.is_none() && probe.error.is_none() {
				probe.error = Some(error.to_string());
			}
		}
	}

	tracing::debug!(
		target: LOG_TARGET,
		email=to_email.to_string(),
		attempt=verif_method.config.retries - count + 1,
		mx_host=mx_host,
		port=verif_method.config.smtp_port,
		result=?result,
		"Got SMTP check result"
	);

	match &result {
		// Don't retry if we used Hotmail or Yahoo API. This two options should
		// be non-callable, as this function only deals with actual SMTP
		// connection errors.
		Err(SmtpError::HeadlessError(_)) => result,
		Err(SmtpError::YahooError(_)) => result,
		// Only retry if the SMTP error was unknown.
		Err(err) if err.get_description().is_none() => {
			if count <= 1 {
				result
			} else {
				tracing::debug!(
					target: LOG_TARGET,
					email=to_email.to_string(),
					"Potential greylisting detected, retrying"
				);
				check_smtp_with_retry(to_email, mx_host, domain, verif_method, count - 1, debug)
					.await
			}
		}
		_ => result,
	}
}

#[cfg(test)]
mod tests;
