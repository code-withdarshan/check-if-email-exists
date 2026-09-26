use super::*;
use crate::misc::MiscDetails;
use crate::smtp::verif_method::{EverythingElseVerifMethod, VerifMethod, VerifMethodSmtpConfig};
use crate::{calculate_reachable, CheckEmailInputBuilder, Reachable};
use hickory_proto::rr::Name;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

enum Reply {
	Text(&'static str),
	Disconnect,
	Stall,
}

// Exercise real SMTP parsing/transactions against a local scripted server.
// No DNS lookup, external mail server or actual message delivery is used.
async fn verify(
	domain: &str,
	sessions: Vec<Vec<Reply>>,
	timeout: Duration,
) -> (Result<SmtpDetails, SmtpError>, SmtpDebug, Vec<String>) {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let port = listener.local_addr().unwrap().port();
	let retries = sessions.len();
	let server = tokio::spawn(async move {
		let mut commands = Vec::new();
		for session in sessions {
			let (stream, _) = listener.accept().await.unwrap();
			let mut stream = BufReader::new(stream);
			stream
				.get_mut()
				.write_all(b"220 mock.example ESMTP\r\n")
				.await
				.unwrap();
			let mut replies = session.into_iter();
			loop {
				let mut line = String::new();
				if stream.read_line(&mut line).await.unwrap() == 0 {
					break;
				}
				commands.push(line.trim().to_owned());
				let reply = if line.starts_with("EHLO ") || line.starts_with("MAIL FROM:") {
					"250 mock.example OK\r\n"
				} else if line.starts_with("RCPT TO:") {
					match replies.next().expect("Unexpected extra recipient probe") {
						Reply::Text(text) => text,
						Reply::Disconnect => break,
						Reply::Stall => {
							// The client times out and drops the stream.
							let mut rest = String::new();
							stream.read_line(&mut rest).await.unwrap();
							assert!(rest.is_empty());
							break;
						}
					}
				} else if line == "QUIT\r\n" {
					stream.get_mut().write_all(b"221 bye\r\n").await.unwrap();
					break;
				} else {
					panic!("Unexpected SMTP command: {:?}", line);
				};
				stream.get_mut().write_all(reply.as_bytes()).await.unwrap();
			}
			assert!(replies.next().is_none(), "Expected probe was not sent");
		}
		commands
	});
	let config = VerifMethodSmtpConfig {
		smtp_port: port,
		smtp_timeout: Some(timeout),
		retries,
		..Default::default()
	};
	let input = CheckEmailInputBuilder::default()
		.to_email(format!("target@{domain}"))
		.verif_method(VerifMethod {
			everything_else: EverythingElseVerifMethod::Smtp(config),
			..Default::default()
		})
		.build()
		.unwrap();
	let (result, debug) = crate::smtp::check_smtp(
		&EmailAddress::from_str(&format!("target@{domain}")).unwrap(),
		&Name::from_str("127.0.0.1.").unwrap(),
		domain,
		&input,
	)
	.await;
	let commands = tokio::time::timeout(Duration::from_secs(5), server)
		.await
		.unwrap()
		.unwrap();
	(result, debug, commands)
}

const MISSING: &str = "550 5.1.1 The email account that you tried to reach does not exist\r\n";
const ACCEPTED: &str = "250 2.1.5 OK\r\n";

fn reachable(result: &Result<SmtpDetails, SmtpError>) -> Reachable {
	calculate_reachable(&MiscDetails::default(), result)
}

#[tokio::test]
async fn accepted_recipient_retains_both_replies() {
	let (result, debug, commands) = verify(
		"example.com",
		vec![vec![Reply::Text(MISSING), Reply::Text(ACCEPTED)]],
		Duration::from_secs(2),
	)
	.await;
	assert_eq!(reachable(&result), Reachable::Safe);
	assert_eq!(debug.probes.len(), 2);
	assert_eq!(debug.probes[0].stage, SmtpProbeStage::CatchAll);
	assert_eq!(debug.probes[1].stage, SmtpProbeStage::Recipient);
	let json = serde_json::to_value(&debug).unwrap();
	assert_eq!(json["probes"][0]["response"]["code"], "550");
	assert_eq!(json["probes"][1]["response"]["messages"][0], "2.1.5 OK");
	assert_eq!(json["catch_all_skipped"], false);
	assert!(commands.iter().all(|command| !command.starts_with("DATA")));
}

#[tokio::test]
async fn rejected_recipient_is_invalid_with_original_multiline_reply() {
	let (result, debug, _) = verify("example.com", vec![vec![Reply::Text(MISSING), Reply::Text("550-5.1.1 The email account does not exist\r\n550 5.1.1 Please check the address\r\n")]], Duration::from_secs(2)).await;
	assert_eq!(reachable(&result), Reachable::Invalid);
	let response = debug.probes[1].response.as_ref().unwrap();
	assert_eq!(response.code, "550");
	assert_eq!(response.messages.len(), 2);
}

#[tokio::test]
async fn catch_all_is_risky_without_claiming_target_was_probed() {
	let (result, debug, commands) = verify(
		"example.com",
		vec![vec![Reply::Text(ACCEPTED)]],
		Duration::from_secs(2),
	)
	.await;
	assert_eq!(reachable(&result), Reachable::Risky);
	assert!(result.unwrap().is_catch_all);
	assert_eq!(debug.probes.len(), 1);
	assert!(!commands
		.iter()
		.any(|command| command.contains("target@example.com")));
}

#[tokio::test]
async fn catch_all_refusals_are_unknown_and_never_probe_target() {
	for reply in [
		"451 4.7.1 Try again later\r\n",
		"450 4.2.1 The user you are trying to contact is receiving mail at a rate that prevents delivery\r\n",
		"550 5.7.1 Recipient address rejected: Access denied\r\n",
		"550 5.7.1 Policy rejection\r\n",
		"450 4.1.1 User unknown, try later\r\n",
		"550 5.2.1 Account disabled\r\n",
		"452 4.2.2 The recipient's inbox is out of storage space\r\n",
		"550 Unable to verify user\r\n",
	] {
		let (result, debug, commands) = verify("example.com", vec![vec![Reply::Text(reply)]], Duration::from_secs(2)).await;
		assert_eq!(reachable(&result), Reachable::Unknown, "{reply}");
		assert_eq!(debug.probes.len(), 1);
		assert!(debug.probes[0].response.is_some());
		assert!(!commands.iter().any(|command| command.contains("target@example.com")));
	}
}

#[tokio::test]
async fn recipient_temporary_and_policy_failures_are_unknown() {
	for reply in [
		"451 4.7.1 Try again later\r\n",
		"450 4.2.1 The user you are trying to contact is receiving mail at a rate that prevents delivery\r\n",
		"550 5.7.1 Recipient address rejected: Access denied\r\n",
		"252 Cannot verify user\r\n",
	] {
		let (result, debug, _) = verify("example.com", vec![vec![Reply::Text(MISSING), Reply::Text(reply)]], Duration::from_secs(2)).await;
		assert_eq!(reachable(&result), Reachable::Unknown, "{reply}");
		assert_eq!(debug.probes.len(), 2);
		assert!(debug.probes[1].response.is_some());
	}
}

#[tokio::test]
async fn failed_attempt_is_preserved_when_retry_succeeds() {
	let (result, debug, _) = verify(
		"example.com",
		vec![
			vec![Reply::Text("451 4.7.1 Try again later\r\n")],
			vec![Reply::Text(MISSING), Reply::Text(ACCEPTED)],
		],
		Duration::from_secs(2),
	)
	.await;
	assert_eq!(reachable(&result), Reachable::Safe);
	assert_eq!(
		debug
			.probes
			.iter()
			.map(|probe| probe.attempt)
			.collect::<Vec<_>>(),
		vec![1, 2, 2]
	);
	assert_eq!(debug.probes[0].response.as_ref().unwrap().code, "451");
}

#[tokio::test]
async fn failed_catch_all_connection_and_timeout_are_unknown_with_evidence() {
	for reply in [Reply::Disconnect, Reply::Stall] {
		let (result, debug, _) =
			verify("example.com", vec![vec![reply]], Duration::from_millis(500)).await;
		assert_eq!(reachable(&result), Reachable::Unknown);
		assert_eq!(debug.probes.len(), 1);
		assert!(debug.probes[0].error.is_some());
		assert!(debug.probes[0].response.is_none());
	}
}

#[tokio::test]
async fn provider_skip_is_explicit_and_still_checks_target() {
	let (result, debug, commands) = verify(
		"gmail.com",
		vec![vec![Reply::Text(ACCEPTED)]],
		Duration::from_secs(2),
	)
	.await;
	assert_eq!(reachable(&result), Reachable::Safe);
	assert!(debug.catch_all_skipped);
	assert_eq!(debug.probes.len(), 1);
	assert_eq!(debug.probes[0].stage, SmtpProbeStage::Recipient);
	assert!(commands
		.iter()
		.any(|command| command.contains("target@gmail.com")));
}

#[tokio::test]
async fn target_full_inbox_stays_risky_and_disabled_stays_invalid() {
	for (reply, expected) in [
		(
			"452 4.2.2 The recipient's inbox is out of storage space\r\n",
			Reachable::Risky,
		),
		(
			"550 5.2.1 The email account is disabled\r\n",
			Reachable::Invalid,
		),
	] {
		let (result, _, _) = verify(
			"example.com",
			vec![vec![Reply::Text(MISSING), Reply::Text(reply)]],
			Duration::from_secs(2),
		)
		.await;
		assert_eq!(reachable(&result), expected);
	}
}
