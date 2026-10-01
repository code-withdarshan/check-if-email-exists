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

//! Checks of the sending setup that decide whether mail servers answer at
//! all: the server's reverse DNS, its HELO name, blocklists, the sender
//! domain and outgoing port 25. Problems here turn many results "unknown".

use hickory_resolver::error::ResolveErrorKind;
use hickory_resolver::system_conf::read_system_conf;
use hickory_resolver::TokioAsyncResolver;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::Duration;

/// How a check went: fine, worth fixing, broken, or not checkable from here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
	Ok,
	Skipped,
	Warn,
	Fail,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckFinding {
	pub name: &'static str,
	pub status: CheckStatus,
	pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SelfCheck {
	/// The IPv4 address mail servers see, when this machine has a public one.
	pub ip: Option<String>,
	/// The worst status among the findings.
	pub status: CheckStatus,
	pub findings: Vec<CheckFinding>,
}

/// Blocklists the large providers consult. A listed IP gets refusals that
/// leave addresses "unknown".
const BLOCKLISTS: [&str; 2] = ["zen.spamhaus.org", "bl.spamcop.net"];
/// A mail server that always listens, to test that outgoing port 25 is open.
const PORT_25_TEST_HOST: &str = "gmail-smtp-in.l.google.com";
const TIMEOUT: Duration = Duration::from_secs(10);

/// The local IPv4 address used for outgoing traffic. Connecting a UDP socket
/// sends nothing; it only picks the route.
fn outgoing_ipv4() -> Option<Ipv4Addr> {
	let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
	socket.connect("8.8.8.8:53").ok()?;
	match socket.local_addr().ok()?.ip() {
		IpAddr::V4(ip) => Some(ip),
		IpAddr::V6(_) => None,
	}
}

/// Whether mail servers would see this address itself (no NAT in between).
pub fn is_public_ipv4(ip: Ipv4Addr) -> bool {
	let [a, b, ..] = ip.octets();
	!(ip.is_private()
		|| ip.is_loopback()
		|| ip.is_link_local()
		|| ip.is_unspecified()
		|| ip.is_documentation()
		// Carrier-grade NAT (100.64.0.0/10).
		|| (a == 100 && (64..128).contains(&b)))
}

/// The DNS name for looking up an IPv4 address in a blocklist zone.
pub fn blocklist_query(ip: Ipv4Addr, zone: &str) -> String {
	let [a, b, c, d] = ip.octets();
	format!("{d}.{c}.{b}.{a}.{zone}.")
}

/// Reads a blocklist answer. 127.255.255.x means the list refused the query,
/// usually because it came through a large public resolver.
fn blocklist_finding(zone: &str, answer: Option<Vec<Ipv4Addr>>) -> CheckFinding {
	let name = "blocklist";
	match answer {
		None => CheckFinding {
			name,
			status: CheckStatus::Ok,
			detail: format!("Not listed on {zone}."),
		},
		Some(codes) if codes.iter().any(|ip| ip.octets()[..3] == [127, 255, 255]) => CheckFinding {
			name,
			status: CheckStatus::Skipped,
			detail: format!(
				"{zone} refused to answer this server's DNS resolver (public resolvers are blocked); check the IP on its website."
			),
		},
		Some(codes) => CheckFinding {
			name,
			status: CheckStatus::Fail,
			detail: format!(
				"Listed on {zone} ({}). Providers that use it refuse checks from this IP; request removal on its website.",
				codes.iter().map(Ipv4Addr::to_string).collect::<Vec<_>>().join(", ")
			),
		},
	}
}

/// The HELO name compared with the reverse DNS names of the sending IP.
pub fn helo_finding(hello_name: &str, ptr_names: &[String]) -> CheckFinding {
	let name = "helo_name";
	let helo = hello_name.trim_end_matches('.').to_ascii_lowercase();
	if helo.is_empty() || helo == "localhost" || !helo.contains('.') {
		return CheckFinding {
			name,
			status: CheckStatus::Fail,
			detail: format!("The HELO name \"{hello_name}\" isn't a real host name. Set RCH__HELLO_NAME to the server's reverse DNS name."),
		};
	}
	if ptr_names.is_empty() {
		return CheckFinding {
			name,
			status: CheckStatus::Skipped,
			detail: format!("HELO name is {helo}; there is no reverse DNS name to compare it with."),
		};
	}
	if ptr_names.iter().any(|p| p.trim_end_matches('.').eq_ignore_ascii_case(&helo)) {
		CheckFinding {
			name,
			status: CheckStatus::Ok,
			detail: format!("HELO name {helo} matches the reverse DNS."),
		}
	} else {
		CheckFinding {
			name,
			status: CheckStatus::Warn,
			detail: format!(
				"HELO name {helo} differs from the reverse DNS ({}). Some providers refuse that; set RCH__HELLO_NAME to it.",
				ptr_names.join(", ")
			),
		}
	}
}

/// Runs every check. Each one has its own timeout, so this finishes within a minute.
pub async fn run_self_check(hello_name: &str, from_email: &str) -> SelfCheck {
	let mut findings = Vec::new();
	let resolver = match read_system_conf() {
		Ok((config, opts)) => Some(TokioAsyncResolver::tokio(config, opts)),
		Err(err) => {
			findings.push(CheckFinding {
				name: "dns",
				status: CheckStatus::Fail,
				detail: format!("Can't read the DNS configuration: {err}"),
			});
			None
		}
	};

	let ip = outgoing_ipv4();
	let public_ip = ip.filter(|ip| is_public_ipv4(*ip));
	match (ip, public_ip) {
		(None, _) => findings.push(CheckFinding {
			name: "ipv4",
			status: CheckStatus::Fail,
			detail: "This machine has no IPv4 route. Most mail servers can only be checked over IPv4.".into(),
		}),
		(Some(ip), None) => findings.push(CheckFinding {
			name: "ipv4",
			status: CheckStatus::Skipped,
			detail: format!("This machine's address {ip} is private (behind NAT), so its public IP's reverse DNS and blocklists can't be checked from here."),
		}),
		(Some(ip), Some(_)) => findings.push(CheckFinding {
			name: "ipv4",
			status: CheckStatus::Ok,
			detail: format!("Checks are sent from {ip}."),
		}),
	}

	if let (Some(resolver), Some(ip)) = (&resolver, public_ip) {
		// Reverse DNS that resolves back to the same IP ("forward-confirmed").
		let ptr_names: Vec<String> =
			match tokio::time::timeout(TIMEOUT, resolver.reverse_lookup(IpAddr::V4(ip))).await {
				Ok(Ok(lookup)) => lookup.iter().map(|n| n.to_ascii()).collect(),
				_ => Vec::new(),
			};
		if ptr_names.is_empty() {
			findings.push(CheckFinding {
				name: "reverse_dns",
				status: CheckStatus::Fail,
				detail: format!("{ip} has no reverse DNS (PTR) name. Gmail, Microsoft, Yahoo and others refuse such IPs; set one at your hosting provider."),
			});
		} else {
			let mut confirmed = false;
			for name in &ptr_names {
				if let Ok(Ok(lookup)) = tokio::time::timeout(TIMEOUT, resolver.ipv4_lookup(name.as_str())).await {
					confirmed |= lookup.iter().any(|a| a.0 == ip);
				}
			}
			findings.push(CheckFinding {
				name: "reverse_dns",
				status: if confirmed { CheckStatus::Ok } else { CheckStatus::Warn },
				detail: if confirmed {
					format!("{ip} has reverse DNS {}, which points back to it.", ptr_names.join(", "))
				} else {
					format!("{ip} has reverse DNS {}, but that name doesn't point back to {ip}. Add an A record for it.", ptr_names.join(", "))
				},
			});
		}
		findings.push(helo_finding(hello_name, &ptr_names));

		for zone in BLOCKLISTS {
			let query = blocklist_query(ip, zone);
			let finding = match tokio::time::timeout(TIMEOUT, resolver.ipv4_lookup(query.as_str())).await {
				Ok(Ok(lookup)) => blocklist_finding(zone, Some(lookup.iter().map(|a| a.0).collect())),
				Ok(Err(err)) if matches!(err.kind(), ResolveErrorKind::NoRecordsFound { .. }) => {
					blocklist_finding(zone, None)
				}
				_ => CheckFinding {
					name: "blocklist",
					status: CheckStatus::Skipped,
					detail: format!("Couldn't look this IP up on {zone}."),
				},
			};
			findings.push(finding);
		}
	} else if public_ip.is_none() {
		findings.push(helo_finding(hello_name, &[]));
	}

	// The sender address must look real: some servers check that its domain receives mail.
	let sender_domain = from_email.rsplit_once('@').map(|(_, d)| d.to_ascii_lowercase());
	match (&resolver, sender_domain) {
		(_, None) => findings.push(CheckFinding {
			name: "sender",
			status: CheckStatus::Fail,
			detail: format!("The sender address \"{from_email}\" isn't an email address. Set RCH__FROM_EMAIL."),
		}),
		(_, Some(domain)) if domain == "example.org" || domain == "example.com" || domain.ends_with(".example") => {
			findings.push(CheckFinding {
				name: "sender",
				status: CheckStatus::Fail,
				detail: format!("The sender address {from_email} is a placeholder. Set RCH__FROM_EMAIL to a real mailbox on your own domain."),
			})
		}
		(Some(resolver), Some(domain)) => {
			let has_mx = matches!(
				tokio::time::timeout(TIMEOUT, resolver.mx_lookup(format!("{domain}."))).await,
				Ok(Ok(lookup)) if lookup.iter().any(|mx| !crate::mx::is_unusable_mx(mx.exchange()))
			);
			findings.push(CheckFinding {
				name: "sender",
				status: if has_mx { CheckStatus::Ok } else { CheckStatus::Warn },
				detail: if has_mx {
					format!("The sender domain {domain} receives mail.")
				} else {
					format!("The sender domain {domain} has no mail server. Servers that verify the sender refuse such checks; use a domain that receives mail.")
				},
			});
		}
		(None, Some(_)) => {}
	}

	// Many hosting providers block outgoing port 25 until asked to open it.
	let port_25 = tokio::time::timeout(
		TIMEOUT,
		crate::smtp::connect_tcp(PORT_25_TEST_HOST, 25),
	)
	.await;
	findings.push(match port_25 {
		Ok(Ok(_)) => CheckFinding {
			name: "port_25",
			status: CheckStatus::Ok,
			detail: "Outgoing port 25 is open.".into(),
		},
		Ok(Err(err)) => CheckFinding {
			name: "port_25",
			status: CheckStatus::Fail,
			detail: format!("Can't open port 25 to {PORT_25_TEST_HOST}: {err}. Ask your hosting provider to unblock outgoing port 25."),
		},
		Err(_) => CheckFinding {
			name: "port_25",
			status: CheckStatus::Fail,
			detail: format!("Connecting to {PORT_25_TEST_HOST} on port 25 timed out. Outgoing port 25 is probably blocked; ask your hosting provider to open it."),
		},
	});

	SelfCheck {
		ip: public_ip.map(|ip| ip.to_string()),
		status: findings.iter().map(|f| f.status).max().unwrap_or(CheckStatus::Ok),
		findings,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn private_and_shared_addresses_are_not_public() {
		for ip in ["10.0.0.5", "192.168.1.2", "172.16.0.1", "100.64.3.4", "127.0.0.1", "169.254.1.1"] {
			assert!(!is_public_ipv4(ip.parse().unwrap()), "{ip}");
		}
		assert!(is_public_ipv4("203.0.114.9".parse().unwrap()));
		assert!(is_public_ipv4("8.8.8.8".parse().unwrap()));
	}

	#[test]
	fn blocklist_queries_reverse_the_address() {
		assert_eq!(
			blocklist_query("198.51.100.7".parse().unwrap(), "zen.spamhaus.org"),
			"7.100.51.198.zen.spamhaus.org."
		);
	}

	#[test]
	fn blocklist_answers_are_read() {
		let zone = "zen.spamhaus.org";
		assert_eq!(blocklist_finding(zone, None).status, CheckStatus::Ok);
		let listed = blocklist_finding(zone, Some(vec!["127.0.0.4".parse().unwrap()]));
		assert_eq!(listed.status, CheckStatus::Fail);
		assert!(listed.detail.contains("127.0.0.4"));
		// A refused query is not a listing.
		let refused = blocklist_finding(zone, Some(vec!["127.255.255.254".parse().unwrap()]));
		assert_eq!(refused.status, CheckStatus::Skipped);
	}

	#[test]
	fn helo_name_should_match_reverse_dns() {
		let ptr = vec!["mail.example.net.".to_string()];
		assert_eq!(helo_finding("mail.example.net", &ptr).status, CheckStatus::Ok);
		assert_eq!(helo_finding("MAIL.example.net.", &ptr).status, CheckStatus::Ok);
		assert_eq!(helo_finding("verify.example.org", &ptr).status, CheckStatus::Warn);
		assert_eq!(helo_finding("localhost", &ptr).status, CheckStatus::Fail);
		assert_eq!(helo_finding("", &[]).status, CheckStatus::Fail);
		assert_eq!(helo_finding("verify.example.org", &[]).status, CheckStatus::Skipped);
	}
}
