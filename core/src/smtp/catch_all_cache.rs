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

//! Domains recently found to accept every address. Every check on such a
//! domain ends "catch-all", so further checks skip the SMTP conversation:
//! lists finish faster and the domain's servers see fewer connections.

use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Catch-all settings rarely change; a day keeps an answer from going stale.
const TTL: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_DOMAINS: usize = 100_000;

static DOMAINS: Lazy<Mutex<HashMap<String, Instant>>> = Lazy::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
thread_local! {
	/// Tests share domain names, so a test opts in to the cache on its own thread.
	pub(crate) static ENABLED_IN_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether checks use the cache: always, except in tests that didn't opt in.
pub fn enabled() -> bool {
	#[cfg(test)]
	return ENABLED_IN_TEST.with(|enabled| enabled.get());
	#[cfg(not(test))]
	true
}

/// Whether the domain was found to be catch-all within the last day.
pub fn is_known_catch_all(domain: &str) -> bool {
	let Ok(domains) = DOMAINS.lock() else { return false };
	domains
		.get(&domain.to_ascii_lowercase())
		.is_some_and(|seen| seen.elapsed() < TTL)
}

/// Records that the domain's mail server accepted a made-up address.
pub fn remember_catch_all(domain: &str) {
	let Ok(mut domains) = DOMAINS.lock() else { return };
	if domains.len() >= MAX_DOMAINS {
		domains.retain(|_, seen| seen.elapsed() < TTL);
		if domains.len() >= MAX_DOMAINS {
			domains.clear();
		}
	}
	domains.insert(domain.to_ascii_lowercase(), Instant::now());
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn remembered_domains_are_known_case_insensitively() {
		assert!(!is_known_catch_all("cache-test-accepts-all.example"));
		remember_catch_all("Cache-Test-Accepts-All.example");
		assert!(is_known_catch_all("cache-test-accepts-all.example"));
		assert!(!is_known_catch_all("cache-test-other.example"));
	}
}
