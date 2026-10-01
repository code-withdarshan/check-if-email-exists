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

//! This file implements the `GET /v1/self_check` endpoint, which reports
//! whether this server's IP, reverse DNS, HELO name, sender address and
//! port 25 are set up so mail servers answer its checks.

use crate::config::BackendConfig;
use crate::http::check_header;
use check_if_email_exists::self_check::{run_self_check, CheckStatus, SelfCheck};
use check_if_email_exists::LOG_TARGET;
use serde::Serialize;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};
use warp::Filter;

/// Blocklist listings and DNS changes come and go, so the check repeats.
const EVERY: Duration = Duration::from_secs(60 * 60);

#[derive(Clone, Serialize)]
struct Report {
	/// Unix time of the check, in seconds.
	checked_at: u64,
	#[serde(flatten)]
	check: SelfCheck,
}

static LATEST: RwLock<Option<Report>> = RwLock::new(None);

/// Runs the self-check now and then every hour, logging what needs fixing.
pub async fn run_self_check_periodically(config: Arc<BackendConfig>) {
	loop {
		let check = run_self_check(&config.hello_name, &config.from_email).await;
		for f in &check.findings {
			match f.status {
				CheckStatus::Warn | CheckStatus::Fail => {
					warn!(target: LOG_TARGET, check=f.name, status=?f.status, "Self-check: {}", f.detail)
				}
				_ => info!(target: LOG_TARGET, check=f.name, status=?f.status, "Self-check: {}", f.detail),
			}
		}
		let checked_at = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0);
		if let Ok(mut latest) = LATEST.write() {
			*latest = Some(Report { checked_at, check });
		}
		tokio::time::sleep(EVERY).await;
	}
}

pub fn v1_get_self_check(
	config: Arc<BackendConfig>,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
	warp::path!("v1" / "self_check")
		.and(warp::get())
		.and(check_header(config))
		.map(|| {
			let latest = LATEST.read().ok().and_then(|l| l.clone());
			// null until the first check finishes, a few seconds after start.
			warp::reply::json(&latest)
		})
		.with(warp::log(LOG_TARGET))
}
