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

//! This file implements the `GET /health` endpoint, for load balancers and
//! container health checks. It needs no secret and reports only "ok" or
//! "error" per dependency, never error details.

use crate::config::BackendConfig;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use warp::http::StatusCode;
use warp::Filter;

/// Maximum time for each dependency check.
const CHECK_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Serialize)]
struct HealthResponse {
	status: &'static str,
	/// Only dependencies this backend is configured to use are listed.
	checks: BTreeMap<&'static str, &'static str>,
}

async fn check_health(config: &BackendConfig) -> (StatusCode, HealthResponse) {
	let mut checks = BTreeMap::new();

	if let Some(pool) = config.get_pg_pool() {
		let ping = tokio::time::timeout(CHECK_TIMEOUT, sqlx::query("SELECT 1").execute(&pool));
		let ok = matches!(ping.await, Ok(Ok(_)));
		checks.insert("database", if ok { "ok" } else { "error" });
	}

	if config.worker.enable {
		let ok = config
			.must_worker_config()
			.map(|worker| worker.channel.status().connected())
			.unwrap_or(false);
		checks.insert("rabbitmq", if ok { "ok" } else { "error" });
	}

	let healthy = checks.values().all(|state| *state == "ok");
	let (code, status) = if healthy {
		(StatusCode::OK, "ok")
	} else {
		(StatusCode::SERVICE_UNAVAILABLE, "error")
	};
	(code, HealthResponse { status, checks })
}

/// Create the `GET /health` endpoint.
pub fn get_health(
	config: Arc<BackendConfig>,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
	warp::path("health")
		.and(warp::path::end())
		.and(warp::get())
		.and_then(move || {
			let config = Arc::clone(&config);
			async move {
				let (code, body) = check_health(&config).await;
				Ok::<_, warp::Rejection>(warp::reply::with_status(warp::reply::json(&body), code))
			}
		})
}

#[cfg(test)]
mod tests {
	use super::*;
	use warp::test::request;

	#[tokio::test]
	async fn healthy_without_dependencies() {
		let resp = request()
			.path("/health")
			.method("GET")
			.reply(&get_health(Arc::new(BackendConfig::empty())))
			.await;

		assert_eq!(resp.status(), StatusCode::OK);
		assert_eq!(resp.body(), r#"{"status":"ok","checks":{}}"#);
	}

	#[tokio::test]
	async fn unhealthy_when_worker_has_no_broker() {
		let mut config = BackendConfig::empty();
		config.worker.enable = true;

		let resp = request()
			.path("/health")
			.method("GET")
			.reply(&get_health(Arc::new(config)))
			.await;

		assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
		assert_eq!(
			resp.body(),
			r#"{"status":"error","checks":{"rabbitmq":"error"}}"#
		);
	}
}
