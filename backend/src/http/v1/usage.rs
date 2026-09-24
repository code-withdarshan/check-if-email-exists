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

//! This file implements the `GET /v1/usage` endpoint, which reports how much
//! of each throttle window this process has used.

use crate::config::BackendConfig;
use crate::http::check_header;
use check_if_email_exists::LOG_TARGET;
use std::sync::Arc;
use warp::Filter;

pub fn v1_get_usage(
	config: Arc<BackendConfig>,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
	warp::path!("v1" / "usage")
		.and(warp::get())
		.and(check_header(Arc::clone(&config)))
		.and_then(move || {
			let throttle = config.get_throttle_manager();
			async move { Ok::<_, warp::Rejection>(warp::reply::json(&throttle.usage().await)) }
		})
		.with(warp::log(LOG_TARGET))
}
