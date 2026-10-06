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

//! This file implements the `POST /v1/bulk` endpoint.

use std::sync::Arc;

use check_if_email_exists::LOG_TARGET;
use futures::stream::StreamExt;
use futures::stream::TryStreamExt;
use lapin::Channel;
use lapin::{options::*, publisher_confirm::Confirmation, BasicProperties};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{debug, error, info};
use warp::http::StatusCode;
use warp::Filter;

use super::with_worker_db;
use crate::config::BackendConfig;
use crate::http::account;
use crate::http::v0::check_email::post::with_config;
use crate::http::CheckEmailRequest;
use crate::http::ReacherResponseError;
use crate::worker::consume::CHECK_EMAIL_QUEUE;
use crate::worker::do_work::CheckEmailJobId;
use crate::worker::do_work::CheckEmailTask;
use crate::worker::do_work::TaskWebhook;

/// POST v1/bulk endpoint request body.
#[derive(Debug, Deserialize)]
struct Request {
	input: Vec<String>,
	webhook: Option<TaskWebhook>,
}

/// POST v1/bulk endpoint response body.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Response {
	job_id: i32,
}

async fn http_handler(
	owner: Option<uuid::Uuid>,
	config: Arc<BackendConfig>,
	pg_pool: PgPool,
	body: Request,
) -> Result<impl warp::Reply, warp::Rejection> {
	if owner.is_some() && body.webhook.is_some() {
		return Err(ReacherResponseError::new(
			StatusCode::FORBIDDEN,
			"Webhooks require machine API access.",
		)
		.into());
	}
	if body.input.is_empty() {
		return Err(ReacherResponseError::new(StatusCode::BAD_REQUEST, "Empty input").into());
	}
	if body.input.len() > config.max_bulk_emails {
		return Err(ReacherResponseError::new(
			StatusCode::BAD_REQUEST,
			format!(
				"Too many emails: {} submitted, the limit is {} per job",
				body.input.len(),
				config.max_bulk_emails
			),
		)
		.into());
	}

	// create job entry
	let job_id: i32 = sqlx::query_scalar(
		"INSERT INTO v1_bulk_job (total_records, owner_id) VALUES ($1, $2) RETURNING id",
	)
	.bind(body.input.len() as i32)
	.bind(owner)
	.fetch_one(&pg_pool)
	.await
	.map_err(ReacherResponseError::from)?;

	let n = body.input.len();
	let webhook = body.webhook.clone();
	let stream = futures::stream::iter(body.input.into_iter());

	let properties = BasicProperties::default()
		.with_content_type("application/json".into())
		.with_priority(1) // Low priority
		// Persistent, so queued tasks survive a broker restart.
		.with_delivery_mode(2);

	stream
		.map::<Result<_, ReacherResponseError>, _>(Ok)
		// Publish tasks to the queue, 10 at a time.
		.try_for_each_concurrent(10, |to_email| async {
			let input = CheckEmailRequest {
				to_email,
				public_network_only: owner.is_some(),
				..Default::default()
			}
			.to_check_email_input(Arc::clone(&config));

			let task = CheckEmailTask {
				input,
				job_id: CheckEmailJobId::Bulk(job_id),
				webhook: webhook.clone(),
				task_id: Some(uuid::Uuid::new_v4()),
			};

			publish_task(
				config
					.must_worker_config()
					.map_err(ReacherResponseError::from)?
					.channel,
				task,
				properties.clone(),
			)
			.await
		})
		.await
		.map_err(|e| {
			error!(target: LOG_TARGET, job_id=job_id, error=%e, "Bulk job only partially queued");
			ReacherResponseError::new(
				StatusCode::INTERNAL_SERVER_ERROR,
				format!("Job {} was only partially queued: {}", job_id, e),
			)
		})?;

	info!(
		target: LOG_TARGET,
		queue = CHECK_EMAIL_QUEUE,
		"Added {n} emails",
	);
	Ok(warp::reply::json(&Response { job_id: job_id }))
}

/// Publish a task to the "check_email" queue.
pub async fn publish_task(
	channel: Arc<Channel>,
	task: CheckEmailTask,
	properties: BasicProperties,
) -> Result<(), ReacherResponseError> {
	let task_json = serde_json::to_vec(&task)?;
	// The channel has publisher confirms on, so this waits for the broker to
	// take responsibility for the message; `mandatory` makes an unroutable
	// message come back instead of being dropped.
	let confirmation = channel
		.basic_publish(
			"",
			CHECK_EMAIL_QUEUE,
			BasicPublishOptions {
				mandatory: true,
				..Default::default()
			},
			&task_json,
			properties,
		)
		.await
		.map_err(ReacherResponseError::from)?
		.await
		.map_err(ReacherResponseError::from)?;
	match confirmation {
		Confirmation::Ack(None) | Confirmation::NotRequested => {}
		Confirmation::Ack(Some(_)) => {
			return Err(ReacherResponseError::new(
				StatusCode::SERVICE_UNAVAILABLE,
				format!("Queue {CHECK_EMAIL_QUEUE} does not exist"),
			))
		}
		Confirmation::Nack(_) => {
			return Err(ReacherResponseError::new(
				StatusCode::SERVICE_UNAVAILABLE,
				"The message broker refused the task",
			))
		}
	}

	debug!(target: LOG_TARGET, email=?task.input.to_email, queue=?CHECK_EMAIL_QUEUE, "Published task");

	Ok(())
}

/// Create the `POST /bulk` endpoint.
/// The endpoint accepts list of email address and creates
/// a new job to check them.
pub fn v1_create_bulk_job(
	config: Arc<BackendConfig>,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
	warp::path!("v1" / "bulk")
		.and(warp::post())
		.and(account::identity(Arc::clone(&config)))
		.and(with_config(Arc::clone(&config)))
		.and(with_worker_db(config))
		// When accepting a body, we want a JSON body (and to reject huge
		// payloads)...
		// TODO: Configure max size limit for a bulk job
		.and(warp::body::content_length_limit(1024 * 1024 * 50))
		.and(warp::body::json())
		.and_then(http_handler)
		// View access logs by setting `RUST_LOG=reacher_backend`.
		.with(warp::log(LOG_TARGET))
}
