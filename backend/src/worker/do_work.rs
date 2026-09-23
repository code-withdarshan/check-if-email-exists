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

use crate::config::BackendConfig;
use crate::storage::commercial_license_trial::send_to_reacher;
use crate::throttle::ThrottleResult;
use crate::worker::single_shot::send_single_shot_reply;
use check_if_email_exists::{
	check_email, CheckEmailInput, CheckEmailOutput, Reachable, LOG_TARGET,
};
use http::HeaderMap;
use lapin::message::Delivery;
use lapin::{options::*, Channel};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, error, info};
use warp::http::StatusCode;

#[derive(Debug, Deserialize, Serialize)]
pub struct CheckEmailTask {
	pub input: CheckEmailInput,
	pub job_id: CheckEmailJobId,
	pub webhook: Option<TaskWebhook>,
	/// Stable identity of a queued task, so a redelivered message cannot store
	/// a second result. Absent on messages published before it existed.
	#[serde(default)]
	pub task_id: Option<uuid::Uuid>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckEmailJobId {
	/// Single-shot email verification, they won't have an actual job id.
	SingleShot,
	/// Job id of the bulk verification.
	Bulk(i32),
}

/// The errors that can occur when processing a task.
#[derive(Debug, Error)]
pub enum TaskError {
	/// The worker is at full capacity and cannot accept more tasks. Note that
	/// this error only occurs for single-shot tasks, and not for bulk
	/// verification, as for bulk verification tasks the task will simply stay
	/// in the queue until one worker is ready to process it.
	#[error("Worker at full capacity, wait {0:?}")]
	Throttle(ThrottleResult),
	#[error("Lapin error: {0}")]
	Lapin(lapin::Error),
	#[error("Reqwest error during webhook: {0}")]
	Reqwest(reqwest::Error),
	#[error("Error converting headers: {0}")]
	Headers(#[from] http::Error),
}

impl TaskError {
	/// Returns the status code that should be returned to the client.
	pub fn status_code(&self) -> StatusCode {
		match self {
			Self::Throttle(_) => StatusCode::TOO_MANY_REQUESTS,
			Self::Lapin(_) => StatusCode::INTERNAL_SERVER_ERROR,
			Self::Reqwest(_) => StatusCode::INTERNAL_SERVER_ERROR,
			Self::Headers(_) => StatusCode::INTERNAL_SERVER_ERROR,
		}
	}
}

impl From<lapin::Error> for TaskError {
	fn from(err: lapin::Error) -> Self {
		Self::Lapin(err)
	}
}

impl From<reqwest::Error> for TaskError {
	fn from(err: reqwest::Error) -> Self {
		Self::Reqwest(err)
	}
}

impl Serialize for TaskError {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		serializer.serialize_str(&self.to_string())
	}
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct TaskWebhook {
	pub on_each_email: Option<Webhook>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct Webhook {
	pub url: String,
	pub headers: HashMap<String, String>,
	pub extra: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct WebhookOutput<'a> {
	result: &'a CheckEmailOutput,
	extra: &'a Option<serde_json::Value>,
}

/// Maximum time for one webhook request.
const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);
/// Webhook delivery attempts before giving up.
const WEBHOOK_ATTEMPTS: u32 = 3;
/// Base delay between webhook attempts; multiplied by the attempt number.
const WEBHOOK_RETRY_DELAY: Duration = Duration::from_secs(2);
/// Delay before a bulk task is requeued after a storage failure, so an
/// unavailable database does not cause a tight retry loop.
const STORAGE_RETRY_DELAY: Duration = Duration::from_secs(5);

/// Processes the check email task asynchronously.
pub(crate) async fn do_check_email_work(
	task: &CheckEmailTask,
	delivery: Delivery,
	channel: Arc<Channel>,
	config: Arc<BackendConfig>,
) -> Result<(), anyhow::Error> {
	// The webhook is sent only once the final result is stored (below), so a
	// retried verification does not notify twice, and a webhook failure does
	// not re-run the verification.
	let worker_output: Result<CheckEmailOutput, TaskError> = Ok(check_email(&task.input).await);

	match (&worker_output, delivery.redelivered) {
		(Ok(output), false) if output.is_reachable == Reachable::Unknown => {
			// If is_reachable is unknown, then we requeue the message, but only once.
			// We might want to add a requeue counter in the future, see:
			// https://stackoverflow.com/questions/25226080/rabbitmq-how-to-requeue-message-with-counter
			delivery
				.reject(BasicRejectOptions { requeue: true })
				.await?;
			info!(target: LOG_TARGET, email=?&task.input.to_email, is_reachable=?Reachable::Unknown, "Requeued message");
		}
		(Err(e), false) => {
			// Same as above, if processing the message failed, we requeue it.
			delivery
				.reject(BasicRejectOptions { requeue: true })
				.await?;
			info!(target: LOG_TARGET, email=?&task.input.to_email, err=?e, "Requeued message");
		}
		_ => {
			// This is the happy path. We store the result *before*
			// acknowledging, so a storage failure leaves the task recoverable
			// instead of silently losing it.
			let storage = config.get_storage_adapter();
			if let Err(e) = storage
				.store(task, &worker_output, storage.get_extra())
				.await
			{
				match task.job_id {
					CheckEmailJobId::SingleShot => {
						// The caller is waiting on this answer: reply anyway
						// and drop the message.
						delivery
							.reject(BasicRejectOptions { requeue: false })
							.await?;
						send_single_shot_reply(channel, &delivery, &worker_output).await?;
					}
					CheckEmailJobId::Bulk(_) => {
						tokio::time::sleep(STORAGE_RETRY_DELAY).await;
						delivery
							.reject(BasicRejectOptions { requeue: true })
							.await?;
						info!(target: LOG_TARGET, email=?&task.input.to_email, "Requeued message after storage failure");
					}
				}
				return Err(e.into());
			}

			delivery.ack(BasicAckOptions::default()).await?;

			if let CheckEmailJobId::SingleShot = task.job_id {
				send_single_shot_reply(channel, &delivery, &worker_output).await?;
			}

			// The result is safely stored, so a webhook failure is logged
			// rather than failing (and retrying) the task.
			if let Ok(output) = &worker_output {
				if let Err(e) = send_webhook(task, output).await {
					error!(target: LOG_TARGET, email=?task.input.to_email, job_id=?task.job_id, error=%e, "Webhook delivery failed");
				}
			}

			// If we're in the Commercial License Trial, we also store the
			// result by sending it to back to Reacher.
			send_to_reacher(config, &task.input.to_email, &worker_output).await?;

			info!(target: LOG_TARGET,
				email=task.input.to_email,
				worker_output=?worker_output.map(|o| o.is_reachable),
				job_id=?task.job_id,
				"Done check",
			);
		}
	}

	Ok(())
}

/// Checks the email and sends the result to the webhook. Used by the SQS
/// handler; the RabbitMQ worker sends the webhook after storing instead.
pub async fn check_email_and_send_result(
	task: &CheckEmailTask,
) -> Result<CheckEmailOutput, TaskError> {
	let output = check_email(&task.input).await;
	send_webhook(task, &output).await?;
	Ok(output)
}

/// Sends a result to the task's `on_each_email` webhook, if any. Each attempt
/// has a timeout, non-2xx responses count as failures, and failures are
/// retried with a growing delay. The `x-reacher-task-id` header lets the
/// receiver discard duplicate deliveries.
pub async fn send_webhook(
	task: &CheckEmailTask,
	output: &CheckEmailOutput,
) -> Result<(), TaskError> {
	let Some(TaskWebhook {
		on_each_email: Some(webhook),
	}) = &task.webhook
	else {
		return Ok(());
	};

	let webhook_output = WebhookOutput {
		result: output,
		extra: &webhook.extra,
	};
	let headers: HeaderMap = (&webhook.headers).try_into()?;
	let client = reqwest::Client::builder()
		.timeout(WEBHOOK_TIMEOUT)
		.build()?;

	let mut attempt = 1;
	loop {
		let mut request = client
			.post(&webhook.url)
			.json(&webhook_output)
			.headers(headers.clone());
		if let Some(task_id) = task.task_id {
			request = request.header("x-reacher-task-id", task_id.to_string());
		}

		match request.send().await.and_then(|res| res.error_for_status()) {
			Ok(res) => {
				debug!(target: LOG_TARGET, email=?output.input, status=%res.status(), attempt, "Webhook delivered");
				return Ok(());
			}
			Err(e) if attempt < WEBHOOK_ATTEMPTS => {
				debug!(target: LOG_TARGET, email=?output.input, error=%e, attempt, "Webhook attempt failed, retrying");
				tokio::time::sleep(WEBHOOK_RETRY_DELAY * attempt).await;
				attempt += 1;
			}
			Err(e) => return Err(e.into()),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn decodes_messages_published_without_task_id() {
		let task = CheckEmailTask {
			input: CheckEmailInput::default(),
			job_id: CheckEmailJobId::Bulk(1),
			webhook: None,
			task_id: Some(uuid::Uuid::new_v4()),
		};
		let mut json = serde_json::to_value(&task).unwrap();
		json.as_object_mut().unwrap().remove("task_id");

		let decoded: CheckEmailTask = serde_json::from_value(json).unwrap();
		assert_eq!(decoded.task_id, None);
	}

	#[tokio::test]
	async fn webhook_retries_failed_status_and_sends_task_id() {
		use std::sync::atomic::{AtomicUsize, Ordering};
		use std::sync::Mutex;
		use warp::Filter;

		// Fails the first request with 500, accepts the second.
		let hits = Arc::new(AtomicUsize::new(0));
		let seen_ids = Arc::new(Mutex::new(Vec::new()));
		let route = warp::post()
			.and(warp::header::optional::<String>("x-reacher-task-id"))
			.map({
				let (hits, seen_ids) = (hits.clone(), seen_ids.clone());
				move |task_id: Option<String>| {
					seen_ids.lock().unwrap().push(task_id);
					let status = if hits.fetch_add(1, Ordering::SeqCst) == 0 {
						StatusCode::INTERNAL_SERVER_ERROR
					} else {
						StatusCode::OK
					};
					warp::reply::with_status("", status)
				}
			});
		let (addr, server) = warp::serve(route).bind_ephemeral(([127, 0, 0, 1], 0));
		tokio::spawn(server);

		let task_id = uuid::Uuid::new_v4();
		let task = CheckEmailTask {
			input: CheckEmailInput::default(),
			job_id: CheckEmailJobId::Bulk(1),
			webhook: Some(TaskWebhook {
				on_each_email: Some(Webhook {
					url: format!("http://{addr}/"),
					headers: HashMap::new(),
					extra: None,
				}),
			}),
			task_id: Some(task_id),
		};

		send_webhook(&task, &CheckEmailOutput::default())
			.await
			.unwrap();

		assert_eq!(hits.load(Ordering::SeqCst), 2);
		let expected = Some(task_id.to_string());
		assert_eq!(*seen_ids.lock().unwrap(), vec![expected.clone(), expected]);
	}
}
