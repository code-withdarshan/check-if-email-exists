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
use crate::worker::consume::{CHECK_EMAIL_QUEUE, FAILED_QUEUE};
use crate::worker::single_shot::send_single_shot_reply;
use check_if_email_exists::{
	check_email, CheckEmailInput, CheckEmailOutput, Reachable, LOG_TARGET,
};
use http::HeaderMap;
use lapin::message::Delivery;
use lapin::types::AMQPValue;
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
/// First delay before a bulk task is retried after a storage failure; it
/// doubles on each attempt up to `MAX_STORAGE_RETRY_DELAY`, so an unavailable
/// database does not cause a tight retry loop.
const STORAGE_RETRY_DELAY: Duration = Duration::from_secs(5);
const MAX_STORAGE_RETRY_DELAY: Duration = Duration::from_secs(60);
/// Storage attempts (about 16 minutes with the delays above) before a bulk
/// task is parked in `FAILED_QUEUE` instead of being retried again.
const MAX_STORAGE_ATTEMPTS: i64 = 20;
/// Message header counting storage attempts. RabbitMQ does not count
/// redeliveries itself, so failed tasks are republished with this header.
const STORAGE_ATTEMPTS_HEADER: &str = "x-reacher-storage-attempts";

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
						retry_after_storage_failure(&delivery, &channel, task).await?;
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

/// Number of storage attempts already recorded on a message.
fn storage_attempts(delivery: &Delivery) -> i64 {
	match delivery
		.properties
		.headers()
		.as_ref()
		.and_then(|headers| headers.inner().get(STORAGE_ATTEMPTS_HEADER))
	{
		Some(AMQPValue::LongLongInt(n)) => *n,
		Some(AMQPValue::LongInt(n)) => i64::from(*n),
		_ => 0,
	}
}

/// Delay before the given (1-based) storage retry.
fn storage_retry_delay(attempt: i64) -> Duration {
	// Clamped, so the exponent always fits a u32 and cannot overflow.
	let exponent = (attempt.clamp(1, 17) - 1) as u32;
	STORAGE_RETRY_DELAY
		.saturating_mul(2u32.pow(exponent))
		.min(MAX_STORAGE_RETRY_DELAY)
}

/// After a storage failure, republishes a bulk task with an incremented
/// attempt count (after a growing delay), or parks it in `FAILED_QUEUE` once
/// `MAX_STORAGE_ATTEMPTS` is reached. The original message is acked only
/// after the copy is published, so a failure here still redelivers it.
async fn retry_after_storage_failure(
	delivery: &Delivery,
	channel: &Channel,
	task: &CheckEmailTask,
) -> Result<(), anyhow::Error> {
	let attempt = storage_attempts(delivery) + 1;
	let queue = if attempt >= MAX_STORAGE_ATTEMPTS {
		error!(target: LOG_TARGET, email=?task.input.to_email, job_id=?task.job_id, attempt, queue=FAILED_QUEUE, "Storage kept failing, parking task");
		FAILED_QUEUE
	} else {
		tokio::time::sleep(storage_retry_delay(attempt)).await;
		CHECK_EMAIL_QUEUE
	};

	let mut headers = delivery.properties.headers().clone().unwrap_or_default();
	headers.insert(
		STORAGE_ATTEMPTS_HEADER.into(),
		AMQPValue::LongLongInt(attempt),
	);
	channel
		.basic_publish(
			"",
			queue,
			BasicPublishOptions::default(),
			&delivery.data,
			delivery.properties.clone().with_headers(headers),
		)
		.await?
		.await?;
	delivery.ack(BasicAckOptions::default()).await?;

	info!(target: LOG_TARGET, email=?task.input.to_email, attempt, queue, "Republished task after storage failure");
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

	#[test]
	fn storage_retry_delay_doubles_up_to_a_minute() {
		let delays: Vec<u64> = (1..=6).map(|a| storage_retry_delay(a).as_secs()).collect();
		assert_eq!(delays, vec![5, 10, 20, 40, 60, 60]);
		assert_eq!(storage_retry_delay(i64::MAX), MAX_STORAGE_RETRY_DELAY);
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
