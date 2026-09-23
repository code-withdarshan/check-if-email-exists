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

use super::error::StorageError;
use crate::worker::do_work::{CheckEmailJobId, CheckEmailTask, TaskError};
use check_if_email_exists::{CheckEmailOutput, LOG_TARGET};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tracing::{debug, info};

#[derive(Debug)]
pub struct PostgresStorage {
	pub pg_pool: PgPool,
	extra: Option<serde_json::Value>,
}

impl PostgresStorage {
	pub async fn new(db_url: &str, extra: Option<serde_json::Value>) -> Result<Self, StorageError> {
		debug!(target: LOG_TARGET, "Connecting to PostgreSQL");
		// create connection pool with database
		// connection pool internally the shared db connection
		// with arc so it can safely be cloned and shared across threads
		let pg_pool = PgPoolOptions::new().connect(db_url).await?;

		sqlx::migrate!("./migrations").run(&pg_pool).await?;

		info!(target: LOG_TARGET, table="v1_task_result", "Connected to DB, Reacher will write verification results to DB");

		Ok(Self { pg_pool, extra })
	}

	pub async fn store(
		&self,
		task: &CheckEmailTask,
		worker_output: &Result<CheckEmailOutput, TaskError>,
		extra: Option<serde_json::Value>,
	) -> Result<(), StorageError> {
		let payload_json = serde_json::to_value(task)?;
		let (result, error) = match worker_output {
			Ok(output) => (Some(serde_json::to_value(output)?), None),
			Err(err) => (None, Some(err.to_string())),
		};
		let job_id = match task.job_id {
			CheckEmailJobId::Bulk(job_id) => Some(job_id),
			CheckEmailJobId::SingleShot => None,
		};

		// A redelivered task with the same `task_id` is a no-op, so retries
		// cannot inflate job progress. Rows without a task_id never conflict.
		let inserted = sqlx::query(
			r#"
			INSERT INTO v1_task_result (task_id, payload, job_id, extra, result, error)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (task_id) DO NOTHING
			"#,
		)
		.bind(task.task_id)
		.bind(payload_json)
		.bind(job_id)
		.bind(extra)
		.bind(result)
		.bind(error)
		.execute(&self.pg_pool)
		.await?
		.rows_affected();

		if inserted == 0 {
			debug!(target: LOG_TARGET, email=?task.input.to_email, task_id=?task.task_id, "Result already stored, skipping duplicate");
		} else {
			debug!(target: LOG_TARGET, email=?task.input.to_email, "Wrote to DB");
		}

		Ok(())
	}

	pub fn get_extra(&self) -> Option<serde_json::Value> {
		self.extra.clone()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Needs a disposable PostgreSQL database; set `TEST_DATABASE_URL` to run.
	#[tokio::test]
	async fn redelivered_task_stores_one_result() {
		let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else {
			eprintln!("TEST_DATABASE_URL unset, skipping");
			return;
		};
		let storage = PostgresStorage::new(&db_url, None).await.unwrap();
		let job_id: i32 =
			sqlx::query_scalar("INSERT INTO v1_bulk_job (total_records) VALUES (3) RETURNING id")
				.fetch_one(&storage.pg_pool)
				.await
				.unwrap();
		let task = |task_id| CheckEmailTask {
			input: Default::default(),
			job_id: CheckEmailJobId::Bulk(job_id),
			webhook: None,
			task_id,
		};
		let output = Ok(CheckEmailOutput::default());

		// The same queued task delivered twice stores one row.
		let queued = task(Some(uuid::Uuid::new_v4()));
		storage.store(&queued, &output, None).await.unwrap();
		storage.store(&queued, &output, None).await.unwrap();
		// Rows without a task_id never conflict with each other.
		storage.store(&task(None), &output, None).await.unwrap();
		storage.store(&task(None), &output, None).await.unwrap();

		let count: i64 =
			sqlx::query_scalar("SELECT COUNT(*) FROM v1_task_result WHERE job_id = $1")
				.bind(job_id)
				.fetch_one(&storage.pg_pool)
				.await
				.unwrap();
		assert_eq!(count, 3);
	}
}
