DROP INDEX IF EXISTS idx_v1_task_result_task_id;
ALTER TABLE v1_task_result DROP COLUMN IF EXISTS task_id;
