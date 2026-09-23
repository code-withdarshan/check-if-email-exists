-- Stable task identity, so a redelivered queue message stores one result.
ALTER TABLE v1_task_result ADD COLUMN task_id UUID;

-- NULLs are distinct in a unique index, so rows without a task_id (direct
-- checks, legacy messages) never conflict.
CREATE UNIQUE INDEX idx_v1_task_result_task_id ON v1_task_result (task_id);
