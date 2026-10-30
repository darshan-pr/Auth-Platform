CREATE INDEX idx_audit_logs_created_actor_action
    ON audit_logs (created_at DESC, actor_type, action);
