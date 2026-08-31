DELETE FROM budget_reset_outbox WHERE scope = 'user';

ALTER TABLE budget_reset_outbox
    DROP CONSTRAINT IF EXISTS budget_reset_outbox_scope_check;

ALTER TABLE budget_reset_outbox
    ADD CONSTRAINT budget_reset_outbox_scope_check CHECK (scope IN ('org', 'team', 'key'));
