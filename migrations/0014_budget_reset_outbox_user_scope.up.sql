ALTER TABLE budget_reset_outbox
    DROP CONSTRAINT IF EXISTS budget_reset_outbox_scope_check;

DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT conname
        FROM pg_constraint
        WHERE conrelid = 'budget_reset_outbox'::regclass
          AND contype = 'c'
          AND pg_get_constraintdef(oid) LIKE '%scope%'
    LOOP
        EXECUTE format('ALTER TABLE budget_reset_outbox DROP CONSTRAINT %I', r.conname);
    END LOOP;
END $$;

ALTER TABLE budget_reset_outbox
    ADD CONSTRAINT budget_reset_outbox_scope_check CHECK (scope IN ('org', 'team', 'user', 'key'));
