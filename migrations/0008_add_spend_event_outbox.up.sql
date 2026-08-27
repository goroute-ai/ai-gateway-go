-- Spend events are committed here before an inference response is reported as successful.
CREATE TABLE IF NOT EXISTS spend_event_outbox (
    id              VARCHAR(64) PRIMARY KEY,
    payload_json    JSONB NOT NULL,
    status          VARCHAR(16) NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'processing', 'delivered', 'dead_letter')),
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_at       TIMESTAMPTZ,
    last_error      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_spend_event_outbox_pending
    ON spend_event_outbox(next_attempt_at, created_at)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_spend_event_outbox_stale
    ON spend_event_outbox(locked_at)
    WHERE status = 'processing';
