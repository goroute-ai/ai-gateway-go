-- Persist whether a catalogue model supports an inference operation.
-- Existing catalogue rows are treated as callable to preserve legacy behavior;
-- newly imported non-inference products explicitly store FALSE.
ALTER TABLE global_models
    ADD COLUMN IF NOT EXISTS supports_inference BOOLEAN NOT NULL DEFAULT TRUE;
