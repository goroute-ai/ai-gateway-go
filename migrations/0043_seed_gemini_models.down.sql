-- Rollback Migration 0043: Remove default seeded Gemini models if unreferenced

DELETE FROM global_models
WHERE id IN (
    'gemini/gemini-2.5-flash',
    'gemini/gemini-2.5-pro',
    'gemini/gemini-2.5-flash-lite',
    'gemini/gemini-embedding-001'
)
  AND NOT EXISTS (
      SELECT 1 FROM model_deployments WHERE global_model_id = global_models.id
  )
  AND NOT EXISTS (
      SELECT 1 FROM org_model_policies WHERE global_model_id = global_models.id
  );
