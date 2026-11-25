-- Rollback Migration 0042: Remove default seeded Ollama models if unreferenced

DELETE FROM global_models
WHERE id IN ('ollama/qwen2.5:0.5b', 'ollama/all-minilm:latest')
  AND NOT EXISTS (
      SELECT 1 FROM model_deployments WHERE global_model_id = global_models.id
  )
  AND NOT EXISTS (
      SELECT 1 FROM org_model_policies WHERE global_model_id = global_models.id
  );
