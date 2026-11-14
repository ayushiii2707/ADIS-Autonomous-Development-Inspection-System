-- AI usage reported by the security audit worker for each scan, so the app can
-- show the report's estimated cost and stop AI calls at SCAN_AI_BUDGET_USD.
-- Additive only.

ALTER TABLE security_scan_runs ADD COLUMN ai_input_tokens INTEGER NOT NULL DEFAULT 0;
ALTER TABLE security_scan_runs ADD COLUMN ai_cached_tokens INTEGER NOT NULL DEFAULT 0;
ALTER TABLE security_scan_runs ADD COLUMN ai_output_tokens INTEGER NOT NULL DEFAULT 0;
ALTER TABLE security_scan_runs ADD COLUMN ai_cost_usd REAL NOT NULL DEFAULT 0;
ALTER TABLE security_scan_runs ADD COLUMN ai_budget_usd REAL;
