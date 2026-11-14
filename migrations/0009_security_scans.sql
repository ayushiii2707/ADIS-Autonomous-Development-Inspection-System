-- Security scans run by the security-audit-pipeline worker against a project's
-- connected GitHub or Bitbucket repository. Additive only.

CREATE TABLE IF NOT EXISTS security_scan_runs (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  connection_id TEXT REFERENCES repository_connections(id) ON DELETE SET NULL,
  provider TEXT NOT NULL CHECK (provider IN ('github', 'bitbucket')),
  repository TEXT NOT NULL,
  repo_url TEXT NOT NULL,
  branch TEXT NOT NULL,
  -- verifying: checking credentials and access; running: accepted by the worker;
  -- succeeded / failed: final state from the worker's webhook or a local check.
  status TEXT NOT NULL CHECK (status IN ('verifying', 'running', 'succeeded', 'failed')),
  stage TEXT NOT NULL DEFAULT 'verify',
  scanners_json TEXT NOT NULL DEFAULT '[]',
  ai_provider TEXT NOT NULL DEFAULT '',
  ai_model TEXT NOT NULL DEFAULT '',
  report_key TEXT,
  raw_outputs_json TEXT NOT NULL DEFAULT '[]',
  findings_count INTEGER,
  severity_counts_json TEXT NOT NULL DEFAULT '{}',
  coverage_summary_json TEXT,
  error TEXT,
  requested_by TEXT,
  created_at TEXT NOT NULL,
  started_at TEXT,
  last_heartbeat_at TEXT,
  finished_at TEXT,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_security_scan_runs_project
  ON security_scan_runs(project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS security_scan_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL REFERENCES security_scan_runs(id) ON DELETE CASCADE,
  level TEXT NOT NULL CHECK (level IN ('info', 'warn', 'error')),
  stage TEXT NOT NULL DEFAULT '',
  message TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_security_scan_logs_run
  ON security_scan_logs(run_id, id);
