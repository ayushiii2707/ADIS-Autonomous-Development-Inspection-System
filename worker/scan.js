// Security scans: the app is the control plane for the security-audit-pipeline
// worker (github.com/ayushiii2707/security-audit-pipeline).
//
//   Run full scan → re-verify the stored credential, repository access and branch
//   with GitHub/Bitbucket → check the worker is up and free → dispatch a job signed
//   with a short-lived Ed25519 token → the worker clones, scans, merges findings,
//   writes the AI report and uploads results to the app's S3-compatible artifact
//   store → it reports logs, heartbeats and the final result back to /scan-worker/*.
//
// Callbacks and uploads are authenticated: callbacks carry the run's own signed
// token; uploads are AWS Signature V4 requests signed with the store's credentials.

import { createHash, createHmac, createPrivateKey, createPublicKey, randomUUID, sign, timingSafeEqual, verify } from 'node:crypto';

export const SCAN_BUCKET = 'adis-scan-artifacts';
const TOKEN_PREFIX = 'adisjob2.';
const DISPATCH_SCOPE = 'dispatch:security-audit';
const CALLBACK_SCOPE = 'callback:security-audit';
const KNOWN_SCANNERS = ['codeql', 'opengrep', 'sonarqube', 'dependency-track', 'bom-cyclonedx', 'trivy', 'osv', 'trufflehog', 'nuclei', 'zap'];
const DEFAULT_SCANNERS = ['codeql', 'opengrep', 'trivy', 'osv', 'trufflehog'];
const HEARTBEAT_TIMEOUT_MS = 10 * 60 * 1000;
const RUN_TOKEN_TTL_S = 6 * 60 * 60;
const STAGES = new Set(['verify', 'setup', 'clone', 'scan', 'coverage', 'claude', 'pdf', 'upload', 'complete', 'failed', 'cleanup']);
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

const now = () => new Date().toISOString();
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' } });
const parseJson = (value, fallback) => { try { return JSON.parse(value); } catch { return fallback; } };
const clip = (value, max) => String(value ?? '').slice(0, max);

export class ScanError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function scanConfig(env) {
  const scanners = String(env.SCAN_SCANNERS || '').split(',').map((item) => item.trim()).filter((item) => KNOWN_SCANNERS.includes(item));
  return {
    workerUrl: String(env.SCAN_WORKER_URL || 'http://127.0.0.1:4101').replace(/\/+$/, ''),
    scanners: scanners.length ? scanners : DEFAULT_SCANNERS,
    aiProvider: env.SCAN_AI_PROVIDER === 'anthropic-claude-code' ? 'anthropic-claude-code' : 'openai-codex',
    aiKey: String(env.SCAN_AI_API_KEY || '').trim(),
    aiModel: String(env.SCAN_AI_MODEL || '').trim(),
  };
}

// ---------- tokens (format verified by the worker's job-token-verify.ts) ----------

export function mintRunToken(privatePem, { kind, scope, run, ttlSeconds = RUN_TOKEN_TTL_S }) {
  const iat = Math.floor(Date.now() / 1000);
  const body = Buffer.from(JSON.stringify({ v: 2, ws: 1, kind, scopes: [scope], run, iat, exp: iat + ttlSeconds, jti: randomUUID() })).toString('base64url');
  const signature = sign(null, Buffer.from(TOKEN_PREFIX + body), createPrivateKey(privatePem)).toString('base64url');
  return `${TOKEN_PREFIX}${body}.${signature}`;
}

export function verifyRunToken(publicPem, header) {
  const raw = String(header || '').trim().replace(/^bearer\s+/i, '');
  if (!raw.startsWith(TOKEN_PREFIX)) return null;
  const [body, signature, extra] = raw.slice(TOKEN_PREFIX.length).split('.');
  if (!body || !signature || extra !== undefined) return null;
  let ok = false;
  try { ok = verify(null, Buffer.from(TOKEN_PREFIX + body), createPublicKey(publicPem), Buffer.from(signature, 'base64url')); } catch { ok = false; }
  if (!ok) return null;
  const claims = parseJson(Buffer.from(body, 'base64url').toString('utf8'), null);
  if (!claims || claims.v !== 2 || !Array.isArray(claims.scopes) || typeof claims.run !== 'string') return null;
  if (!Number.isSafeInteger(claims.exp) || Math.floor(Date.now() / 1000) >= claims.exp) return null;
  return claims;
}

// ---------- run records ----------

async function addLog(env, runId, level, stage, message) {
  await env.DB.prepare('INSERT INTO security_scan_logs(run_id,level,stage,message,created_at) VALUES(?,?,?,?,?)')
    .bind(runId, ['info', 'warn', 'error'].includes(level) ? level : 'info', clip(stage, 40), clip(message, 4000), now()).run();
}

async function failRun(env, runId, stage, message) {
  const at = now();
  await env.DB.batch([
    env.DB.prepare("UPDATE security_scan_runs SET status='failed',stage=?,error=?,finished_at=?,updated_at=? WHERE id=? AND status IN ('verifying','running')").bind(stage, clip(message, 2000), at, at, runId),
    env.DB.prepare('INSERT INTO security_scan_logs(run_id,level,stage,message,created_at) VALUES(?,?,?,?,?)').bind(runId, 'error', stage, clip(message, 4000), at),
  ]);
}

// A worker that stops sending heartbeats has died; record that instead of waiting forever.
async function reconcileStale(env, run) {
  if (!run || run.status !== 'running') return run;
  const last = Date.parse(run.last_heartbeat_at || run.started_at || run.created_at);
  if (Number.isFinite(last) && Date.now() - last > HEARTBEAT_TIMEOUT_MS) {
    await failRun(env, run.id, run.stage || 'scan', 'The scan worker stopped responding (no heartbeat for 10 minutes). Check the worker with: npm run scan-worker:logs');
    return env.DB.prepare('SELECT * FROM security_scan_runs WHERE id=?').bind(run.id).first();
  }
  return run;
}

function publicRun(run) {
  if (!run) return null;
  return {
    id: run.id, provider: run.provider, repository: run.repository, branch: run.branch, status: run.status, stage: run.stage,
    scanners: parseJson(run.scanners_json, []), ai_provider: run.ai_provider, ai_model: run.ai_model,
    report_available: Boolean(run.report_key), findings_count: run.findings_count, severity_counts: parseJson(run.severity_counts_json, {}),
    coverage_summary: parseJson(run.coverage_summary_json || 'null', null), raw_outputs: parseJson(run.raw_outputs_json, []).map((item) => ({ filename: item.filename, scanner: item.scannerKey })),
    error: run.error && run.error.includes('\n') ? summarizeWorkerError(run.error) : run.error, created_at: run.created_at, started_at: run.started_at, last_heartbeat_at: run.last_heartbeat_at, finished_at: run.finished_at,
  };
}

// ---------- start: verify credentials and access, then dispatch ----------

export function numericProjectRef(projectId) {
  return (parseInt(createHash('sha256').update(String(projectId)).digest('hex').slice(0, 8), 16) % 2000000000) + 1;
}

function gitCredentials(connection, bundle, bitbucketMethod) {
  if (connection.provider === 'github') return { username: 'x-access-token', token: bundle.token };
  // Bitbucket git-over-HTTPS usernames per credential type: workspace/repository
  // access tokens use x-token-auth; Atlassian API tokens use x-bitbucket-api-token-auth;
  // legacy app passwords use the account username.
  if (bitbucketMethod === 'bearer') return { username: 'x-token-auth', token: bundle.token };
  if (bitbucketMethod === 'email') return { username: 'x-bitbucket-api-token-auth', token: bundle.token };
  return { username: bundle.username, token: bundle.token };
}

async function verifyAccess(env, ctx, connection, branch) {
  let bundle;
  try { bundle = await ctx.credentialBundle(connection, env); } catch (error) { throw new ScanError(400, error.message); }
  if (connection.provider === 'github') {
    const repo = await ctx.github(ctx.repoPath(connection.owner, connection.repository), bundle.token);
    if (repo.error) throw new ScanError(repo.status === 503 ? 503 : 400, repo.error);
    const permissions = repo.data.permissions || {};
    if (!permissions.pull && !permissions.push && !permissions.admin) throw new ScanError(400, 'The token authenticated, but can no longer read this repository.');
    const ref = await ctx.github(ctx.repoPath(connection.owner, connection.repository, '/branches/' + encodeURIComponent(branch)), bundle.token);
    if (ref.error) throw new ScanError(400, ref.status === 404 ? `Branch "${branch}" no longer exists in ${connection.owner}/${connection.repository}.` : ref.error);
    return { bundle, method: 'pat', summary: `${repo.data.full_name || connection.owner + '/' + connection.repository} is reachable and readable` };
  }
  const repoPath = ctx.bitbucketPath(connection.owner, connection.repository);
  const repo = await ctx.bitbucket(repoPath, bundle);
  if (repo.error) throw new ScanError(repo.status === 503 ? 503 : 400, repo.error);
  let method = repo.auth;
  if (method === 'basic') {
    // Distinguish an Atlassian API token (email) from an app password (username): git needs a different username for each.
    const emailOnly = bundle.email ? await ctx.bitbucket(repoPath, { token: bundle.token, email: bundle.email }) : null;
    method = emailOnly && !emailOnly.error && emailOnly.auth === 'basic' ? 'email' : 'username';
  }
  const ref = await ctx.bitbucket(ctx.bitbucketPath(connection.owner, connection.repository, '/refs/branches/' + encodeURIComponent(branch)), bundle);
  if (ref.error) throw new ScanError(400, ref.status === 404 ? `Branch "${branch}" no longer exists in ${connection.owner}/${connection.repository}.` : ref.error);
  return { bundle, method, summary: `${connection.owner}/${connection.repository} is reachable and readable` };
}

async function workerRequest(url, options = {}, timeoutMs = 15000) {
  const control = new AbortController();
  const timer = setTimeout(() => control.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: control.signal });
  } finally {
    clearTimeout(timer);
  }
}

export async function startScan(env, ctx, projectId, actorId) {
  if (!env.SCAN_DISPATCH_PRIVATE_KEY || !env.SCAN_STORE) throw new ScanError(503, 'Security scanning is not available on this server.');
  const config = scanConfig(env);
  const active = await reconcileStale(env, await env.DB.prepare("SELECT * FROM security_scan_runs WHERE project_id=? AND status IN ('verifying','running') ORDER BY created_at DESC LIMIT 1").bind(projectId).first());
  if (active && ['verifying', 'running'].includes(active.status)) throw new ScanError(409, 'A scan is already running for this project.');
  const setup = await env.DB.prepare('SELECT connection_id,selected_branch,setup_completed_at FROM project_setup WHERE project_id=?').bind(projectId).first();
  if (!setup?.setup_completed_at || !setup.connection_id || !setup.selected_branch) throw new ScanError(400, 'Finish connecting the repository and choosing a branch before scanning.');
  const connection = await ctx.connectionFor(env, projectId, setup.connection_id);
  if (!connection) throw new ScanError(400, 'The repository connection for this project no longer exists. Connect the repository again.');
  if (!config.aiKey) throw new ScanError(400, 'The security pipeline writes its report with an AI model. Set SCAN_AI_API_KEY (your OpenAI key) in .env and restart the app.');

  const runId = 'scan-' + randomUUID();
  const at = now();
  const label = `${connection.owner}/${connection.repository}`;
  const repoUrl = connection.provider === 'github'
    ? `https://github.com/${encodeURIComponent(connection.owner)}/${encodeURIComponent(connection.repository)}.git`
    : `https://bitbucket.org/${encodeURIComponent(connection.owner)}/${encodeURIComponent(connection.repository)}.git`;
  await env.DB.batch([
    env.DB.prepare('INSERT INTO security_scan_runs(id,project_id,connection_id,provider,repository,repo_url,branch,status,stage,scanners_json,ai_provider,ai_model,requested_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
      .bind(runId, projectId, connection.id, connection.provider, label, repoUrl, setup.selected_branch, 'verifying', 'verify', JSON.stringify(config.scanners), config.aiProvider, config.aiModel || (config.aiProvider === 'openai-codex' ? 'gpt-5' : 'claude-haiku-5-5'), actorId || null, at, at),
    env.DB.prepare('INSERT INTO security_scan_logs(run_id,level,stage,message,created_at) VALUES(?,?,?,?,?)').bind(runId, 'info', 'verify', `Verifying the ${connection.provider === 'github' ? 'GitHub' : 'Bitbucket'} credential, access to ${label}, and branch "${setup.selected_branch}".`, at),
  ]);

  try {
    const access = await verifyAccess(env, ctx, connection, setup.selected_branch);
    await addLog(env, runId, 'info', 'verify', `Credential verified: ${access.summary}; branch "${setup.selected_branch}" exists.`);

    let health;
    try {
      const response = await workerRequest(config.workerUrl + '/health', {}, 8000);
      health = await response.json();
    } catch {
      throw new ScanError(503, 'The security scan worker is not running. Start it with: npm run scan-worker:start');
    }
    if (health?.busy) throw new ScanError(409, 'The scan worker is busy with another scan. Try again when it finishes.');

    const callbackToken = mintRunToken(env.SCAN_DISPATCH_PRIVATE_KEY, { kind: 'job', scope: CALLBACK_SCOPE, run: runId });
    const dispatchToken = mintRunToken(env.SCAN_DISPATCH_PRIVATE_KEY, { kind: 'dispatch', scope: DISPATCH_SCOPE, run: runId, ttlSeconds: 300 });
    const base = `http://worker-callback/scan-worker/runs/${encodeURIComponent(runId)}`;
    const job = {
      runId,
      // The worker's AI-usage metering requires a numeric project reference; derive a stable one from the project id.
      softwareProjectId: numericProjectRef(projectId),
      sourceType: connection.provider === 'github' ? 'GITHUB' : 'BITBUCKET',
      repoUrl,
      targetRef: setup.selected_branch,
      credentials: gitCredentials(connection, access.bundle, access.method),
      // The worker re-bases these onto its configured API_PUBLIC_URL; only the path is used.
      webhookUrl: base + '/webhook',
      logWebhookUrl: base + '/logs',
      heartbeatUrl: base + '/heartbeat',
      scannerKeys: config.scanners,
      providerConfig: { providerKey: config.aiProvider, apiKey: config.aiKey, ...(config.aiModel ? { models: { plan: config.aiModel } } : {}) },
      scanMode: 'full',
      jobToken: callbackToken,
    };
    let response;
    try {
      response = await workerRequest(config.workerUrl + '/jobs', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + dispatchToken }, body: JSON.stringify(job) }, 30000);
    } catch {
      throw new ScanError(503, 'The security scan worker did not accept the job. Check it with: npm run scan-worker:logs');
    }
    const reply = await response.json().catch(() => ({}));
    if (response.status === 403) throw new ScanError(503, 'The scan worker rejected this app\'s signed job. Restart it with npm run scan-worker:start so it uses this app\'s key.');
    if (response.status === 409) throw new ScanError(409, 'The scan worker is busy with another scan. Try again when it finishes.');
    if (response.status === 503) throw new ScanError(503, 'The scan worker is not ready: ' + (Array.isArray(reply.issues) ? reply.issues.join('; ') : 'unknown reason') + '.');
    if (!response.ok) throw new ScanError(502, 'The scan worker refused the job: ' + clip(reply.error || JSON.stringify(reply.issues || reply), 300));
    const started = now();
    await env.DB.batch([
      env.DB.prepare("UPDATE security_scan_runs SET status='running',stage='setup',started_at=?,last_heartbeat_at=?,updated_at=? WHERE id=? AND status='verifying'").bind(started, started, started, runId),
      env.DB.prepare('INSERT INTO security_scan_logs(run_id,level,stage,message,created_at) VALUES(?,?,?,?,?)').bind(runId, 'info', 'setup', `The security audit worker accepted the scan (${config.scanners.join(', ')}).`, started),
    ]);
  } catch (error) {
    const message = error instanceof ScanError ? error.message : 'The scan could not be started.';
    if (!(error instanceof ScanError)) console.error('Scan start failed:', error instanceof Error ? error.message : 'unknown error');
    await failRun(env, runId, 'verify', message);
  }
  return publicRun(await env.DB.prepare('SELECT * FROM security_scan_runs WHERE id=?').bind(runId).first());
}

// The stage a failed run stopped in: the last pipeline stage logged before its first failure.
function failedStage(logs, fallback) {
  const first = logs.findIndex((log) => log.stage === 'failed');
  if (first < 0) return fallback;
  const before = logs.slice(0, first).reverse().find((log) => log.stage && !['failed', 'cleanup'].includes(log.stage));
  return before ? before.stage : fallback;
}

// ---------- browser API ----------

// Scanners report severity in their own vocabulary (SARIF error/warning/note,
// OpenGrep ERROR/WARNING/INFO, CVSS-style critical/high/…). Map to one scale for
// counting and filtering; the original value is kept on each finding.
export function normalizeSeverity(raw) {
  const value = String(raw || '').toLowerCase();
  if (value === 'critical') return 'critical';
  if (value === 'high' || value === 'error') return 'high';
  if (value === 'medium' || value === 'moderate' || value === 'warning') return 'medium';
  if (value === 'low' || value === 'note') return 'low';
  return 'info';
}

// The pipeline's de-duplicated findings register, written on its success path.
// When the run stops before that (for example the AI report step fails), the
// pipeline has still saved its fingerprinted baseline snapshot of every finding.
async function findingsFor(env, run) {
  const outputs = parseJson(run.raw_outputs_json, []);
  const register = outputs.find((item) => item.filename === 'findings-register.json' || String(item.s3Key || '').endsWith('/findings-register.json'));
  const registerFile = register ? await env.SCAN_STORE.get(register.s3Key) : null;
  const registerEntries = registerFile ? parseJson(registerFile.body.toString('utf8'), null)?.entries : null;
  let entries = Array.isArray(registerEntries) ? registerEntries : null;
  let source = 'register';
  if (!entries) {
    const snapshot = await env.SCAN_STORE.get(`security-baselines/${run.id}.json`);
    const snapshotFindings = snapshot ? parseJson(snapshot.body.toString('utf8'), null)?.findings : null;
    if (!Array.isArray(snapshotFindings)) return null;
    entries = snapshotFindings;
    source = 'baseline';
  }
  return {
    source,
    entries: entries.map((item) => ({ id: item.id || item.stableKey || item.fingerprint, scanner: item.scanner, ruleId: item.ruleId, filePath: item.filePath, startLine: item.startLine, severity: normalizeSeverity(item.severity), scannerSeverity: item.severity, message: item.message, fingerprint: item.fingerprint })),
  };
}

function severityCounts(entries) {
  const counts = Object.fromEntries(SEVERITIES.map((key) => [key, 0]));
  for (const entry of entries) counts[normalizeSeverity(entry.severity)] += 1;
  return counts;
}

// The worker's error text can include an AI agent's whole transcript; keep the
// first line (what failed) and the last provider error line (why).
export function summarizeWorkerError(text) {
  const lines = String(text || '').split('\n').map((line) => line.trim()).filter(Boolean);
  if (!lines.length) return 'The security audit failed.';
  const cause = [...lines].reverse().find((line) => /^ERROR:/.test(line) && !/Reconnecting/.test(line));
  const head = lines[0].replace(/:\s*Reading prompt from stdin\.\.\.$/, '');
  if (cause) return clip(`${head}: ${cause.replace(/^ERROR:\s*/, '')}`, 1000);
  return clip(lines.length > 1 ? `${head}. See the pipeline log for details.` : head, 1000);
}

export async function scanRoute(req, env, path, method, ctx) {
  const base = path.match(/^\/api\/projects\/([^/]+)\/scans(?:\/([^/]+)(?:\/(findings|report))?)?$/);
  if (!base) return null;
  const projectId = decodeURIComponent(base[1]);
  const project = await ctx.ownedProject(env, req, projectId);
  if (!project) return json({ error: 'Project not found.' }, 404);
  const runId = base[2] ? decodeURIComponent(base[2]) : null;
  try {
    if (!runId) {
      if (method === 'POST') return json({ run: await startScan(env, ctx, projectId, ctx.userId(req, env)) }, 201);
      if (method !== 'GET') return json({ error: 'Method not allowed.' }, 405);
      const rows = (await env.DB.prepare('SELECT * FROM security_scan_runs WHERE project_id=? ORDER BY created_at DESC LIMIT 20').bind(projectId).all()).results;
      const runs = [];
      for (const row of rows) runs.push(publicRun(await reconcileStale(env, row)));
      return json({ runs, configured: Boolean(env.SCAN_DISPATCH_PRIVATE_KEY && env.SCAN_STORE), ai_key_configured: Boolean(scanConfig(env).aiKey) });
    }
    if (method !== 'GET') return json({ error: 'Method not allowed.' }, 405);
    let run = await reconcileStale(env, await env.DB.prepare('SELECT * FROM security_scan_runs WHERE id=? AND project_id=?').bind(runId, projectId).first());
    if (!run) return json({ error: 'Scan not found.' }, 404);
    // Fill in finding counts for a finished run whose results were stored without them.
    if (['succeeded', 'failed'].includes(run.status) && run.findings_count === null) {
      const found = await findingsFor(env, run);
      if (found) {
        await env.DB.prepare('UPDATE security_scan_runs SET findings_count=?,severity_counts_json=? WHERE id=?').bind(found.entries.length, JSON.stringify(severityCounts(found.entries)), run.id).run();
        run = { ...run, findings_count: found.entries.length, severity_counts_json: JSON.stringify(severityCounts(found.entries)) };
      }
    }
    if (base[3] === 'findings') {
      const found = await findingsFor(env, run);
      if (!found) return json({ error: 'No findings are available for this scan.' }, 404);
      return json({ findings: found.entries.slice(0, 5000), total: found.entries.length, source: found.source, severity_counts: severityCounts(found.entries) });
    }
    if (base[3] === 'report') {
      const stored = run.report_key ? await env.SCAN_STORE.get(run.report_key) : null;
      if (!stored) return json({ error: 'No PDF report is available for this scan.' }, 404);
      const name = `security-report-${run.repository.replace(/[^A-Za-z0-9._-]+/g, '-')}-${run.created_at.slice(0, 10)}.pdf`;
      return new Response(stored.body, { headers: { 'content-type': 'application/pdf', 'content-disposition': `attachment; filename="${name}"`, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' } });
    }
    const logs = (await env.DB.prepare('SELECT level,stage,message,created_at FROM (SELECT * FROM security_scan_logs WHERE run_id=? ORDER BY id DESC LIMIT 400) ORDER BY id').bind(runId).all()).results;
    return json({ run: { ...publicRun(run), stage: run.status === 'failed' ? failedStage(logs, run.stage) : run.stage }, logs });
  } catch (error) {
    if (error instanceof ScanError) return json({ error: error.message }, error.status);
    throw error;
  }
}

// ---------- worker callbacks (/scan-worker/*) ----------

export async function handleScanWorker(req, env, path) {
  if (req.method !== 'POST' && req.method !== 'GET') return json({ error: 'Method not allowed.' }, 405);
  if (!env.SCAN_DISPATCH_PUBLIC_KEY) return json({ error: 'Scanning is not configured.' }, 503);
  const claims = verifyRunToken(env.SCAN_DISPATCH_PUBLIC_KEY, req.headers.get('authorization'));
  if (!claims || !claims.scopes.includes(CALLBACK_SCOPE)) return json({ error: 'Unauthorized.' }, 401);
  const run = await env.DB.prepare('SELECT * FROM security_scan_runs WHERE id=?').bind(claims.run).first();
  if (!run) return json({ error: 'Unknown scan.' }, 404);
  const rest = path.slice('/scan-worker'.length);

  // AI metering: the worker asks before each AI call and reports usage after. This app does not meter AI spend.
  if (rest === '/hub/adis/ai-metering/begin') return json({ invocationId: randomUUID() });
  if (rest.startsWith('/hub/adis/llm-invocations/') || rest === '/hub/adis/ai-governance/tool-usage') return json({ ok: true });
  // No prompt overrides: the worker falls back to the prompts it ships with.
  if (rest.startsWith('/hub/adis/prompts/')) return json({ error: 'Not found.' }, 404);

  const match = rest.match(/^\/runs\/([^/]+)\/(logs|heartbeat|webhook)$/);
  if (!match || req.method !== 'POST') return json({ error: 'Not found.' }, 404);
  if (decodeURIComponent(match[1]) !== claims.run) return json({ error: 'This token is for a different scan.' }, 403);
  const body = await req.json().catch(() => ({}));
  const at = now();
  if (match[2] === 'heartbeat') {
    await env.DB.prepare("UPDATE security_scan_runs SET last_heartbeat_at=?,updated_at=? WHERE id=? AND status='running'").bind(at, at, run.id).run();
    return json({ ok: true });
  }
  if (match[2] === 'logs') {
    const stage = STAGES.has(body.stage) ? body.stage : '';
    await env.DB.batch([
      env.DB.prepare('INSERT INTO security_scan_logs(run_id,level,stage,message,created_at) VALUES(?,?,?,?,?)').bind(run.id, ['info', 'warn', 'error'].includes(body.level) ? body.level : 'info', stage, clip(body.message, 4000), at),
      // After the worker logs a failure it still uploads and cleans up; keep the stage that failed.
      env.DB.prepare("UPDATE security_scan_runs SET stage=CASE WHEN ? IN ('','cleanup','failed') OR EXISTS (SELECT 1 FROM security_scan_logs WHERE run_id=? AND stage='failed') THEN stage ELSE ? END,last_heartbeat_at=?,updated_at=? WHERE id=? AND status='running'").bind(stage, run.id, stage, at, at, run.id),
    ]);
    return json({ ok: true });
  }
  // Final result. Idempotent: the worker retries it, and a finished run stays finished.
  if (!['running', 'verifying'].includes(run.status)) return json({ ok: true, duplicate: true });
  const rawOutputs = (Array.isArray(body.rawOutputFiles) ? body.rawOutputFiles : []).slice(0, 200).map((item) => ({ filename: clip(item?.filename, 200), s3Key: clip(item?.s3Key, 500), scannerKey: clip(item?.scannerKey, 60), label: clip(item?.label, 120) }));
  const updated = { ...run, raw_outputs_json: JSON.stringify(rawOutputs) };
  const found = await findingsFor(env, updated).catch(() => null);
  const entries = found ? found.entries : null;
  const counts = entries ? severityCounts(entries) : {};
  const failure = summarizeWorkerError(body.error);
  const succeeded = body.status === 'succeeded';
  await env.DB.batch([
    env.DB.prepare('UPDATE security_scan_runs SET status=?,stage=?,report_key=?,raw_outputs_json=?,findings_count=?,severity_counts_json=?,coverage_summary_json=?,error=?,finished_at=?,last_heartbeat_at=?,updated_at=? WHERE id=?')
      .bind(succeeded ? 'succeeded' : 'failed', succeeded ? 'complete' : (run.stage || 'failed'), succeeded ? clip(body.s3Key, 500) || null : null, JSON.stringify(rawOutputs), entries ? entries.length : null, JSON.stringify(counts), body.coverageSummary ? JSON.stringify(body.coverageSummary).slice(0, 20000) : null, succeeded ? null : failure, at, at, at, run.id),
    env.DB.prepare('INSERT INTO security_scan_logs(run_id,level,stage,message,created_at) VALUES(?,?,?,?,?)').bind(run.id, succeeded ? 'info' : 'error', succeeded ? 'complete' : 'failed', succeeded ? `Scan finished: ${entries ? entries.length + ' findings' : 'no findings register'}; report ${body.s3Key ? 'ready' : 'missing'}.` : `Scan failed: ${failure}`, at),
  ]);
  return json({ ok: true });
}

// ---------- S3-compatible artifact store (/adis-scan-artifacts/*) ----------
// Implements the two operations the worker uses (PutObject, GetObject) with full
// AWS Signature V4 verification against this app's store credentials.

const rfc3986 = (value) => encodeURIComponent(value).replace(/[!'()*]/g, (char) => '%' + char.charCodeAt(0).toString(16).toUpperCase());
const sha256hex = (data) => createHash('sha256').update(data).digest('hex');
const hmac = (key, data) => createHmac('sha256', key).update(data).digest();

function s3Error(status, code, message) {
  return new Response(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>${code}</Code><Message>${message}</Message></Error>`, { status, headers: { 'content-type': 'application/xml' } });
}

function verifySigV4(req, url, credentials) {
  const header = req.headers.get('authorization') || '';
  const match = header.match(/^AWS4-HMAC-SHA256 Credential=([^/]+)\/(\d{8})\/([^/]+)\/s3\/aws4_request, ?SignedHeaders=([a-z0-9;-]+), ?Signature=([0-9a-f]{64})$/);
  if (!match) return false;
  const [, accessKeyId, date, region, signedHeaders, signature] = match;
  if (accessKeyId !== credentials.accessKeyId) return false;
  const amzDate = req.headers.get('x-amz-date') || '';
  const time = Date.parse(amzDate.replace(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/, '$1-$2-$3T$4:$5:$6Z'));
  if (!amzDate.startsWith(date) || !Number.isFinite(time) || Math.abs(Date.now() - time) > 15 * 60 * 1000) return false;
  const headerNames = signedHeaders.split(';');
  if (!headerNames.includes('host')) return false;
  const canonicalHeaders = headerNames.map((name) => {
    const value = name === 'host' ? url.host : (req.headers.get(name) ?? '');
    return `${name}:${String(value).trim().replace(/\s+/g, ' ')}\n`;
  }).join('');
  const query = [...url.searchParams.entries()].map(([key, value]) => [rfc3986(key), rfc3986(value)]).sort((a, b) => (a[0] === b[0] ? (a[1] < b[1] ? -1 : 1) : a[0] < b[0] ? -1 : 1)).map(([key, value]) => `${key}=${value}`).join('&');
  const payloadHash = req.headers.get('x-amz-content-sha256') || sha256hex('');
  const canonicalRequest = [req.method, url.pathname, query, canonicalHeaders, signedHeaders, payloadHash].join('\n');
  const scope = `${date}/${region}/s3/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256hex(canonicalRequest)].join('\n');
  const signingKey = hmac(hmac(hmac(hmac('AWS4' + credentials.secretAccessKey, date), region), 's3'), 'aws4_request');
  const expected = Buffer.from(createHmac('sha256', signingKey).update(stringToSign).digest('hex'));
  const given = Buffer.from(signature);
  return expected.length === given.length && timingSafeEqual(expected, given);
}

// aws-chunked bodies: "<hex size>[;chunk-signature=…]\r\n<data>\r\n … 0\r\n[trailers]\r\n"
function decodeAwsChunked(buffer) {
  const parts = [];
  let offset = 0;
  for (;;) {
    const lineEnd = buffer.indexOf('\r\n', offset);
    if (lineEnd < 0) throw new Error('Malformed aws-chunked body.');
    const size = parseInt(buffer.subarray(offset, lineEnd).toString('ascii').split(';')[0], 16);
    if (!Number.isFinite(size)) throw new Error('Malformed aws-chunked body.');
    offset = lineEnd + 2;
    if (size === 0) return Buffer.concat(parts);
    parts.push(buffer.subarray(offset, offset + size));
    offset += size + 2;
  }
}

export function artifactKey(path) {
  const raw = path.slice(`/${SCAN_BUCKET}/`.length);
  let key;
  try { key = raw.split('/').map((part) => decodeURIComponent(part)).join('/'); } catch { return null; }
  if (!key || key.length > 600 || key.startsWith('/') || key.split('/').some((part) => part === '' || part === '.' || part === '..') || /[\0\\]/.test(key)) return null;
  return key;
}

export async function handleArtifactStore(req, env, url) {
  if (!env.SCAN_STORE || !env.SCAN_STORAGE) return s3Error(503, 'ServiceUnavailable', 'Artifact store not configured');
  if (!verifySigV4(req, url, env.SCAN_STORAGE)) return s3Error(403, 'SignatureDoesNotMatch', 'Request signature is not valid');
  const key = artifactKey(url.pathname);
  if (!key) return s3Error(400, 'InvalidArgument', 'Invalid object key');
  if (req.method === 'PUT') {
    let body = Buffer.from(await req.arrayBuffer());
    const payloadHash = req.headers.get('x-amz-content-sha256') || '';
    if (/^STREAMING-/.test(payloadHash) || /aws-chunked/.test(req.headers.get('content-encoding') || '')) {
      try { body = decodeAwsChunked(body); } catch { return s3Error(400, 'IncompleteBody', 'Malformed chunked body'); }
    } else if (/^[0-9a-f]{64}$/.test(payloadHash) && sha256hex(body) !== payloadHash) {
      return s3Error(400, 'XAmzContentSHA256Mismatch', 'Payload hash does not match');
    }
    await env.SCAN_STORE.put(key, body);
    return new Response(null, { status: 200, headers: { etag: `"${createHash('md5').update(body).digest('hex')}"` } });
  }
  if (req.method === 'GET' || req.method === 'HEAD') {
    const stored = await env.SCAN_STORE.get(key);
    if (!stored) return s3Error(404, 'NoSuchKey', 'The specified key does not exist.');
    return new Response(req.method === 'HEAD' ? null : stored.body, { status: 200, headers: { 'content-type': 'application/octet-stream', 'content-length': String(stored.body.length) } });
  }
  return s3Error(405, 'MethodNotAllowed', 'Method not allowed');
}
