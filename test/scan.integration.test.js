// Security scan integration: the real app server, a fake security-audit worker
// that follows the real worker's contracts (Ed25519 dispatch tokens, job-token
// callbacks, SigV4 uploads), and mocked GitHub/Bitbucket APIs.
import assert from "node:assert/strict";
import { createPublicKey, verify } from "node:crypto";
import { mkdtemp, readFile } from "node:fs/promises";
import { createServer, request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";

import { startLocalBackend } from "../scripts/local-backend.mjs";
import { signS3Request } from "./helpers/sigv4.js";

const nativeFetch = globalThis.fetch;
const KEY = Buffer.alloc(32, 31).toString("base64");
const GITHUB_PAT = "ghp_scanTestToken0123456789abcdef";
const BITBUCKET_TOKEN = "ATATT3xBitbucketScanToken";
const OPENAI_KEY = "sk-test-openai-scan-key";
const jsonResponse = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

// Mirrors the worker's dispatch check (dispatch-auth.ts + job-token-verify.ts).
function workerAcceptsDispatch(publicPem, header, runId) {
  const token = String(header || "").replace(/^Bearer /, "");
  if (!token.startsWith("adisjob2.")) return false;
  const [body, signature] = token.slice(9).split(".");
  if (!verify(null, Buffer.from("adisjob2." + body), createPublicKey(publicPem), Buffer.from(signature, "base64url"))) return false;
  const claims = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  return claims.v === 2 && claims.kind === "dispatch" && claims.scopes.includes("dispatch:security-audit") && claims.run === runId && claims.exp > Date.now() / 1000;
}

function createProviders() {
  const providers = { githubValid: true, branchExists: true, bitbucketMode: "email" };
  providers.fetch = async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    const auth = request.headers.get("authorization") || "";
    if (url.host === "api.github.com") {
      if (!providers.githubValid || auth !== `Bearer ${GITHUB_PAT}`) return jsonResponse({ message: "Bad credentials" }, 401);
      if (url.pathname === "/repos/acme/web") return jsonResponse({ id: 77, name: "web", full_name: "acme/web", owner: { login: "acme" }, html_url: "https://github.com/acme/web", default_branch: "main", private: true, permissions: { pull: true } });
      if (url.pathname === "/repos/acme/web/branches") return jsonResponse([{ name: "main" }]);
      if (url.pathname === "/repos/acme/web/branches/main") return providers.branchExists ? jsonResponse({ name: "main" }) : jsonResponse({ message: "Branch not found" }, 404);
      if (url.pathname === "/repos/acme/web/contents") return jsonResponse([]);
      return jsonResponse({ message: "Not Found" }, 404);
    }
    if (url.host === "api.bitbucket.org") {
      const emailBasic = "Basic " + Buffer.from(`dev@example.com:${BITBUCKET_TOKEN}`).toString("base64");
      const ok = (providers.bitbucketMode === "email" && auth === emailBasic) || (providers.bitbucketMode === "bearer" && auth === `Bearer ${BITBUCKET_TOKEN}`);
      if (!ok) return jsonResponse({ error: { message: "Unauthorized" } }, 401);
      if (url.pathname === "/2.0/repositories/team/svc") return jsonResponse({ uuid: "{svc-uuid}", slug: "svc", full_name: "team/svc", workspace: { slug: "team" }, links: { html: { href: "https://bitbucket.org/team/svc" } }, mainbranch: { name: "main" }, is_private: true });
      if (url.pathname === "/2.0/repositories/team/svc/refs/branches") return jsonResponse({ values: [{ name: "main" }] });
      if (url.pathname === "/2.0/repositories/team/svc/refs/branches/main") return jsonResponse({ name: "main" });
      if (url.pathname.startsWith("/2.0/repositories/team/svc/src/")) return jsonResponse({ values: [] });
      return jsonResponse({ error: { message: "Not found" } }, 404);
    }
    return nativeFetch(input, init);
  };
  return providers;
}

// A fake worker with the real worker's HTTP contract.
async function createFakeWorker(dataDir, { outcome = "succeeded", busy = false } = {}) {
  const publicPem = createPublicKey(await readFile(join(dataDir, "scan-dispatch.key"), "utf8")).export({ type: "spki", format: "pem" });
  const storage = JSON.parse(await readFile(join(dataDir, "scan-storage.json"), "utf8"));
  const worker = { jobs: [], appOrigin: "", rejected: 0, busy, outcome };
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const send = (status, body) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
    if (req.method === "GET" && req.url === "/health") return send(200, { ok: true, busy: worker.busy, ready: true, issues: [] });
    if (req.method === "POST" && req.url === "/jobs") {
      const job = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      if (!workerAcceptsDispatch(publicPem, req.headers.authorization, job.runId)) { worker.rejected += 1; return send(403, { error: "forbidden" }); }
      worker.jobs.push(job);
      send(202, { accepted: true, runId: job.runId });
      setTimeout(() => simulate(job).catch((error) => { worker.error = error; }), 10);
      return;
    }
    send(404, { error: "not found" });
  });
  async function callback(job, suffix, body) {
    const path = new URL(job.webhookUrl).pathname.replace(/\/webhook$/, suffix);
    const response = await nativeFetch(worker.appOrigin + path, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${job.jobToken}` }, body: body === undefined ? undefined : JSON.stringify(body) });
    assert.equal(response.status, 200, `${suffix} callback -> ${response.status}`);
  }
  async function upload(key, body) {
    const url = `${worker.appOrigin}/adis-scan-artifacts/${key}`;
    const headers = signS3Request({ method: "PUT", url, body, accessKeyId: storage.accessKeyId, secretAccessKey: storage.secretAccessKey, headers: { "content-type": "application/octet-stream" } });
    const response = await nativeFetch(url, { method: "PUT", headers, body });
    assert.equal(response.status, 200, `upload ${key} -> ${response.status} ${await response.text()}`);
  }
  async function simulate(job) {
    await callback(job, "/logs", { level: "info", stage: "clone", message: `Cloning ${job.repoUrl} at ${job.targetRef}.` });
    await callback(job, "/heartbeat");
    await callback(job, "/logs", { level: "info", stage: "scan", message: "Starting scanners." });
    const prefix = `security-audits/${job.runId}`;
    const register = { version: 1, fingerprintVersion: 1, generatedAt: new Date().toISOString(), entries: [
      { id: "F-1", scanner: "opengrep", ruleId: "js.sqli", filePath: "src/db.js", startLine: 12, severity: "high", message: "SQL built from user input.", fingerprint: "a" },
      { id: "F-2", scanner: "trivy", ruleId: "CVE-2024-0001", filePath: "package-lock.json", startLine: 1, severity: "critical", message: "Vulnerable dependency.", fingerprint: "b" },
      { id: "F-3", scanner: "trufflehog", ruleId: "aws-key", filePath: "config.js", startLine: 3, severity: "medium", message: "Possible secret ([REDACTED]).", fingerprint: "c" },
    ] };
    // Like the real worker: the baseline snapshot is saved before the AI report step,
    // the findings register only on the success path.
    const baseline = { runId: job.runId, capturedAt: new Date().toISOString(), fingerprintVersion: 1, findings: [
      { ruleId: "py.md5", filePath: "audit/evaluator.py", startLine: 44, severity: "WARNING", message: "Insecure MD5 hash.", scanner: "opengrep", fingerprint: "d" },
      { ruleId: "py/empty-except", filePath: "core/run.py", startLine: 9, severity: "note", message: "Empty except.", scanner: "codeql", fingerprint: "e" },
      { ruleId: "py/sql-injection", filePath: "core/db.py", startLine: 30, severity: "error", message: "SQL injection.", scanner: "codeql", fingerprint: "f" },
      { ruleId: "py/unused-import", filePath: "core/db.py", startLine: 1, severity: "warning", message: "Unused import.", scanner: "codeql", fingerprint: "g" },
    ] };
    await upload(`security-baselines/${job.runId}.json`, Buffer.from(JSON.stringify(baseline)));
    if (worker.outcome === "succeeded") {
      await upload(`${prefix}/raw-outputs/findings-register.json`, Buffer.from(JSON.stringify(register)));
      await upload(`${prefix}.pdf`, Buffer.from("%PDF-1.4 security report"));
      await callback(job, "/logs", { level: "info", stage: "upload", message: "Uploading PDF report." });
      await callback(job, "/webhook", { status: "succeeded", s3Key: `${prefix}.pdf`, rawOutputFiles: [{ filename: "findings-register.json", s3Key: `${prefix}/raw-outputs/findings-register.json`, scannerKey: "register" }], coverageSummary: { languages: 2, gaps: 0 } });
    } else {
      // As in a real run: report stage starts, fails, then raw outputs are still uploaded.
      await callback(job, "/logs", { level: "info", stage: "claude", message: "Starting report assembly and PDF generation via openai-codex." });
      await callback(job, "/logs", { level: "error", stage: "failed", message: "openai-codex stage codeql.md failed (exit 1)" });
      await callback(job, "/logs", { level: "info", stage: "upload", message: "Uploading raw output file: codeql.sarif" });
      // The real worker forwards the AI agent's whole output; the cause is the last ERROR line.
      const dump = ["openai-codex stage codeql.md failed (exit 1): Reading prompt from stdin...", "OpenAI Codex v0.136.0", "--------", "model: gpt-5", ...Array.from({ length: 60 }, () => "prompt text that should not reach the user"), "ERROR: Reconnecting... 5/5", "ERROR: stream disconnected before completion: You have no credits remaining."].join("\n");
      await callback(job, "/webhook", { status: "failed", error: dump, rawOutputFiles: [{ filename: "codeql.sarif", s3Key: `${prefix}/raw-outputs/codeql.sarif`, scannerKey: "codeql" }] });
    }
  }
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  worker.url = `http://127.0.0.1:${server.address().port}`;
  worker.close = () => new Promise((resolve) => server.close(resolve));
  return worker;
}

async function withScanning(run, { workerOptions = {}, env = {} } = {}) {
  const directory = await mkdtemp(join(tmpdir(), "adis-scan-"));
  const databasePath = join(directory, "adis.sqlite");
  const providers = createProviders();
  globalThis.fetch = (input, init) => providers.fetch(input, init);
  let backend;
  let worker;
  try {
    // Start once to create the keys, then start the fake worker that trusts them.
    backend = await startLocalBackend({ databasePath, env: { CREDENTIAL_ENCRYPTION_KEY: KEY, TRUST_USER_HEADER: "", SCAN_AI_API_KEY: OPENAI_KEY, ...env } });
    worker = await createFakeWorker(directory, workerOptions);
    await backend.close();
    backend = await startLocalBackend({ databasePath, env: { CREDENTIAL_ENCRYPTION_KEY: KEY, TRUST_USER_HEADER: "", SCAN_AI_API_KEY: OPENAI_KEY, SCAN_WORKER_URL: worker.url, ...env } });
    worker.appOrigin = backend.origin;
    const responses = [];
    const call = async (path, { method = "GET", body } = {}) => {
      const response = await nativeFetch(backend.origin + path, { method, headers: method === "GET" ? {} : { "content-type": "application/json" }, body: method === "GET" ? undefined : JSON.stringify(body || {}) });
      const buffer = Buffer.from(await response.arrayBuffer());
      responses.push(buffer.toString("utf8"));
      let parsed = null;
      try { parsed = JSON.parse(buffer.toString("utf8")); } catch {}
      return { status: response.status, body: parsed, buffer, headers: response.headers };
    };
    await run({ call, worker, providers, databasePath, directory, responses, origin: backend.origin });
  } finally {
    if (backend) await backend.close();
    if (worker) await worker.close();
    globalThis.fetch = nativeFetch;
  }
}

async function connectedProject(call, provider = "github", code = "SCAN") {
  const projectId = (await call("/api/projects", { method: "POST", body: { name: "Scan project", code } })).body.project.id;
  const body = provider === "github"
    ? { provider: "github", owner: "acme", repository: "web", pat: GITHUB_PAT }
    : { provider: "bitbucket", workspace: "team", repository: "svc", token: BITBUCKET_TOKEN, email: "dev@example.com" };
  const connected = await call(`/api/projects/${projectId}/connections`, { method: "POST", body });
  assert.equal(connected.status, 201, JSON.stringify(connected.body));
  const connection = connected.body.connection;
  assert.equal((await call(`/api/projects/${projectId}/connections/${connection.id}/discover`, { method: "POST" })).status, 200);
  assert.equal((await call(`/api/projects/${projectId}/setup`, { method: "PATCH", body: { connection_id: connection.id, selected_branch: "main", service_type: "API" } })).status, 200);
  assert.equal((await call(`/api/projects/${projectId}/setup/finish`, { method: "POST" })).status, 200);
  return { projectId, connection };
}

async function waitForRun(call, projectId, runId, statuses = ["succeeded", "failed"]) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const detail = await call(`/api/projects/${projectId}/scans/${runId}`);
    if (statuses.includes(detail.body.run.status)) return detail.body;
    await new Promise((resolve) => setTimeout(resolve, 30));
  }
  throw new Error("run did not finish");
}

test("a GitHub scan verifies access, runs on the worker, and stores findings and the PDF", async () => {
  await withScanning(async ({ call, worker, responses }) => {
    const { projectId } = await connectedProject(call);
    const started = await call(`/api/projects/${projectId}/scans`, { method: "POST" });
    assert.equal(started.status, 201, JSON.stringify(started.body));
    assert.equal(started.body.run.status, "running");
    const detail = await waitForRun(call, projectId, started.body.run.id);
    assert.equal(detail.run.status, "succeeded", JSON.stringify(detail));
    assert.equal(detail.run.stage, "complete");
    assert.equal(detail.run.findings_count, 3);
    assert.deepEqual(detail.run.severity_counts, { critical: 1, high: 1, medium: 1, low: 0, info: 0 });
    assert.equal(detail.run.report_available, true);
    const stages = detail.logs.map((log) => log.stage);
    assert.ok(stages.includes("verify") && stages.includes("clone") && stages.includes("complete"));
    assert.match(detail.logs[1].message, /Credential verified: acme\/web is reachable and readable; branch "main" exists/);

    // The worker received the intended repository, branch, and credentials.
    assert.equal(worker.jobs.length, 1);
    const job = worker.jobs[0];
    assert.equal(job.sourceType, "GITHUB");
    assert.equal(job.repoUrl, "https://github.com/acme/web.git");
    assert.equal(job.targetRef, "main");
    assert.ok(Number.isSafeInteger(job.softwareProjectId) && job.softwareProjectId > 0, "a numeric project reference for AI-usage metering");
    assert.deepEqual(job.credentials, { username: "x-access-token", token: GITHUB_PAT });
    assert.deepEqual(job.scannerKeys, ["codeql", "opengrep", "trivy", "osv", "trufflehog"]);
    assert.deepEqual(job.providerConfig, { providerKey: "openai-codex", apiKey: OPENAI_KEY });
    assert.match(job.webhookUrl, /\/scan-worker\/runs\/scan-[0-9a-f-]+\/webhook$/);

    const findings = await call(`/api/projects/${projectId}/scans/${started.body.run.id}/findings`);
    assert.equal(findings.body.total, 3);
    assert.equal(findings.body.findings[0].ruleId, "js.sqli");
    const report = await call(`/api/projects/${projectId}/scans/${started.body.run.id}/report`);
    assert.equal(report.status, 200);
    assert.equal(report.headers.get("content-type"), "application/pdf");
    assert.match(report.headers.get("content-disposition"), /attachment; filename="security-report-acme-web-/);
    assert.equal(report.buffer.toString(), "%PDF-1.4 security report");

    // Neither the repository token nor the AI key is ever returned to the browser.
    assert.ok(responses.every((text) => !text.includes(GITHUB_PAT) && !text.includes(OPENAI_KEY)));
  });
});

test("Bitbucket scans pass the git username that matches the verified credential type", async () => {
  await withScanning(async ({ call, worker, providers }) => {
    const { projectId } = await connectedProject(call, "bitbucket", "BBEMAIL");
    const run = (await call(`/api/projects/${projectId}/scans`, { method: "POST" })).body.run;
    assert.equal(run.status, "running", JSON.stringify(run));
    await waitForRun(call, projectId, run.id);
    assert.equal(worker.jobs[0].sourceType, "BITBUCKET");
    assert.equal(worker.jobs[0].repoUrl, "https://bitbucket.org/team/svc.git");
    assert.deepEqual(worker.jobs[0].credentials, { username: "x-bitbucket-api-token-auth", token: BITBUCKET_TOKEN });

    providers.bitbucketMode = "bearer";
    const second = (await call(`/api/projects/${projectId}/scans`, { method: "POST" })).body.run;
    await waitForRun(call, projectId, second.id);
    assert.deepEqual(worker.jobs[1].credentials, { username: "x-token-auth", token: BITBUCKET_TOKEN });
  });
});

test("credential, branch, and worker problems stop the scan before anything is dispatched", async () => {
  await withScanning(async ({ call, worker, providers }) => {
    const { projectId } = await connectedProject(call);
    providers.githubValid = false;
    const revoked = (await call(`/api/projects/${projectId}/scans`, { method: "POST" })).body.run;
    assert.equal(revoked.status, "failed");
    assert.equal(revoked.stage, "verify");
    assert.equal(revoked.error, "GitHub could not authenticate that token.");

    providers.githubValid = true;
    providers.branchExists = false;
    const noBranch = (await call(`/api/projects/${projectId}/scans`, { method: "POST" })).body.run;
    assert.equal(noBranch.error, 'Branch "main" no longer exists in acme/web.');

    providers.branchExists = true;
    worker.busy = true;
    const busy = (await call(`/api/projects/${projectId}/scans`, { method: "POST" })).body.run;
    assert.match(busy.error, /busy with another scan/);
    assert.equal(worker.jobs.length, 0, "no job reached the worker");
  });
});

test("scans need setup, an AI key, and a running worker", async () => {
  await withScanning(async ({ call }) => {
    const bare = (await call("/api/projects", { method: "POST", body: { name: "Bare", code: "BARE" } })).body.project.id;
    const notReady = await call(`/api/projects/${bare}/scans`, { method: "POST" });
    assert.equal(notReady.status, 400);
    assert.match(notReady.body.error, /Finish connecting the repository/);
    const { projectId } = await connectedProject(call, "github", "NOWORKER");
    const down = (await call(`/api/projects/${projectId}/scans`, { method: "POST" })).body.run;
    assert.equal(down.status, "failed");
    assert.match(down.error, /worker is not running\. Start it with: npm run scan-worker:start/);
  }, { env: { SCAN_WORKER_URL: "http://127.0.0.1:9" } });

  await withScanning(async ({ call }) => {
    const { projectId } = await connectedProject(call, "github", "NOKEY");
    const missing = await call(`/api/projects/${projectId}/scans`, { method: "POST" });
    assert.equal(missing.status, 400);
    assert.match(missing.body.error, /SCAN_AI_API_KEY/);
    assert.deepEqual((await call(`/api/projects/${projectId}/scans`)).body.runs, [], "no run is created");
  }, { env: { SCAN_AI_API_KEY: "" } });
});

test("a failed pipeline run still exposes the findings it produced", async () => {
  await withScanning(async ({ call }) => {
    const { projectId } = await connectedProject(call);
    const run = (await call(`/api/projects/${projectId}/scans`, { method: "POST" })).body.run;
    const detail = await waitForRun(call, projectId, run.id);
    assert.equal(detail.run.status, "failed");
    assert.equal(detail.run.error, "openai-codex stage codeql.md failed (exit 1): stream disconnected before completion: You have no credits remaining.");
    assert.equal(detail.run.stage, "claude", "the stage that failed, not the uploads after it");
    assert.equal(detail.run.report_available, false);
    // No findings register on the failure path: the pipeline's baseline snapshot is used, with severities mapped.
    assert.equal(detail.run.findings_count, 4);
    assert.deepEqual(detail.run.severity_counts, { critical: 0, high: 1, medium: 2, low: 1, info: 0 });
    const findings = (await call(`/api/projects/${projectId}/scans/${run.id}/findings`)).body;
    assert.equal(findings.source, "baseline");
    assert.deepEqual(findings.findings.map((item) => `${item.scannerSeverity}->${item.severity}`), ["WARNING->medium", "note->low", "error->high", "warning->medium"]);
    assert.equal((await call(`/api/projects/${projectId}/scans/${run.id}/report`)).status, 404);
  }, { workerOptions: { outcome: "failed" } });
});

test("worker callbacks require the run's own signed token", async () => {
  await withScanning(async ({ call, worker, origin }) => {
    const { projectId } = await connectedProject(call);
    const run = (await call(`/api/projects/${projectId}/scans`, { method: "POST" })).body.run;
    await waitForRun(call, projectId, run.id);
    const other = (await call(`/api/projects/${projectId}/scans`, { method: "POST" })).body.run;
    await waitForRun(call, projectId, other.id);
    const [first, second] = worker.jobs;
    const post = (path, token, body = {}) => nativeFetch(origin + path, { method: "POST", headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(body) });
    assert.equal((await post(`/scan-worker/runs/${first.runId}/logs`)).status, 401, "no token");
    assert.equal((await post(`/scan-worker/runs/${first.runId}/logs`, second.jobToken)).status, 403, "another run's token");
    const tampered = first.jobToken.slice(0, -4) + (first.jobToken.endsWith("AAAA") ? "BBBB" : "AAAA");
    assert.equal((await post(`/scan-worker/runs/${first.runId}/logs`, tampered)).status, 401, "tampered token");
    // A finished run is not reopened by a repeated final webhook.
    assert.equal((await post(`/scan-worker/runs/${first.runId}/webhook`, first.jobToken, { status: "failed", error: "late" })).status, 200);
    assert.equal((await call(`/api/projects/${projectId}/scans/${first.runId}`)).body.run.status, "succeeded");
    // AI metering and prompt lookups answer like the reference control plane.
    const begin = await post("/scan-worker/hub/adis/ai-metering/begin", first.jobToken);
    assert.match((await begin.json()).invocationId, /^[0-9a-f-]{36}$/);
    assert.equal((await nativeFetch(origin + "/scan-worker/hub/adis/prompts/assembly", { headers: { authorization: `Bearer ${first.jobToken}` } })).status, 404);
  });
});

test("the artifact store accepts only correctly signed requests inside the bucket", async () => {
  await withScanning(async ({ origin, directory }) => {
    const storage = JSON.parse(await readFile(join(directory, "scan-storage.json"), "utf8"));
    const put = async (key, body, credentials = storage, extraHeaders = {}, payloadHash) => {
      const url = `${origin}/adis-scan-artifacts/${key}`;
      const headers = signS3Request({ method: "PUT", url, body, accessKeyId: credentials.accessKeyId, secretAccessKey: credentials.secretAccessKey, headers: extraHeaders, payloadHash });
      return nativeFetch(url, { method: "PUT", headers, body });
    };
    assert.equal((await put("reports/a.json", Buffer.from("{}"))).status, 200);
    const url = `${origin}/adis-scan-artifacts/reports/a.json`;
    const got = await nativeFetch(url, { headers: signS3Request({ method: "GET", url, accessKeyId: storage.accessKeyId, secretAccessKey: storage.secretAccessKey }) });
    assert.equal(await got.text(), "{}");
    assert.equal((await put("reports/b.json", Buffer.from("{}"), { ...storage, secretAccessKey: "wrong" })).status, 403, "wrong secret");
    assert.equal((await nativeFetch(`${origin}/adis-scan-artifacts/reports/c.json`, { method: "PUT", body: "{}" })).status, 403, "unsigned");
    // Dot segments are normalised away by URL parsing; an encoded slash survives it and must be refused.
    assert.equal((await put("reports/..%2F..%2Fescape.json", Buffer.from("{}"))).status, 400, "path traversal");
    // aws-chunked uploads (newer AWS SDKs) are decoded.
    const chunked = Buffer.from("5;chunk-signature=x\r\nhello\r\n0;chunk-signature=y\r\nx-amz-checksum-crc32:abc\r\n\r\n");
    assert.equal((await put("reports/chunked.txt", chunked, storage, { "content-encoding": "aws-chunked" }, "STREAMING-UNSIGNED-PAYLOAD-TRAILER")).status, 200);
    assert.equal(await readFile(join(directory, "scan-artifacts", "reports", "chunked.txt"), "utf8"), "hello");
  });
});

test("host.docker.internal is accepted only on worker paths, and a silent worker fails the run", async () => {
  await withScanning(async ({ call, origin, databasePath }) => {
    const port = new URL(origin).port;
    const raw = (path) => new Promise((resolve, reject) => {
      const req = httpRequest({ hostname: "127.0.0.1", port, path, method: "POST", headers: { host: `host.docker.internal:${port}`, "content-type": "application/json" } }, (res) => { res.resume(); res.on("end", () => resolve(res.statusCode)); });
      req.on("error", reject);
      req.end("{}");
    });
    assert.equal(await raw("/api/projects"), 403, "the browser API rejects the worker host name");
    assert.equal(await raw("/scan-worker/runs/x/logs"), 401, "worker paths accept the host name and then require a token");

    const { projectId } = await connectedProject(call);
    const sqlite = new DatabaseSync(databasePath);
    const at = new Date(Date.now() - 11 * 60 * 1000).toISOString();
    sqlite.prepare("INSERT INTO security_scan_runs(id,project_id,provider,repository,repo_url,branch,status,stage,created_at,started_at,last_heartbeat_at,updated_at) VALUES('scan-stale',?,'github','acme/web','https://github.com/acme/web.git','main','running','scan',?,?,?,?)").run(projectId, at, at, at, at);
    sqlite.close();
    const stale = (await call(`/api/projects/${projectId}/scans/scan-stale`)).body.run;
    assert.equal(stale.status, "failed");
    assert.match(stale.error, /stopped responding/);
  }, { workerOptions: { busy: true } });
});
