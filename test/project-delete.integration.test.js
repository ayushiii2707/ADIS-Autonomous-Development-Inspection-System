// Deleting a project: only its owner can do it, never while a scan is running,
// and it takes the project's rows and stored scan reports with it.
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { startLocalBackend } from "../scripts/local-backend.mjs";

async function call(origin, path, { method = "GET", body, cookie } = {}) {
  const headers = { origin };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (cookie) headers.cookie = cookie;
  const response = await fetch(origin + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: response.status, body: await response.json(), cookie: (response.headers.get("set-cookie") || "").split(";")[0] };
}

test("projects can be deleted by their owner only, with their scans and reports", async () => {
  const dir = await mkdtemp(join(tmpdir(), "adis-delete-"));
  const backend = await startLocalBackend({ databasePath: join(dir, "db.sqlite"), env: { LOCAL_DEMO_MODE: "true", CREDENTIAL_KEY_FILE: join(dir, "credential.key") } });
  try {
    const { origin, sqlite } = backend;
    const owner = await call(origin, "/api/auth/signup", { method: "POST", body: { name: "Ada Lovelace", email: "ada@example.com", password: "correct horse" } });
    const other = await call(origin, "/api/auth/signup", { method: "POST", body: { name: "Grace Hopper", email: "grace@example.com", password: "another pass" } });
    const created = await call(origin, "/api/projects", { method: "POST", body: { name: "Doomed", code: "DOOM-1" }, cookie: owner.cookie });
    assert.equal(created.status, 201);
    const projectId = created.body.project.id;
    const keep = await call(origin, "/api/projects", { method: "POST", body: { name: "Keeper", code: "KEEP-1" }, cookie: owner.cookie });

    const now = new Date().toISOString();
    const addRun = (id, status) => sqlite.prepare("INSERT INTO security_scan_runs(id,project_id,provider,repository,repo_url,branch,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)").run(id, projectId, "github", "o/r", "https://github.com/o/r", "main", status, now, now);
    addRun("scan-done", "succeeded");
    const store = join(dir, "scan-artifacts");
    await mkdir(join(store, "security-audits", "scan-done", "raw-outputs"), { recursive: true });
    await mkdir(join(store, "security-baselines"), { recursive: true });
    await writeFile(join(store, "security-audits", "scan-done.pdf"), "%PDF");
    await writeFile(join(store, "security-audits", "scan-done", "raw-outputs", "x.json"), "{}");
    await writeFile(join(store, "security-baselines", "scan-done.json"), "{}");

    // Another account cannot see or delete it.
    assert.equal((await call(origin, `/api/projects/${projectId}`, { method: "DELETE", body: {}, cookie: other.cookie })).status, 404);
    // Signed out, nobody can.
    assert.equal((await call(origin, `/api/projects/${projectId}`, { method: "DELETE", body: {} })).status, 401);

    // Blocked while a scan is running.
    addRun("scan-live", "running");
    const busy = await call(origin, `/api/projects/${projectId}`, { method: "DELETE", body: {}, cookie: owner.cookie });
    assert.equal(busy.status, 409);
    sqlite.prepare("UPDATE security_scan_runs SET status='failed' WHERE id='scan-live'").run();

    const removed = await call(origin, `/api/projects/${projectId}`, { method: "DELETE", body: {}, cookie: owner.cookie });
    assert.equal(removed.status, 200, JSON.stringify(removed.body));
    assert.equal((await call(origin, `/api/projects/${projectId}`, { cookie: owner.cookie })).status, 404);
    assert.deepEqual((await call(origin, "/api/projects", { cookie: owner.cookie })).body.projects.map((project) => project.id), [keep.body.project.id]);
    assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM security_scan_runs WHERE project_id=?").get(projectId).n, 0);
    assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM project_setup WHERE project_id=?").get(projectId).n, 0);
    assert.ok(!existsSync(join(store, "security-audits", "scan-done.pdf")));
    assert.ok(!existsSync(join(store, "security-audits", "scan-done")));
    assert.ok(!existsSync(join(store, "security-baselines", "scan-done.json")));
    assert.deepEqual(sqlite.prepare("PRAGMA foreign_key_check").all(), []);
  } finally {
    await backend.close();
  }
});
