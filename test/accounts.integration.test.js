// Local accounts: single-user mode keeps working until the first account exists,
// that account takes over the existing projects, and afterwards every API call
// needs a session.
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { startLocalBackend } from "../scripts/local-backend.mjs";

async function call(origin, path, { method = "GET", body, cookie } = {}) {
  const headers = { origin };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (cookie) headers.cookie = cookie;
  const response = await fetch(origin + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const setCookie = response.headers.get("set-cookie") || "";
  return { status: response.status, body: await response.json(), cookie: setCookie.split(";")[0], setCookie };
}

test("accounts: sign up claims single-user projects, sessions gate the API, logout ends the session", async () => {
  const dir = await mkdtemp(join(tmpdir(), "adis-accounts-"));
  const backend = await startLocalBackend({ databasePath: join(dir, "db.sqlite"), env: { LOCAL_DEMO_MODE: "true", CREDENTIAL_KEY_FILE: join(dir, "credential.key") } });
  try {
    const { origin, sqlite } = backend;

    // Before any account: single-user mode, exactly as before.
    let me = await call(origin, "/api/auth/me");
    assert.deepEqual(me.body, { user: null, accounts: false, single_user: true });
    const created = await call(origin, "/api/projects", { method: "POST", body: { name: "Existing", code: "EXI-01" } });
    assert.equal(created.status, 201);

    // Validation.
    assert.equal((await call(origin, "/api/auth/signup", { method: "POST", body: { name: "Ada", email: "ada@example.com", password: "short" } })).status, 400);
    assert.equal((await call(origin, "/api/auth/signup", { method: "POST", body: { name: "Ada", email: "not-an-email", password: "long enough" } })).status, 400);

    // First account takes over the single user's projects.
    const signup = await call(origin, "/api/auth/signup", { method: "POST", body: { name: "Ada Lovelace", email: "Ada@Example.com", password: "correct horse" } });
    assert.equal(signup.status, 201, JSON.stringify(signup.body));
    assert.deepEqual(signup.body.user, { name: "Ada Lovelace", email: "ada@example.com", initials: "AL" });
    assert.match(signup.setCookie, /HttpOnly/);
    assert.match(signup.setCookie, /SameSite=Lax/);
    const row = sqlite.prepare("SELECT password_hash FROM users WHERE email='ada@example.com'").get();
    assert.match(row.password_hash, /^pbkdf2-sha256\$310000\$/);
    assert.ok(!row.password_hash.includes("correct horse"));
    const token = signup.cookie.split("=")[1];
    assert.ok(!sqlite.prepare("SELECT 1 FROM user_sessions WHERE token_hash=?").get(token), "only a hash of the session token is stored");

    const mine = await call(origin, "/api/projects", { cookie: signup.cookie });
    assert.deepEqual(mine.body.projects.map((project) => project.code), ["EXI-01"]);

    // Without a session the API is now closed.
    assert.equal((await call(origin, "/api/projects")).status, 401);
    me = await call(origin, "/api/auth/me");
    assert.deepEqual(me.body, { user: null, accounts: true, single_user: false });

    // Duplicate email, wrong password, then a real login.
    assert.equal((await call(origin, "/api/auth/signup", { method: "POST", body: { name: "Other", email: "ada@example.com", password: "another pass" } })).status, 409);
    assert.equal((await call(origin, "/api/auth/login", { method: "POST", body: { email: "ada@example.com", password: "wrong password" } })).status, 401);
    const login = await call(origin, "/api/auth/login", { method: "POST", body: { email: "ADA@example.com", password: "correct horse" } });
    assert.equal(login.status, 200);
    assert.equal((await call(origin, "/api/auth/me", { cookie: login.cookie })).body.user.name, "Ada Lovelace");

    // A second account sees only its own projects.
    const second = await call(origin, "/api/auth/signup", { method: "POST", body: { name: "Grace Hopper", email: "grace@example.com", password: "another pass" } });
    assert.equal(second.status, 201);
    assert.deepEqual((await call(origin, "/api/projects", { cookie: second.cookie })).body.projects, []);

    // Logout removes the session.
    const out = await call(origin, "/api/auth/logout", { method: "POST", body: {}, cookie: login.cookie });
    assert.equal(out.status, 200);
    assert.match(out.setCookie, /Max-Age=0/);
    assert.equal((await call(origin, "/api/projects", { cookie: login.cookie })).status, 401);

    // Auth changes are protected from other sites like every other API change.
    const cross = await fetch(origin + "/api/auth/login", { method: "POST", headers: { "content-type": "text/plain", origin }, body: "{}" });
    assert.equal(cross.status, 415);
  } finally {
    await backend.close();
  }
});
