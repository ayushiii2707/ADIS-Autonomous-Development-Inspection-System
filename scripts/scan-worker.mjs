// Builds and runs the security-audit-pipeline worker in Docker for this app.
//
//   npm run scan-worker:build   clone the pipeline at the pinned commit and build its image
//   npm run scan-worker:start   start the worker (HTTP mode) wired to this app
//   npm run scan-worker:stop    stop it
//   npm run scan-worker:status  container state and /health
//   npm run scan-worker:logs    recent worker logs
//
// The worker is published on 127.0.0.1 only. It verifies jobs with this app's
// Ed25519 public key, calls back to the app as host.docker.internal, and uploads
// results to the app's built-in S3-compatible store.

import { spawnSync } from "node:child_process";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { SCAN_BUCKET, loadScanKeys } from "./scan-keys.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PIPELINE_REPO = "https://github.com/ayushiii2707/security-audit-pipeline.git";
const PIPELINE_COMMIT = "5451d049de0117a63f2e84a352c71ef155ec7bb8";
const IMAGE = process.env.SCAN_WORKER_IMAGE || "security-audit-worker";
// The image is built for this machine's own CPU (docker/scan-worker.Dockerfile supports both), so
// the scanners run natively instead of under emulation. SCAN_WORKER_PLATFORM overrides it.
const PLATFORM = process.env.SCAN_WORKER_PLATFORM || (process.arch === "arm64" ? "linux/arm64" : "linux/amd64");
const CONTAINER = "adis-scan-worker";
const dataDir = resolve(dirname(resolve(process.env.LOCAL_DB_PATH || resolve(root, ".data", "adis-local.sqlite"))));
const appPort = Number(process.env.PORT || 8787);
const workerUrl = String(process.env.SCAN_WORKER_URL || "http://127.0.0.1:4101").replace(/\/+$/, "");
const workerPort = Number(new URL(workerUrl).port || 4101);

function run(command, args, { quiet = false } = {}) {
  const result = spawnSync(command, args, { stdio: quiet ? "pipe" : "inherit", encoding: "utf8" });
  if (result.error) throw new Error(`${command} is not available: ${result.error.message}`);
  return result;
}

function requireDocker() {
  const info = run("docker", ["info", "--format", "{{.ServerVersion}}"], { quiet: true });
  if (info.status !== 0) {
    console.error("Docker is not running. Start Docker Desktop and try again.");
    process.exit(1);
  }
}

async function health() {
  try {
    const response = await fetch(workerUrl + "/health", { signal: AbortSignal.timeout(5000) });
    return await response.json();
  } catch {
    return null;
  }
}

async function build() {
  requireDocker();
  const source = resolve(dataDir, "security-audit-pipeline");
  if (!existsSync(source)) {
    await mkdir(dataDir, { recursive: true });
    if (run("git", ["clone", PIPELINE_REPO, source]).status !== 0) process.exit(1);
  }
  run("git", ["-C", source, "fetch", "--quiet", "origin"]);
  if (run("git", ["-C", source, "checkout", "--quiet", PIPELINE_COMMIT]).status !== 0) process.exit(1);
  console.log(`Building ${IMAGE} from security-audit-pipeline@${PIPELINE_COMMIT.slice(0, 7)} for ${PLATFORM}. The first build downloads several GB and takes a while.`);
  // The build context is the pipeline checkout; `adis` is this repo's docker/ folder, which
  // holds the patch the Dockerfile applies on top of the pinned commit.
  const result = run("docker", ["buildx", "build", "--load", "--platform", PLATFORM,
    "-f", resolve(root, "docker/scan-worker.Dockerfile"), "--build-context", `adis=${resolve(root, "docker")}`,
    "-t", IMAGE, source]);
  process.exit(result.status ?? 1);
}

async function start() {
  requireDocker();
  const inspected = run("docker", ["image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", IMAGE], { quiet: true });
  if (inspected.status !== 0) {
    console.error(`The ${IMAGE} image is not built yet. Run: npm run scan-worker:build`);
    process.exit(1);
  }
  const imagePlatform = inspected.stdout.trim();
  if (imagePlatform !== PLATFORM) {
    console.warn(`Note: the ${IMAGE} image is ${imagePlatform}, but this machine is ${PLATFORM}, so its scanners run under emulation and may be refused as too slow. Rebuild it natively with: npm run scan-worker:build`);
  }
  const keys = await loadScanKeys(dataDir);
  const appBase = `http://host.docker.internal:${appPort}`;
  const envFile = resolve(dataDir, "scan-worker.env");
  await writeFile(envFile, [
    `JOB_TOKEN_PUBLIC_KEY=${keys.publicKeyBase64}`,
    `API_PUBLIC_URL=${appBase}/scan-worker`,
    `AWS_S3_ENDPOINT=${appBase}`,
    `AWS_S3_BUCKET_NAME=${SCAN_BUCKET}`,
    "AWS_REGION=us-east-1",
    `AWS_ACCESS_KEY_ID=${keys.storage.accessKeyId}`,
    `AWS_SECRET_ACCESS_KEY=${keys.storage.secretAccessKey}`,
    "PORT=4101",
    "",
  ].join("\n"), { mode: 0o600 });
  await chmod(envFile, 0o600);
  run("docker", ["rm", "-f", CONTAINER], { quiet: true });
  const result = run("docker", ["run", "-d", "--name", CONTAINER, "--platform", imagePlatform, "-p", `127.0.0.1:${workerPort}:4101`, "--env-file", envFile, "--add-host", "host.docker.internal:host-gateway", IMAGE, "node", "dist/server.js"], { quiet: true });
  if (result.status !== 0) {
    console.error(result.stderr.trim());
    process.exit(1);
  }
  let state = null;
  for (let attempt = 0; attempt < 60 && !state?.ok; attempt += 1) {
    state = await health();
    if (!state?.ok) await new Promise((resolveWait) => setTimeout(resolveWait, 2000));
  }
  if (!state?.ok) {
    console.error("The worker did not answer /health within 2 minutes. Check: npm run scan-worker:logs");
    process.exit(1);
  }
  // The worker refuses jobs unless `codeql --version` and `opengrep --version` answer
  // within 5 seconds. A native image answers in well under a second; on a first, cold
  // start (or an emulated image) warm them up and wait until the worker sees them.
  const slowCheck = (issues = []) => issues.some((issue) => /^(codeql|opengrep) binary not found/.test(issue));
  for (let attempt = 0; attempt < 12 && slowCheck(state?.issues); attempt += 1) {
    run("docker", ["exec", CONTAINER, "sh", "-c", "codeql --version >/dev/null 2>&1; opengrep --version >/dev/null 2>&1"], { quiet: true });
    await new Promise((resolveWait) => setTimeout(resolveWait, 10000));
    state = await health();
  }
  const pending = (state?.issues || []).filter((issue) => /binary not found/.test(issue));
  console.log(`Security audit worker is running at ${workerUrl} (busy: ${state.busy}).`);
  if (pending.length) console.warn(`Warning: ${pending.join("; ")}. Scans that include these scanners will be refused until they respond; try npm run scan-worker:start again.`);
}

async function status() {
  const ps = run("docker", ["ps", "-a", "--filter", `name=^${CONTAINER}$`, "--format", "{{.Status}}"], { quiet: true });
  console.log(`Container: ${ps.stdout?.trim() || "not created"}`);
  const state = await health();
  console.log(state ? `Health: ok=${state.ok} busy=${state.busy}` : `Health: no answer at ${workerUrl}`);
}

const command = process.argv[2];
if (command === "build") await build();
else if (command === "start") await start();
else if (command === "stop") process.exit(run("docker", ["rm", "-f", CONTAINER]).status ?? 1);
else if (command === "status") await status();
else if (command === "logs") process.exit(run("docker", ["logs", "--tail", "200", CONTAINER]).status ?? 1);
else {
  console.error("Usage: node scripts/scan-worker.mjs <build|start|stop|status|logs>");
  process.exit(1);
}
