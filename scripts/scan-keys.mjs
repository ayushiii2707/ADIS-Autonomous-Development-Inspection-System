// Key material shared by the app and the security-audit worker launcher.
//
// - An Ed25519 key pair: the app signs short-lived per-run tokens with the private
//   key; the worker verifies dispatch tokens with the public key, and the app
//   verifies the worker's callbacks with the same public key.
// - Access credentials for the app's built-in S3-compatible artifact store, which
//   the worker uploads its report and scanner outputs to.
//
// Both are created once under the data directory (mode 600) and reused, so a
// running worker keeps working across app restarts.

import { generateKeyPairSync, randomBytes, createPrivateKey, createPublicKey } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";

export const SCAN_BUCKET = "adis-scan-artifacts";

async function readOrCreate(path, create) {
  if (existsSync(path)) return readFile(path, "utf8");
  const value = create();
  await writeFile(path, value, { mode: 0o600, flag: "wx" }).catch((error) => {
    if (error.code !== "EEXIST") throw error;
  });
  await chmod(path, 0o600);
  return readFile(path, "utf8");
}

export async function loadScanKeys(dataDir) {
  await mkdir(dataDir, { recursive: true });
  const privatePem = await readOrCreate(join(dataDir, "scan-dispatch.key"), () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    return privateKey.export({ type: "pkcs8", format: "pem" });
  });
  const privateKey = createPrivateKey(privatePem);
  const publicPem = createPublicKey(privateKey).export({ type: "spki", format: "pem" });
  const storage = JSON.parse(await readOrCreate(join(dataDir, "scan-storage.json"), () => JSON.stringify({
    accessKeyId: "ADIS" + randomBytes(8).toString("hex").toUpperCase(),
    secretAccessKey: randomBytes(30).toString("base64url"),
  })));
  return {
    privatePem,
    publicPem: String(publicPem),
    // The worker reads JOB_TOKEN_PUBLIC_KEY as base64 of the PEM.
    publicKeyBase64: Buffer.from(String(publicPem)).toString("base64"),
    storage,
  };
}
