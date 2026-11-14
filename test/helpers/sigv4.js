// Minimal AWS Signature V4 signer for S3 PutObject/GetObject, written
// independently of the app's verifier so tests check real interoperability.
import { createHash, createHmac } from "node:crypto";

const sha256hex = (data) => createHash("sha256").update(data).digest("hex");
const hmac = (key, data) => createHmac("sha256", key).update(data).digest();

export function signS3Request({ method, url, body = Buffer.alloc(0), accessKeyId, secretAccessKey, region = "us-east-1", headers = {}, payloadHash, date = new Date() }) {
  const target = new URL(url);
  const amzDate = date.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const day = amzDate.slice(0, 8);
  const contentHash = payloadHash || sha256hex(body);
  const all = { host: target.host, "x-amz-content-sha256": contentHash, "x-amz-date": amzDate, ...Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), String(v)])) };
  const names = Object.keys(all).sort();
  const canonicalHeaders = names.map((name) => `${name}:${all[name].trim()}\n`).join("");
  const signedHeaders = names.join(";");
  const canonicalRequest = [method, target.pathname, "", canonicalHeaders, signedHeaders, contentHash].join("\n");
  const scope = `${day}/${region}/s3/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256hex(canonicalRequest)].join("\n");
  const key = hmac(hmac(hmac(hmac("AWS4" + secretAccessKey, day), region), "s3"), "aws4_request");
  const signature = createHmac("sha256", key).update(stringToSign).digest("hex");
  const { host, ...send } = all;
  return { ...send, authorization: `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}` };
}
