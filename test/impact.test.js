// Scan Impact Analysis: reading a downloaded report back in. The fixtures follow the
// structure of real ADIS reports (numbered sections, finding cards, tables, Appendix A).
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { appendixFindings, buildReportAnalysis, compareReports, impactRoute, narrative, pdfImages } from "../worker/impact.js";
import { assessFindings } from "../worker/scan.js";

const MUTABLE = "yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag";
const SQL = "python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query";

function reportMarkdown({ commit = "02829106f8de603c77c9787861421b96ac2d37fd", mutableUnder = "Medium Findings" } = {}) {
  return [
    "# Security Assessment",
    "## 1. Overview",
    `This assessment covers the \`agentic-harness\` repository at commit \`${commit}\` on 2026-11-20.`,
    '<div class="callout callout-important">',
    "<strong>TOP RISK — P1:</strong> mutable GitHub Action tags in `.github/workflows/ci.yml` allow CI supply-chain risk.",
    "</div>",
    "## 4. Finding Summary",
    "### 4.2 Security Findings by CWE (Deduplicated Across All Scanners)",
    "| CWE | Description | Locations | CodeQL | OpenGrep | SonarQube |",
    "|-----|-------------|-----------|--------|----------|-----------|",
    "| CWE-89 | SQL Injection ⚠ single-scanner | 1 | ❌ | ERROR ✅ | ❌ |",
    "| CWE-353 | CWE-353 ⚠ single-scanner | 2 | ❌ | WARNING ✅ | ❌ |",
    "## 5. Critical Findings",
    "There are no critical findings.",
    "## 6. High Findings",
    "There are no confirmed high-severity findings in this run.",
    `## 7. ${mutableUnder}`,
    "### 7.1 Mutable GitHub Actions tags in CI workflow",
    "- File: `.github/workflows/ci.yml:23,42`",
    "OpenGrep flagged mutable tags such as `actions/checkout@v4`.",
    "Recommended fix: pin the actions to a full commit SHA.",
    "## 11. Infrastructure & Hardening Recommendations",
    "### 11.1 CI Supply-Chain — Mutable Action Tags (OpenGrep)",
    `- Rule: \`${MUTABLE}\``,
    "## 12. False Positives",
    "| File | Line | Rule | Reason | Appendix |",
    "| --- | --- | --- | --- | --- |",
    `| \`src/api.py\` | 650 | \`${SQL}\` | Uses bound parameters, not string concatenation. | OG-001 |`,
    "## 14. Remediation Roadmap",
    "### P1 — This Sprint",
    "| # | Action | File(s) |",
    "|---|---|---|",
    "| 1 | Pin GitHub Actions to commit SHAs. | `.github/workflows/ci.yml` |",
    "## Appendix A — Complete Scanner Findings (Unfiltered)",
    "### OpenGrep — 3 findings",
    "| ID | Level | Rule | File | Line | Message |",
    "|---|---|---|---|---|---|",
    `| OG-001 | ERROR | ${SQL.slice(0, 40)}… | src/api.py | 650 | Avoid raw SQL. |`,
    `| OG-002 | WARNING | ${MUTABLE.slice(0, 40)}… | .github/workflows/ci.yml | 23 | GitHub Actions step uses a mutable tag. |`,
    `| OG-003 | WARNING | ${MUTABLE.slice(0, 40)}… | .github/workflows/ci.yml | 42 | GitHub Actions step uses a mutable tag. |`,
  ].join("\n");
}

const finding = (id, assessment, extra = {}) => ({
  key: null, id, scanner: "OpenGrep", ruleId: MUTABLE, file: ".github/workflows/ci.yml", line: 23, level: "warning", message: "mutable tag",
  assessment, fingerprint: `${id}`.padEnd(64, "0"), cwe: ["CWE-353"], snippet: "- uses: actions/checkout@v4", actionable: ["critical", "high", "medium", "low", "hardening"].includes(assessment),
  excerpt: null, proposedFix: { title: "Pin GitHub Actions to commit SHAs.", priority: "P1", roadmapNumber: 1 }, dismissal: null, ...extra,
});
const report = (findings, meta = {}) => buildReportAnalysis({
  upload: { name: "r.pdf", kind: "pdf", sha256: createHash("sha256").update(JSON.stringify(meta)).digest("hex") },
  run: { id: meta.id || "scan-1", repository: "acme/web", branch: "main", created_at: meta.at || "2026-11-01T00:00:00Z", scanners_json: JSON.stringify(meta.scanners || ["opengrep"]), coverage_summary_json: null },
  markdown: `## 1. Overview\nat commit \`${meta.commit || "aaaaaaaaaaaa"}\`.`, findings, assessed: true, pdf: { embeddedImages: 0, screenshotCandidates: 0 }, sources: [],
});

test("a markdown report on its own: findings, assessments, evidence and no remediation claims", () => {
  const md = reportMarkdown();
  const entries = appendixFindings(md);
  assert.deepEqual(entries.map((item) => `${item.id}:${item.scanner}:${item.startLine}`), ["OG-001:OpenGrep:650", "OG-002:OpenGrep:23", "OG-003:OpenGrep:42"]);
  const analysis = buildReportAnalysis({ upload: { name: "report.md", kind: "md", sha256: "0".repeat(64) }, run: null, markdown: md, findings: assessFindings(md, entries).map((item) => ({ ...item, file: item.filePath, line: item.startLine, cwe: [], actionable: ["medium"].includes(item.assessment) })), assessed: true, pdf: null, sources: [] });
  assert.equal(analysis.meta.commit, "02829106f8de603c77c9787861421b96ac2d37fd");
  assert.match(analysis.meta.topRisk, /mutable GitHub Action tags/);
  assert.deepEqual(analysis.cweTable.map((row) => `${row.cwe}:${row.description}`), ["CWE-89:SQL Injection", "CWE-353:null"], "a description that only repeats the id is treated as missing");
  assert.deepEqual(analysis.roadmap, [{ priority: "P1", number: 1, action: "Pin GitHub Actions to commit SHAs.", files: ".github/workflows/ci.yml" }]);
  assert.equal(analysis.screenshots.checked, false, "a markdown report cannot be checked for screenshots");
  const story = narrative(analysis, null, null);
  assert.match(story.executive.join(" "), /Only one report was supplied/);
  assert.match(story.remediation.join(" "), /No remediation can be confirmed from a single report/);
  assert.match(story.conclusion[0], /Whether anything was fixed is not shown by one report/);
  assert.doesNotMatch(JSON.stringify(story), /\d+ (?:were|was|are|is) (?:fixed|remediated)|no longer reported|verified by re-scan/i, "one report never claims a fix");
  assert.deepEqual(analysis.cwe.map((row) => `${row.cwe}:${row.count}:${row.source}`), ["CWE-89:1:report CWE table", "CWE-353:2:report CWE table"]);
});

test("the report passage, dismissal reason and assessment are found for each finding", async () => {
  const md = reportMarkdown();
  const assessed = assessFindings(md, appendixFindings(md));
  assert.deepEqual(assessed.map((item) => `${item.id}:${item.assessment}`), ["OG-001:false-positive", "OG-002:medium", "OG-003:medium"]);
  const { reportExcerpt } = await import("../worker/impact.js");
  const excerpt = reportExcerpt(md, { id: "OG-002", ruleId: MUTABLE.slice(0, 40), file: ".github/workflows/ci.yml", line: 23, assessment: "medium" });
  assert.equal(excerpt.section, "7. Medium Findings");
  assert.match(excerpt.text, /pin the actions to a full commit SHA/);
});

test("before vs after: verified by re-scan, still reported, new, and partly addressed groups", () => {
  const before = report([finding("a", "medium"), finding("b", "medium", { line: 42 }), finding("c", "false-positive", { proposedFix: null })], { commit: "1111111111aa", at: "2026-11-01T00:00:00Z" });
  const after = report([finding("b", "medium", { line: 44 }), finding("d", "high", { ruleId: "other.rule", proposedFix: null })], { id: "scan-2", commit: "2222222222bb", at: "2026-11-05T00:00:00Z" });
  const cmp = compareReports(before, after);
  assert.equal(cmp.matchedBy, "pipeline fingerprint");
  assert.deepEqual(cmp.items.map((item) => `${item.before.id}:${item.status}`), ["a:verified-by-rescan", "b:unresolved", "c:verified-by-rescan"]);
  assert.deepEqual(cmp.introduced.map((item) => item.id), ["d"]);
  assert.deepEqual(cmp.groups.map((group) => `${group.status}:${group.resolved}/${group.total}`), ["partial:1/2"]);
  assert.equal(cmp.verifiedResolved, 1);
  assert.equal(cmp.verifiedPercent, 50, "only actionable findings count, and only with different commits");
  assert.match(narrative(before, cmp, after).executive.join(" "), /no longer reports 1 of the 2 actionable findings \(50%\)/);
});

test("before vs after: no remediation is measured for the same commit, a skipped scanner, or reversed reports", () => {
  const same = compareReports(report([finding("a", "high")], { commit: "1111111111aa" }), report([finding("a", "medium")], { id: "s2", commit: "1111111111aa", at: "2026-11-02T00:00:00Z" }));
  assert.equal(same.sameCommit, true);
  assert.equal(same.verifiedPercent, null);
  assert.match(same.verifiedPercentReason, /same commit/);
  assert.deepEqual(same.items[0].severityChange, { from: "high", to: "medium", scannerLevelUnchanged: true });

  const gone = compareReports(report([finding("a", "high")], { commit: "1111111111aa" }), report([], { id: "s2", commit: "2222222222bb", at: "2026-11-02T00:00:00Z" }));
  assert.equal(gone.items[0].status, "verified-by-rescan");
  const sameCommitGone = compareReports(report([finding("a", "high")], { commit: "1111111111aa" }), report([], { id: "s2", commit: "1111111111aa", at: "2026-11-02T00:00:00Z" }));
  assert.equal(sameCommitGone.items[0].status, "not-reported-same-commit");
  const skipped = compareReports(report([finding("a", "high")], { commit: "1111111111aa" }), report([], { id: "s2", commit: "2222222222bb", at: "2026-11-02T00:00:00Z", scanners: ["codeql"] }));
  assert.equal(skipped.items[0].status, "not-rechecked");
  assert.equal(skipped.verifiedPercent, null);
  const reversed = compareReports(report([finding("a", "high")], { commit: "1111111111aa", at: "2026-11-09T00:00:00Z" }), report([], { id: "s2", commit: "2222222222bb", at: "2026-11-02T00:00:00Z" }));
  assert.equal(reversed.reversed, true);
  assert.equal(reversed.verifiedPercent, null);
});

test("small embedded images such as emoji are not counted as screenshots", () => {
  const pdf = Buffer.from("<</Type /XObject\n/Subtype /Image\n/Width 80\n/Height 76>> <</Type /XObject /Subtype /Image /Width 1280 /Height 720>>", "latin1");
  assert.deepEqual(pdfImages(pdf), { bytes: pdf.length, embeddedImages: 2, screenshotCandidates: 1, largest: 1280 * 720 });
});

test("the API matches an uploaded PDF to its scan by SHA-256 and rejects one it cannot match", async () => {
  const md = reportMarkdown();
  const pdf = Buffer.from("%PDF-1.4 stored report");
  const register = { entries: appendixFindings(md).map((item) => ({ ...item, ruleId: item.ruleId, severity: item.level, fingerprint: item.id.padEnd(64, "f") })) };
  const files = {
    "security-audits/scan-1.pdf": pdf,
    "security-audits/scan-1/raw-outputs/SECURITY_ASSESSMENT_REPORT.md": Buffer.from(md),
    "security-audits/scan-1/raw-outputs/findings-register.json": Buffer.from(JSON.stringify(register)),
  };
  const run = {
    id: "scan-1", project_id: "p1", repository: "acme/web", branch: "main", status: "succeeded", created_at: "2026-11-20T06:15:58Z", report_key: "security-audits/scan-1.pdf",
    scanners_json: '["opengrep"]', coverage_summary_json: null, ai_cost_usd: 0.17, ai_model: "gpt-5-mini",
    raw_outputs_json: JSON.stringify(Object.keys(files).filter((key) => key.includes("raw-outputs")).map((key) => ({ filename: key.split("/").pop(), s3Key: key }))),
  };
  const env = {
    SCAN_STORE: { get: async (key) => (files[key] ? { body: files[key] } : null) },
    DB: { prepare: () => ({ bind: () => ({ all: async () => ({ results: [run] }) }) }) },
  };
  const ctx = { ownedProject: async (_env, _req, id) => (id === "p1" ? { id } : null) };
  const call = (body, project = "p1") => impactRoute(new Request("http://localhost/x", { method: "POST", body: JSON.stringify(body) }), env, `/api/projects/${project}/impact/analyze`, "POST", ctx);

  const ok = await call({ before: { name: "report.pdf", kind: "pdf", sha256: createHash("sha256").update(pdf).digest("hex") } });
  assert.equal(ok.status, 200);
  const { analysis } = await ok.json();
  assert.equal(analysis.before.source.matched, true);
  assert.equal(analysis.before.source.runId, "scan-1");
  assert.equal(analysis.before.total, 3);
  assert.equal(analysis.before.counts.medium, 2);
  assert.equal(analysis.before.findings.find((item) => item.id === "OG-001").dismissal, "Uses bound parameters, not string concatenation.");
  assert.equal(analysis.comparison, null);

  const unmatched = await call({ before: { name: "other.pdf", kind: "pdf", sha256: "a".repeat(64) } });
  assert.equal(unmatched.status, 422);
  assert.match((await unmatched.json()).error, /does not match any report/);
  assert.equal((await call({ before: { name: "x", kind: "exe" } })).status, 400);
  assert.equal((await call({ before: { name: "report.pdf", kind: "pdf", sha256: "a".repeat(64) } }, "someone-else")).status, 404);
  const sameTwice = await call({ before: { kind: "md", text: md }, after: { kind: "md", text: md } });
  assert.equal(sameTwice.status, 400);
  assert.match((await sameTwice.json()).error, /same report/);
});
