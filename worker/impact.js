// Scan Impact Analysis: reads a downloaded ADIS security report back in and explains
// what it found and, given a later report, what changed.
//
// The uploaded file is matched by SHA-256 to a report this project's scans produced, so
// the analysis reads that run's own stored evidence (report markdown, findings register,
// scanner outputs, remediation plan). A markdown report that matches no run is parsed on
// its own, with less evidence. Nothing here writes to the database or the artifact store.
//
// The analysis never claims more than the reports show. One report shows what was
// detected and what fixes it proposed. Only a second, later report can show that a
// finding is no longer reported, and neither report contains code diffs, so an applied
// fix is never asserted.

import { createHash } from 'node:crypto';
import { ASSESSMENTS, assessFindings, findingsFor } from './scan.js';

const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' } });
const parseJson = (value, fallback) => { try { return JSON.parse(value); } catch { return fallback; } };
const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const clip = (value, max) => { const text = String(value ?? ''); return text.length > max ? text.slice(0, max - 1).trimEnd() + '…' : text; };
const MAX_MARKDOWN_CHARS = 600000;
const MAX_RUNS_SEARCHED = 100;

export const ACTIONABLE = ['critical', 'high', 'medium', 'low', 'hardening'];
export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'hardening', 'false-positive', 'not-in-report'];
const SECTION_TITLES = {
  critical: 'Critical Findings', high: 'High Findings', medium: 'Medium Findings', low: 'Low Findings',
  hardening: 'Infrastructure & Hardening', 'false-positive': 'False Positives',
};

// ---------- markdown helpers ----------

const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const plain = (text) => String(text || '')
  .replace(/<br\s*\/?>/gi, '\n').replace(/<\/(p|div|h\d|li)>/gi, '\n').replace(/<[^>]+>/g, '')
  .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
  .replace(/\n{3,}/g, '\n\n').trim();

export function markdownSection(markdown, title) {
  const heading = new RegExp(`^##\\s+(?:\\d+\\.\\s*)?${escapeRegExp(title)}\\b.*$`, 'im');
  const match = String(markdown || '').match(heading);
  if (!match) return null;
  const rest = markdown.slice(match.index + match[0].length);
  const next = rest.search(/^##\s/m);
  return next < 0 ? rest : rest.slice(0, next);
}

function tableRows(text) {
  return String(text || '').split('\n')
    .filter((line) => /^\s*\|/.test(line) && !/^\s*\|\s*:?-{3}/.test(line))
    .map((line) => line.trim().replace(/^\||\|$/g, '').split('|').map((cell) => cell.trim().replace(/^`|`$/g, '')));
}

function lineList(spec) {
  return String(spec || '').split(/[,;]/).flatMap((part) => {
    const numbers = part.match(/\d+/g);
    if (!numbers) return [];
    const [from, to] = numbers.map(Number);
    return [[from, to ?? from]];
  });
}
const coversLine = (spec, line) => lineList(spec).some(([from, to]) => line >= from && line <= to);

export function reportMeta(markdown) {
  const text = String(markdown || '');
  const commit = text.match(/commit\s+`?([0-9a-f]{7,40})`?/i)?.[1] || null;
  const topRisk = text.match(/TOP RISK[^:]*:\s*<\/strong>\s*([\s\S]*?)<\/div>/i)?.[1] || text.match(/TOP RISK[^:]*:\*{0,2}\s*(.+)/i)?.[1] || null;
  const overview = markdownSection(text, 'Overview');
  return {
    commit,
    topRisk: topRisk ? clip(plain(topRisk), 600) : null,
    overview: overview ? clip(plain(overview.split(/<div class="callout/)[0]), 1500) : null,
  };
}

export function cweTable(markdown) {
  const section = markdownSection(markdown, 'Security Findings by CWE') || (String(markdown || '').match(/###[^\n]*Findings by CWE[^\n]*\n([\s\S]*?)(?=\n#{2,3}\s|$)/)?.[1]) || '';
  return tableRows(section).filter((cells) => /^CWE-\d+$/i.test(cells[0])).map((cells) => ({
    cwe: cells[0].toUpperCase(), description: (() => { const text = cells[1].replace(/⚠.*$/, '').trim(); return text && text.toUpperCase() !== cells[0].toUpperCase() ? text : null; })(), locations: Number(cells[2]) || null,
  }));
}

export function remediationRoadmap(markdown) {
  const section = markdownSection(markdown, 'Remediation Roadmap');
  if (!section) return [];
  const items = [];
  let priority = null;
  for (const line of section.split('\n')) {
    const heading = line.match(/^###\s+(P\d)\b/);
    if (heading) { priority = heading[1]; continue; }
    const cells = tableRows(line)[0];
    if (cells && /^\d+$/.test(cells[0]) && cells.length >= 2) items.push({ priority, number: Number(cells[0]), action: plain(cells[1]), files: plain(cells[2] || '') });
  }
  return items;
}

function falsePositiveRows(markdown) {
  return tableRows(markdownSection(markdown, 'False Positives') || '')
    .filter((cells) => cells.length >= 4 && !/^file$/i.test(cells[0]))
    .map((cells) => ({ file: cells[0], lines: cells[1], rule: cells[2], reason: plain(cells[3]), appendix: cells[4] || '' }));
}

// The units of a report section a finding can be cited in: table rows and ### blocks / finding cards.
function sectionUnits(section) {
  if (!section) return [];
  const rows = section.split('\n').filter((line) => (line.match(/\|/g) || []).length >= 3 && !/^\s*\|?\s*:?-{3}/.test(line) && !/^\s*\|?\s*File\s*\|/i.test(line));
  const blocks = section.split(/^###\s|<div class="finding-card">/m).slice(1);
  return [...blocks.map((text) => ({ text, row: false })), ...rows.map((text) => ({ text, row: true }))];
}

function unitCites(unit, finding) {
  const { text, row } = unit;
  if (finding.id && new RegExp(`(?<![\\w-])${escapeRegExp(finding.id)}(?![\\w-])`).test(text)) return true;
  const namesFile = finding.file && text.includes(finding.file);
  if (!namesFile) return false;
  if (row) {
    const cells = text.split('|').map((cell) => cell.trim());
    const spec = cells.find((cell) => /^\d+(\s*[-–,]\s*\d+)*$/.test(cell));
    if (spec && finding.line && !coversLine(spec, finding.line)) return false;
    return Boolean(finding.ruleId && text.includes(finding.ruleId.split('.').slice(0, 3).join('.')));
  }
  if (finding.ruleId && text.includes(finding.ruleId)) return true;
  const cite = text.match(new RegExp(`${escapeRegExp(finding.file)}\`?(?::|\\s*\\(?\\s*lines?\\s+)([\\d\\s,–-]+)`, 'i'));
  return Boolean(cite && finding.line && coversLine(cite[1], finding.line));
}

// The passage of the report that assessed this finding, quoted as evidence.
export function reportExcerpt(markdown, finding) {
  const title = SECTION_TITLES[finding.assessment];
  if (!title) return null;
  const section = markdownSection(markdown, title);
  const unit = sectionUnits(section).find((item) => unitCites(item, finding));
  if (!unit) return null;
  const text = unit.row ? unit.text.trim() : plain(unit.text.split(/\n##\s/)[0]);
  const heading = String(markdown).match(new RegExp(`^##\\s+(?:\\d+\\.\\s*)?${escapeRegExp(title)}[^\\n]*`, 'im'))?.[0].replace(/^##\s+/, '') || title;
  return { section: heading, text: clip(text, 1200) };
}

// ---------- findings from a stored run, or from a markdown report alone ----------

function cweFromSarif(sarif) {
  const map = {};
  for (const run of sarif?.runs || []) {
    const rules = [...(run.tool?.driver?.rules || []), ...(run.tool?.extensions || []).flatMap((ext) => ext.rules || [])];
    for (const rule of rules) {
      const cwes = (rule.properties?.tags || []).map((tag) => tag.match(/cwe[-/](\d+)/i)?.[1]).filter(Boolean).map((n) => `CWE-${Number(n)}`);
      if (cwes.length && rule.id) map[rule.id] = [...new Set(cwes)];
    }
  }
  return map;
}

// CWE names as OpenGrep's rule metadata states them ("CWE-1357: Reliance on ...").
function cweNamesFrom(report) {
  const names = {};
  for (const result of report?.results || []) {
    for (const value of result.extra?.metadata?.cwe || []) {
      const match = String(value).match(/^(CWE-\d+)\s*:\s*(.+)$/i);
      if (match) names[match[1].toUpperCase()] = match[2].trim();
    }
  }
  return names;
}

function opengrepEvidence(report) {
  const byLocation = {};
  for (const result of report?.results || []) {
    const key = `${result.path}:${result.start?.line}:${result.check_id}`;
    const cwes = (result.extra?.metadata?.cwe || []).map((value) => String(value).match(/CWE-\d+/i)?.[0]?.toUpperCase()).filter(Boolean);
    byLocation[key] = { snippet: result.extra?.lines ? clip(String(result.extra.lines).replace(/\s+$/, ''), 800) : null, cwe: [...new Set(cwes)] };
  }
  return byLocation;
}

function remediationGroups(plan) {
  const byFingerprint = {};
  for (const group of plan?.groups || []) {
    const fingerprints = String(group.fingerprints || '').match(/[0-9a-f]{64}/g) || [];
    const fix = { title: plain(group.title), priority: group.priority || null, roadmapNumber: group.roadmapNumber ? Number(group.roadmapNumber) || null : null };
    for (const fingerprint of fingerprints) (byFingerprint[fingerprint] ||= []).push(fix);
  }
  // A finding can sit in several roadmap groups; list them in roadmap order.
  for (const fixes of Object.values(byFingerprint)) fixes.sort((a, b) => (a.roadmapNumber ?? 99) - (b.roadmapNumber ?? 99));
  return byFingerprint;
}

// Parse "Appendix A — Complete Scanner Findings" when the report is all we have.
export function appendixFindings(markdown) {
  const appendix = String(markdown || '').split(/^##\s+Appendix A\b.*$/im)[1];
  if (!appendix) return [];
  const findings = [];
  let scanner = null;
  for (const line of appendix.split('\n')) {
    const heading = line.match(/^###\s+([A-Za-z][\w .-]*?)\s+—\s+\d+\s+findings?/);
    if (heading) { scanner = heading[1].trim(); continue; }
    if (/^##\s/.test(line)) break;
    const cells = tableRows(line)[0];
    if (!cells || cells.length < 6 || /^id$/i.test(cells[0])) continue;
    findings.push({ id: cells[0], scanner, level: cells[1].toLowerCase(), ruleId: cells[2].replace(/…$/, ''), ruleTruncated: /…$/.test(cells[2]), filePath: cells[3], startLine: Number(cells[4]) || null, message: plain(cells[5]) });
  }
  return findings;
}

function decorate(entries, markdown, { cweByRule = {}, opengrep = {}, groups = {} } = {}) {
  const fpRows = falsePositiveRows(markdown);
  return entries.map((entry) => {
    const finding = {
      key: null, id: entry.id || null, scanner: entry.scanner || null, ruleId: entry.ruleId || null, file: entry.filePath || null,
      line: Number(entry.startLine) || null, level: entry.level || null, message: entry.message || null,
      assessment: entry.assessment || 'not-in-report', fingerprint: entry.fingerprint || null,
    };
    const og = opengrep[`${finding.file}:${finding.line}:${finding.ruleId}`];
    finding.cwe = [...new Set([...(og?.cwe || []), ...(cweByRule[finding.ruleId] || [])])];
    finding.snippet = og?.snippet || null;
    finding.actionable = ACTIONABLE.includes(finding.assessment);
    finding.excerpt = reportExcerpt(markdown, finding);
    finding.proposedFixes = (finding.fingerprint && groups[finding.fingerprint]) || [];
    finding.proposedFix = finding.proposedFixes[0] || null;
    if (finding.assessment === 'false-positive') {
      const row = fpRows.find((item) => item.file === finding.file && (!finding.line || !item.lines || coversLine(item.lines, finding.line)) && (!finding.ruleId || item.rule.startsWith(finding.ruleId.split('.').slice(0, 3).join('.')) || finding.ruleId.startsWith(item.rule)));
      finding.dismissal = row ? row.reason : null;
    } else finding.dismissal = null;
    return finding;
  });
}

// Embedded images in the report PDF. Chromium stores colour emoji as small bitmaps, so only
// images at least 300 px on each side are counted as possible screenshots.
export function pdfImages(bytes) {
  const text = Buffer.from(bytes).toString('latin1');
  const images = [...text.matchAll(/<<[^<>]*?\/Subtype\s*\/Image\b[^<>]*?>>/g)].map((match) => ({
    width: Number(match[0].match(/\/Width\s+(\d+)/)?.[1]) || 0, height: Number(match[0].match(/\/Height\s+(\d+)/)?.[1]) || 0,
  }));
  const large = images.filter((image) => image.width >= 300 && image.height >= 300);
  return { bytes: bytes.length, embeddedImages: images.length, screenshotCandidates: large.length, largest: images.reduce((max, image) => Math.max(max, image.width * image.height), 0) };
}

export async function storedRunEvidence(env, run) {
  const outputs = parseJson(run.raw_outputs_json, []);
  const read = async (name) => {
    const item = outputs.find((output) => output.filename === name);
    const file = item ? await env.SCAN_STORE.get(item.s3Key) : null;
    return file ? file.body.toString('utf8') : null;
  };
  const markdown = await read('SECURITY_ASSESSMENT_REPORT.md');
  const found = await findingsFor(env, run);
  const opengrepReport = parseJson(await read('opengrep.json'), null);
  const evidence = {
    cweByRule: cweFromSarif(parseJson(await read('codeql.sarif'), null)),
    opengrep: opengrepEvidence(opengrepReport),
    groups: remediationGroups(parseJson(await read('remediation-plan.json'), null)),
  };
  const pdf = run.report_key ? await env.SCAN_STORE.get(run.report_key) : null;
  const sources = ['SECURITY_ASSESSMENT_REPORT.md', 'findings-register.json', 'opengrep.json', 'codeql.sarif', 'remediation-plan.json', 'coverage-gaps.json']
    .filter((name) => outputs.some((output) => output.filename === name));
  return {
    markdown: markdown || '',
    assessed: Boolean(found?.assessed),
    findings: decorate(found?.entries || [], markdown || '', evidence),
    pdf: pdf ? pdfImages(pdf.body) : null,
    cweNames: cweNamesFrom(opengrepReport),
    sources,
  };
}

// ---------- building one report's analysis ----------

export function buildReportAnalysis({ upload, run, markdown, findings, assessed, pdf, sources, cweNames = {} }) {
  const meta = reportMeta(markdown);
  const counts = Object.fromEntries(SEVERITY_ORDER.map((key) => [key, 0]));
  for (const finding of findings) counts[finding.assessment] = (counts[finding.assessment] || 0) + 1;
  const scanners = {};
  for (const finding of findings) scanners[finding.scanner || 'unknown'] = (scanners[finding.scanner || 'unknown'] || 0) + 1;
  const cweCounts = {};
  for (const finding of findings) for (const cwe of finding.cwe) cweCounts[cwe] = (cweCounts[cwe] || 0) + 1;
  const table = cweTable(markdown);
  return {
    source: {
      name: clip(upload.name || 'report', 200), kind: upload.kind, sha256: upload.sha256, matched: Boolean(run), runId: run?.id || null,
      evidenceFiles: run ? sources : ['uploaded markdown report'],
      note: run ? `Byte-for-byte identical to the report of scan ${run.id}, so that scan's stored outputs are used as evidence.` : 'This markdown report matches no stored scan, so only its own text is used. Code snippets, CWE tags from scanner outputs and the remediation plan are unavailable.',
    },
    meta: {
      repository: run?.repository || null, branch: run?.branch || null, commit: meta.commit, scannedAt: run?.created_at || null,
      finishedAt: run?.finished_at || null, scanners: run ? parseJson(run.scanners_json, []) : [...new Set(findings.map((item) => String(item.scanner || '').toLowerCase()).filter(Boolean))],
      aiModel: run?.ai_model || null, aiCostUsd: run && run.ai_cost_usd != null ? Number(run.ai_cost_usd) : null,
      coverage: run ? parseJson(run.coverage_summary_json, null) : null, topRisk: meta.topRisk, overview: meta.overview,
    },
    assessed,
    counts,
    total: findings.length,
    actionable: findings.filter((item) => item.actionable).length,
    scanners,
    // CWE ids from the scanner outputs per finding; a report read on its own only has its CWE table.
    cwe: Object.keys(cweCounts).length
      ? Object.entries(cweCounts).sort((a, b) => b[1] - a[1]).map(([cwe, count]) => ({ cwe, count, description: table.find((row) => row.cwe === cwe)?.description || cweNames[cwe] || null, source: 'scanner outputs' }))
      : table.filter((row) => row.locations).map((row) => ({ cwe: row.cwe, count: row.locations, description: row.description, source: 'report CWE table' })),
    cweTable: table,
    roadmap: remediationRoadmap(markdown),
    screenshots: pdf ? { checked: true, count: pdf.screenshotCandidates, smallImages: pdf.embeddedImages - pdf.screenshotCandidates } : { checked: false, count: null, smallImages: null },
    findings,
  };
}

// ---------- before vs after ----------

const locationKey = (finding) => [String(finding.scanner || '').toLowerCase(), finding.file || '', finding.line || '', String(finding.ruleId || '').split('.').slice(0, 4).join('.')].join('|');

export function compareReports(before, after) {
  const byFingerprint = before.findings.every((item) => item.fingerprint) && after.findings.every((item) => item.fingerprint);
  const keyOf = byFingerprint ? (item) => item.fingerprint : locationKey;
  const afterByKey = new Map(after.findings.map((item) => [keyOf(item), item]));
  const beforeKeys = new Set(before.findings.map(keyOf));
  const commitsKnown = Boolean(before.meta.commit && after.meta.commit);
  const sameCommit = commitsKnown && (before.meta.commit.startsWith(after.meta.commit) || after.meta.commit.startsWith(before.meta.commit));
  const afterScanners = new Set(after.meta.scanners.map((name) => String(name).toLowerCase()));
  const order = (a, b) => (a.scannedAt || '').localeCompare(b.scannedAt || '');
  const reversed = before.meta.scannedAt && after.meta.scannedAt && order(before.meta, after.meta) > 0;

  const items = before.findings.map((finding) => {
    const later = afterByKey.get(keyOf(finding));
    let status;
    if (later) status = 'unresolved';
    else if (!afterScanners.has(String(finding.scanner || '').toLowerCase())) status = 'not-rechecked';
    else if (sameCommit) status = 'not-reported-same-commit';
    else if (!commitsKnown) status = 'not-reported-unverified';
    else status = 'verified-by-rescan';
    const severityChange = later && later.assessment !== finding.assessment ? { from: finding.assessment, to: later.assessment, scannerLevelUnchanged: later.level === finding.level } : null;
    return { before: finding, after: later || null, status, severityChange };
  });
  const introduced = after.findings.filter((item) => !beforeKeys.has(keyOf(item)));

  // A remediation group (or, without one, a rule in a file) is partly addressed when some of
  // its findings are no longer reported and others remain.
  const groups = new Map();
  for (const item of items) {
    if (!item.before.actionable) continue;
    const name = item.before.proposedFix?.title || `${item.before.ruleId} in ${item.before.file}`;
    if (!groups.has(name)) groups.set(name, []);
    groups.get(name).push(item);
  }
  const groupStatus = [...groups.entries()].map(([name, members]) => {
    const resolved = members.filter((item) => item.status === 'verified-by-rescan').length;
    const remaining = members.filter((item) => item.status === 'unresolved').length;
    const status = resolved && remaining ? 'partial' : resolved === members.length ? 'resolved' : remaining === members.length ? 'unresolved' : 'mixed';
    return { name, priority: members[0].before.proposedFix?.priority || null, total: members.length, resolved, remaining, status };
  });

  const actionableBefore = items.filter((item) => item.before.actionable);
  const verified = actionableBefore.filter((item) => item.status === 'verified-by-rescan').length;
  const canMeasure = commitsKnown && !sameCommit && !reversed && actionableBefore.length > 0 && actionableBefore.every((item) => item.status !== 'not-rechecked');
  const statusCounts = {};
  for (const item of items) statusCounts[item.status] = (statusCounts[item.status] || 0) + 1;
  return {
    matchedBy: byFingerprint ? 'pipeline fingerprint' : 'scanner, file, line and rule (a fix that moved code may show as resolved plus new)',
    commitsKnown, sameCommit, reversed: Boolean(reversed),
    items, introduced, groups: groupStatus, statusCounts,
    actionableBefore: actionableBefore.length,
    actionableAfter: after.findings.filter((item) => item.actionable).length,
    verifiedResolved: verified,
    verifiedPercent: canMeasure ? Math.round((verified / actionableBefore.length) * 1000) / 10 : null,
    verifiedPercentReason: canMeasure ? null : !commitsKnown ? 'A commit is missing from one report, so a code change cannot be established.' : sameCommit ? 'Both reports scanned the same commit, so no code changed between them.' : reversed ? 'The "after" report is older than the "before" report.' : actionableBefore.length === 0 ? 'The first report has no actionable findings.' : 'A scanner from the first report did not run in the second, so some findings were not re-checked.',
  };
}

// ---------- the written analysis (fixed rules, no AI) ----------

const verb = (count, one, many) => (count === 1 ? one : many);
const plural = (count, word) => `${count} ${count === 1 ? word : word.endsWith('y') ? word.slice(0, -1) + 'ies' : word + 's'}`;
const label = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', hardening: 'hardening', 'false-positive': 'false positive', 'not-in-report': 'not in report' };

export function narrative(before, comparison, after) {
  const c = before.counts;
  const severe = ['critical', 'high', 'medium', 'low'].filter((key) => c[key]).map((key) => `${c[key]} ${label[key]}`);
  const where = before.meta.repository ? `${before.meta.repository}${before.meta.branch ? ` (branch ${before.meta.branch}` : ''}${before.meta.commit ? `, commit ${before.meta.commit.slice(0, 10)}` : ''}${before.meta.branch ? ')' : ''}` : 'the scanned repository';
  const out = {};
  out.executive = [
    `The scan of ${where} reported ${plural(before.total, 'raw finding')}. After the report reviewed each one in the code, ${plural(before.actionable, 'finding')} remained actionable${severe.length ? ` (${severe.join(', ')}${c.hardening ? `, ${c.hardening} hardening` : ''})` : c.hardening ? ` (${c.hardening} hardening)` : ''}, ${c['false-positive']} ${verb(c['false-positive'], 'was dismissed as a false positive', 'were dismissed as false positives')} and ${c['not-in-report']} ${verb(c['not-in-report'], 'was', 'were')} left out of the report.`,
    before.meta.topRisk ? `The report names its top risk as: ${before.meta.topRisk}` : 'The report does not name a single top risk.',
    comparison
      ? comparison.verifiedPercent != null
        ? `A later scan of commit ${after.meta.commit.slice(0, 10)} no longer reports ${comparison.verifiedResolved} of the ${comparison.actionableBefore} actionable findings (${comparison.verifiedPercent}%), ${plural(comparison.statusCounts.unresolved || 0, 'finding')} are still reported, and ${plural(comparison.introduced.length, 'new finding')} appeared.`
        : `A second report was supplied, but a remediation rate cannot be measured: ${comparison.verifiedPercentReason}`
      : 'Only one report was supplied, so this analysis describes the state at scan time. It cannot show that anything was fixed; upload a report from a later scan to compare.',
  ];
  out.posture = [
    `Before remediation the codebase had ${plural(before.actionable, 'actionable finding')} across ${plural(Object.keys(before.scanners).length, 'scanner')} and ${plural(before.cwe.length, 'CWE category')}.`,
    before.meta.coverage ? (before.meta.coverage.gapCount ? `Coverage was incomplete: ${(before.meta.coverage.partiallyCoveredLanguages || []).concat(before.meta.coverage.uncoveredLanguages || []).join(', ') || 'some languages'} had no language-specific security rules, so findings there could be missed.` : 'The coverage check found every language in the repository analysed.') : 'The report gives no coverage summary.',
  ];
  out.remediation = comparison ? [
    `Status of the ${plural(comparison.items.length, 'finding')} in the first report: ${Object.entries(comparison.statusCounts).map(([key, value]) => `${value} ${STATUS_TEXT[key].toLowerCase()}`).join(', ')}.`,
    'Neither report contains code diffs, so an applied fix cannot be shown directly. "No longer reported" means the same scanner ran on a newer commit and did not report the finding.',
  ] : [
    'No remediation can be confirmed from a single report. Each finding below is shown as detected, with the fix the report proposed where it gave one.',
    `${before.findings.filter((item) => item.actionable && item.proposedFix).length} of the ${plural(before.actionable, 'actionable finding')} are linked to a fix in the report's remediation plan, which lists ${plural(before.roadmap.length, 'action')} in total.`,
  ];
  out.impact = comparison
    ? comparison.verifiedPercent != null
      ? [`Actionable findings went from ${comparison.actionableBefore} to ${comparison.actionableAfter}. ${comparison.verifiedResolved} were verified as no longer reported by a re-scan of a newer commit.`]
      : [`Actionable findings: ${comparison.actionableBefore} in the first report, ${comparison.actionableAfter} in the second. This difference is not a measured improvement: ${comparison.verifiedPercentReason}`]
    : ['No measured improvement can be reported from one scan. The measurable result of this scan is what it detected and ruled out.'];
  const remaining = comparison ? comparison.items.filter((item) => item.status === 'unresolved' && item.after.actionable).map((item) => item.after) : before.findings.filter((item) => item.actionable);
  out.risks = [
    remaining.length ? `${plural(remaining.length, 'actionable finding')} still ${comparison ? 'reported' : 'open'}, led by ${remaining.slice().sort((a, b) => SEVERITY_ORDER.indexOf(a.assessment) - SEVERITY_ORDER.indexOf(b.assessment))[0].assessment} severity.` : 'No actionable findings remain in the latest report.',
    comparison && comparison.introduced.length ? `${plural(comparison.introduced.length, 'finding')} appeared that the first report did not contain.` : null,
    before.meta.coverage?.gapCount ? 'Coverage gaps mean some code had no language-specific security analysis.' : null,
  ].filter(Boolean);
  const proposed = before.findings.filter((item) => item.actionable && item.proposedFix).length;
  const proposedText = before.roadmap.length ? `its report proposed ${plural(before.roadmap.length, 'remediation action')}${proposed ? ` (${proposed} linked to specific findings)` : ''}` : 'its report proposed no remediation roadmap';
  out.conclusion = [comparison && comparison.verifiedPercent != null
    ? `ADIS detected ${plural(before.actionable, 'actionable issue')}, ${proposedText}, and a re-scan of a newer commit confirmed that ${comparison.verifiedResolved} ${verb(comparison.verifiedResolved, 'is', 'are')} no longer reported.`
    : `ADIS detected ${plural(before.actionable, 'actionable issue')} and ${proposedText}. Whether anything was fixed is not shown by ${comparison ? 'these reports' : 'one report'}.`];
  return out;
}

export const STATUS_TEXT = {
  unresolved: 'Still reported', 'verified-by-rescan': 'No longer reported (verified by re-scan)', 'not-rechecked': 'Not re-checked (scanner did not run)',
  'not-reported-same-commit': 'Not reported, same commit (no code change)', 'not-reported-unverified': 'Not reported (commit unknown, unverified)',
};

// ---------- matching an upload to a stored run ----------

async function findRun(env, projectId, upload) {
  const runs = (await env.DB.prepare("SELECT * FROM security_scan_runs WHERE project_id=? AND status IN ('succeeded','failed') ORDER BY created_at DESC LIMIT ?").bind(projectId, MAX_RUNS_SEARCHED).all()).results;
  for (const run of runs) {
    if (upload.kind === 'pdf') {
      if (!run.report_key) continue;
      const file = await env.SCAN_STORE.get(run.report_key);
      if (file && sha256(file.body) === upload.sha256) return run;
    } else {
      const item = parseJson(run.raw_outputs_json, []).find((output) => output.filename === 'SECURITY_ASSESSMENT_REPORT.md');
      const file = item ? await env.SCAN_STORE.get(item.s3Key) : null;
      if (file && sha256(file.body) === upload.sha256) return run;
    }
  }
  return null;
}

function validUpload(value) {
  if (!value || typeof value !== 'object') return null;
  const kind = value.kind === 'pdf' ? 'pdf' : value.kind === 'md' ? 'md' : null;
  if (!kind) return null;
  if (kind === 'md') {
    if (typeof value.text !== 'string' || !value.text.trim() || value.text.length > MAX_MARKDOWN_CHARS) return null;
    return { kind, name: String(value.name || 'report.md'), text: value.text, sha256: sha256(Buffer.from(value.text, 'utf8')) };
  }
  if (!/^[0-9a-f]{64}$/.test(String(value.sha256 || ''))) return null;
  return { kind, name: String(value.name || 'report.pdf'), sha256: value.sha256 };
}

class ImpactError extends Error { constructor(status, message) { super(message); this.status = status; } }

async function analyseUpload(env, projectId, upload, role) {
  const run = await findRun(env, projectId, upload);
  if (run) return buildReportAnalysis({ upload, run, ...(await storedRunEvidence(env, run)) });
  if (upload.kind === 'pdf') throw new ImpactError(422, `The ${role} PDF does not match any report produced by this project's scans, so it cannot be read reliably. Upload the PDF exactly as downloaded from Operate (in the same project), or the report's SECURITY_ASSESSMENT_REPORT.md.`);
  const entries = appendixFindings(upload.text);
  if (!entries.length && !/^##\s+\d*\.?\s*Overview/im.test(upload.text)) throw new ImpactError(422, `The ${role} file does not look like an ADIS security assessment report.`);
  const assessed = entries.length ? assessFindings(upload.text, entries) : [];
  return buildReportAnalysis({ upload, run: null, markdown: upload.text, findings: decorate(assessed, upload.text), assessed: true, pdf: null, sources: [] });
}

export async function impactRoute(req, env, path, method, ctx) {
  const match = path.match(/^\/api\/projects\/([^/]+)\/impact\/analyze$/);
  if (!match) return null;
  const projectId = decodeURIComponent(match[1]);
  const project = await ctx.ownedProject(env, req, projectId);
  if (!project) return json({ error: 'Project not found.' }, 404);
  if (method !== 'POST') return json({ error: 'Method not allowed.' }, 405);
  if (!env.SCAN_STORE) return json({ error: 'Scan reports are not available on this server.' }, 503);
  const body = await req.json().catch(() => null);
  const beforeUpload = validUpload(body?.before);
  if (!beforeUpload) return json({ error: 'Choose an ADIS report (PDF or .md) to analyse.' }, 400);
  const afterUpload = body?.after ? validUpload(body.after) : null;
  if (body?.after && !afterUpload) return json({ error: 'The second report could not be read. Use a PDF or .md report.' }, 400);
  try {
    const before = await analyseUpload(env, projectId, beforeUpload, 'first');
    const after = afterUpload ? await analyseUpload(env, projectId, afterUpload, 'second') : null;
    if (after && before.source.sha256 === after.source.sha256) return json({ error: 'Both files are the same report. Upload a report from a later scan as the second file.' }, 400);
    const comparison = after ? compareReports(before, after) : null;
    return json({ analysis: { generatedAt: new Date().toISOString(), before, after, comparison, narrative: narrative(before, comparison, after), severityOrder: SEVERITY_ORDER, assessments: ASSESSMENTS, statusText: STATUS_TEXT } });
  } catch (error) {
    if (error instanceof ImpactError) return json({ error: error.message }, error.status);
    throw error;
  }
}
