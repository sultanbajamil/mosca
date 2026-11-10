/**
 * MOSCA — baseline and differential mode
 * =======================================
 *
 * A scanner that fails on every historical finding is a scanner teams switch
 * off. Real adoption needs a ratchet: accept the debt you already have, then
 * fail the build only when a change makes the estate worse.
 *
 * A baseline is a small JSON document of stable fingerprints. Fingerprints
 * deliberately exclude line numbers: moving a function must not create a
 * "new" finding. They include the rule, the algorithm, the file (or
 * host:port) and the normalised source line, so a genuinely different call
 * still shows up as new.
 *
 * The file is human-readable and diffable on purpose. A baseline is a
 * security decision, not a black box.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';

export const BASELINE_VERSION = 1;

/** Normalise whitespace so reformatting does not invalidate a fingerprint. */
function normaliseText(value) {
  return String(value ?? '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 240);
}

/** Normalise a path so Windows and POSIX runs agree. */
function normalisePath(value) {
  return String(value ?? '').replace(/\\/g, '/').replace(/^\.\//, '');
}

/**
 * A stable, line-independent identity for a finding.
 *
 * Endpoint findings have no file; their host and port are the identity.
 * Source and config findings use the rule, algorithm and normalised line.
 *
 * @param {object} item an enriched or raw finding
 * @returns {string} 32 hex characters
 */
export function fingerprint(item) {
  const loc = item.location || {};
  const where = loc.file
    ? normalisePath(loc.file)
    : loc.host
      ? `${normalisePath(loc.host)}:${loc.port ?? ''}`
      : '';
  const content = normaliseText(item.snippet || item.matched || item.title || '');
  const parts = [item.id, item.kind, item.algorithm, item.primitive, where, content];
  return crypto.createHash('sha256').update(parts.join('\u0000')).digest('hex').slice(0, 32);
}

/** Human-readable location for baseline review and diff reports. */
export function locationLabel(item) {
  const loc = item.location || {};
  if (loc.file) return `${normalisePath(loc.file)}:${loc.line || 0}`;
  if (loc.host) return `${loc.host}:${loc.port ?? ''}`;
  return '';
}

/**
 * Build a baseline document from an analysis.
 *
 * Positive findings are not stored: they describe a control that is already
 * working, and they must never become a reason to ignore a regression.
 *
 * @param {object} analysis
 * @param {{toolVersion?:string, now?:Date}} [opts]
 */
export function buildBaseline(analysis, { toolVersion = '3.0.0', now = new Date() } = {}) {
  const findings = [];
  const seen = new Set();
  for (const item of analysis.items || []) {
    if (item.positive) continue;
    const fp = item.fingerprint || fingerprint(item);
    if (seen.has(fp)) continue;
    seen.add(fp);
    findings.push({
      fingerprint: fp,
      id: item.id,
      algorithm: item.algorithm,
      severity: item.severity,
      location: locationLabel(item),
    });
  }
  findings.sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));

  return {
    version: BASELINE_VERSION,
    tool: 'mosca',
    toolVersion,
    createdAt: now.toISOString(),
    crqcYear: analysis.summary?.crqcYear ?? null,
    count: findings.length,
    findings,
  };
}

/**
 * Load and validate a baseline file.
 * @param {string} file
 */
export function loadBaseline(file) {
  let raw;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') throw new Error(`Baseline file not found: ${file}`);
    throw err;
  }
  let doc;
  try {
    doc = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Invalid JSON in baseline ${file}: ${err.message}`);
  }
  if (doc.version !== BASELINE_VERSION) {
    throw new Error(`Unsupported baseline version ${doc.version} in ${file} (expected ${BASELINE_VERSION})`);
  }
  if (!Array.isArray(doc.findings)) {
    throw new Error(`Baseline ${file} has no findings array`);
  }
  for (const entry of doc.findings) {
    if (!entry || typeof entry.fingerprint !== 'string') {
      throw new Error(`Baseline ${file} contains an entry without a fingerprint`);
    }
  }
  return doc;
}

/**
 * Annotate an analysis against a baseline.
 *
 * Mutates `analysis.items` (adds `fingerprint` and `baselineStatus`) and adds
 * a `summary.baseline` block plus `analysis.resolved`. Returns the analysis
 * for convenient chaining.
 *
 * @param {object} analysis
 * @param {object} baseline
 */
export function applyBaseline(analysis, baseline) {
  const known = new Map();
  for (const entry of baseline.findings) known.set(entry.fingerprint, entry);

  const seen = new Set();
  let newFindings = 0;
  let newActionable = 0;
  let highestNew = 'info';

  const severityOrder = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

  for (const item of analysis.items) {
    const fp = item.fingerprint || fingerprint(item);
    item.fingerprint = fp;
    if (item.positive) {
      item.baselineStatus = 'positive';
      continue;
    }
    if (known.has(fp)) {
      item.baselineStatus = 'existing';
      seen.add(fp);
    } else {
      item.baselineStatus = 'new';
      item.isNew = true;
      newFindings += 1;
      if (item.severity !== 'info') newActionable += 1;
      if ((severityOrder[item.severity] ?? 0) > (severityOrder[highestNew] ?? 0)) {
        highestNew = item.severity;
      }
    }
  }

  const resolved = baseline.findings
    .filter((entry) => !seen.has(entry.fingerprint))
    .map((entry) => ({ ...entry }));

  analysis.resolved = resolved;
  analysis.summary.baseline = {
    supplied: true,
    createdAt: baseline.createdAt || null,
    toolVersion: baseline.toolVersion || null,
    recorded: baseline.findings.length,
    newFindings,
    newActionable,
    existingFindings: analysis.items.filter((i) => i.baselineStatus === 'existing').length,
    resolvedFindings: resolved.length,
    highestNewSeverity: highestNew,
  };

  return analysis;
}

/** Only the findings that are new relative to a supplied baseline. */
export function newItems(analysis) {
  return (analysis.items || []).filter((item) => !item.positive && item.baselineStatus === 'new');
}
