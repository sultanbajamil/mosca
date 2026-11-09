/**
 * Baseline / differential mode. The contract that matters: moving code must
 * not create a new finding, but a genuinely new call must.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  BASELINE_VERSION,
  fingerprint,
  buildBaseline,
  loadBaseline,
  applyBaseline,
  newItems,
  locationLabel,
} from '../src/analysis/baseline.js';

function finding(overrides = {}) {
  return {
    id: 'js-hash-md5',
    kind: 'source',
    algorithm: 'md5',
    primitive: 'hash',
    severity: 'critical',
    positive: false,
    location: { file: 'src/app.js', line: 10, column: 3 },
    snippet: "crypto.createHash('md5')",
    ...overrides,
  };
}

function analysis(items) {
  return {
    items,
    summary: { crqcYear: 2033 },
  };
}

test('fingerprints are stable when code moves but change with the call', () => {
  const a = finding({ location: { file: 'src/app.js', line: 10, column: 3 } });
  const b = finding({ location: { file: 'src/app.js', line: 40, column: 7 } });
  const different = finding({ snippet: "crypto.createHash('sha1')", algorithm: 'sha1' });
  const otherFile = finding({ location: { file: 'src/other.js', line: 10 } });

  assert.equal(fingerprint(a), fingerprint(b));
  assert.notEqual(fingerprint(a), fingerprint(different));
  assert.notEqual(fingerprint(a), fingerprint(otherFile));
});

test('endpoint fingerprints use host and port', () => {
  const base = finding({
    kind: 'endpoint',
    id: 'endpoint-classical-kex',
    primitive: 'key-agreement',
    algorithm: 'x25519',
    location: { host: 'example.com', port: 443 },
    snippet: undefined,
  });
  const same = { ...base, location: { host: 'example.com', port: 443 } };
  const otherPort = { ...base, location: { host: 'example.com', port: 8443 } };
  assert.equal(fingerprint(base), fingerprint(same));
  assert.notEqual(fingerprint(base), fingerprint(otherPort));
});

test('buildBaseline stores actionable findings only, sorted and deduplicated', () => {
  const a = finding();
  const duplicate = finding();
  const positive = finding({ positive: true, id: 'endpoint-hybrid-kex' });
  const doc = buildBaseline(analysis([a, duplicate, positive]), { now: new Date('2026-01-01T00:00:00Z') });

  assert.equal(doc.version, BASELINE_VERSION);
  assert.equal(doc.count, 1);
  assert.equal(doc.findings.length, 1);
  assert.equal(doc.createdAt, '2026-01-01T00:00:00.000Z');
  assert.equal(doc.findings[0].id, 'js-hash-md5');
  assert.equal(locationLabel(a), 'src/app.js:10');
});

test('applyBaseline marks new, existing and resolved findings', () => {
  const existing = finding();
  const baseline = buildBaseline(analysis([existing, finding({ location: { file: 'old.js', line: 1 } })]));

  const current = finding({ location: { file: 'src/app.js', line: 99 } }); // moved, same call
  const regression = finding({
    location: { file: 'src/new.js', line: 5 },
    snippet: "crypto.createHash('md5', secret)",
  });
  const a = analysis([current, regression]);
  applyBaseline(a, baseline);

  assert.equal(current.baselineStatus, 'existing');
  assert.equal(regression.baselineStatus, 'new');
  assert.equal(regression.isNew, true);
  assert.equal(a.summary.baseline.newFindings, 1);
  assert.equal(a.summary.baseline.existingFindings, 1);
  assert.equal(a.summary.baseline.resolvedFindings, 1);
  assert.equal(a.summary.baseline.highestNewSeverity, 'critical');
  assert.equal(newItems(a).length, 1);
  assert.equal(a.resolved.length, 1);
  assert.equal(a.resolved[0].location, 'old.js:1');
});

test('loadBaseline rejects missing, malformed and wrong-version files', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mosca-baseline-'));
  const good = path.join(dir, 'good.json');
  fs.writeFileSync(good, JSON.stringify({ version: 1, findings: [] }), 'utf8');
  assert.equal(loadBaseline(good).version, 1);

  const badVersion = path.join(dir, 'bad-version.json');
  fs.writeFileSync(badVersion, JSON.stringify({ version: 99, findings: [] }), 'utf8');
  assert.throws(() => loadBaseline(badVersion), /Unsupported baseline version/);

  const malformed = path.join(dir, 'malformed.json');
  fs.writeFileSync(malformed, '{', 'utf8');
  assert.throws(() => loadBaseline(malformed), /Invalid JSON/);

  assert.throws(() => loadBaseline(path.join(dir, 'missing.json')), /not found/);

  fs.rmSync(dir, { recursive: true, force: true });
});
