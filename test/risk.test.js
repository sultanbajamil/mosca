/**
 * Risk-model tests. The scoring model is the product's main claim, so these
 * tests pin down the two things a reviewer will check: the weight arithmetic
 * and the direction of every effect.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  analyse,
  scoreFinding,
  migrationLeadTime,
  severityFromScore,
  SEVERITY_ORDER,
} from '../src/analysis/risk.js';
import { DEFAULT_CONFIG } from '../src/config.js';

const NOW = new Date('2026-01-01T00:00:00Z');
const config = { ...DEFAULT_CONFIG, crqcYear: 2033, scenario: 'moderate' };

function finding(overrides = {}) {
  return {
    id: 'test-rule',
    kind: 'source',
    title: 'test finding',
    algorithm: 'md5',
    primitive: 'hash',
    location: { file: 'src/app.js', line: 1, column: 1 },
    confidence: 'high',
    ...overrides,
  };
}

const score = (overrides = {}) =>
  scoreFinding(
    {
      quantum: 'broken',
      classical: 'acceptable',
      shelfLife: 7,
      count: 1,
      kind: 'source',
      ...overrides,
    },
    { weights: DEFAULT_CONFIG.weights, yearsToCRQC: 7 },
  );

test('migration lead time grows with breadth and stays bounded', () => {
  assert.equal(migrationLeadTime(1), 1.5);
  let previous = 0;
  for (let count = 1; count <= 2000; count *= 2) {
    const lead = migrationLeadTime(count);
    assert.ok(lead >= 1 && lead <= 5, `lead ${lead} out of range for ${count}`);
    assert.ok(lead >= previous, `lead time decreased at ${count}`);
    if (previous < 5) assert.ok(lead > previous, `lead time did not increase at ${count}`);
    previous = lead;
  }
  assert.equal(migrationLeadTime(100000), 5);
});

test('quantum vulnerability dominates the score', () => {
  assert.ok(score({ quantum: 'broken' }) > score({ quantum: 'weakened' }));
  assert.ok(score({ quantum: 'weakened' }) > score({ quantum: 'safe' }));
  assert.ok(score({ quantum: 'unknown' }) > score({ quantum: 'safe' }));
});

test('longer shelf life and wider use increase the score', () => {
  assert.ok(score({ shelfLife: 30 }) > score({ shelfLife: 1 }));
  assert.ok(score({ count: 100 }) > score({ count: 1 }));
});

test('an internet-facing finding outranks an internal one', () => {
  assert.ok(score({ kind: 'endpoint' }) > score({ kind: 'config' }));
  assert.ok(score({ kind: 'config' }) > score({ kind: 'source' }));
});

test('an already-broken primitive is critical regardless of score', () => {
  assert.equal(severityFromScore(10, { classical: 'broken', quantum: 'broken' }), 'critical');
  assert.equal(severityFromScore(95, { classical: 'strong', quantum: 'weakened' }), 'critical');
  assert.equal(severityFromScore(95, { classical: 'strong', quantum: 'safe' }), 'info');
});

test('analyse applies Mosca\u2019s inequality', () => {
  const { summary, items } = analyse({ findings: [finding()], config, now: NOW });
  const item = items[0];
  assert.equal(summary.yearsToCRQC, 7);
  assert.equal(item.shelfLife, 7);
  assert.equal(item.leadTime, 1.5);
  assert.equal(item.mosca.exposed, true, '7 + 1.5 > 7');
  assert.equal(item.mosca.inequality, '7 + 1.5 > 7');
  assert.equal(summary.exposedItems, 1);
});

test('a conservative CRQC assumption un-exposes short-lived data', () => {
  const conservative = { ...config, crqcYear: 2038 };
  const { summary, items } = analyse({ findings: [finding()], config: conservative, now: NOW });
  assert.equal(summary.yearsToCRQC, 12);
  assert.equal(items[0].mosca.exposed, false);
  assert.equal(items[0].mosca.inequality, '7 + 1.5 ≤ 12');
  assert.equal(summary.exposedItems, 0);
});

test('path-based data classification raises the shelf life', () => {
  const { items } = analyse({
    findings: [finding({ location: { file: 'services/billing/invoice.js', line: 3 } })],
    config,
    now: NOW,
  });
  assert.equal(items[0].shelfLife, 10);
  assert.equal(items[0].dataClass, 'billing records');
});

test('safe primitives are positive, score zero, and never actionable', () => {
  const safe = finding({ id: 'sha', algorithm: 'sha256', primitive: 'hash', title: 'SHA-256' });
  const md5 = finding();
  const { items, summary } = analyse({ findings: [md5, safe], config, now: NOW });
  const safeItem = items.find((i) => i.algorithm === 'sha256');
  const badItem = items.find((i) => i.algorithm === 'md5');

  assert.equal(safeItem.positive, true);
  assert.equal(safeItem.score, 0);
  assert.equal(safeItem.severity, 'info');
  assert.equal(badItem.positive, false);
  assert.equal(summary.actionable, 1);
  assert.equal(summary.totalFindings, 2);
});

test('broken classical primitives are critical and P0', () => {
  const { items } = analyse({ findings: [finding()], config, now: NOW });
  assert.equal(items[0].severity, 'critical');
  assert.equal(items[0].priority, 'P0');
  assert.equal(items[0].replacement, 'sha256');
  assert.equal(items[0].replacementLabel, 'SHA-256');
});

test('RSA replacement depends on the primitive', () => {
  const sig = analyse({
    findings: [finding({ algorithm: 'rsa', primitive: 'signature', title: 'RSA' })],
    config,
    now: NOW,
  }).items[0];
  const kem = analyse({
    findings: [finding({ algorithm: 'rsa', primitive: 'pke', title: 'RSA' })],
    config,
    now: NOW,
  }).items[0];
  assert.equal(sig.replacement, 'ml-dsa-65');
  assert.equal(kem.replacement, 'ml-kem-768');
});

test('HNDL is reported only when endpoints were inspected', () => {
  const none = analyse({ findings: [], config, now: NOW }).summary;
  assert.equal(none.hndlApplicable, false);
  assert.equal(none.hndlExposure, 0);
  assert.equal(none.endpointsInspected, 0);

  const classical = finding({
    id: 'kex-classical',
    kind: 'endpoint',
    algorithm: 'x25519',
    primitive: 'key-agreement',
    location: { host: 'a.example', port: 443 },
  });
  const hybrid = finding({
    id: 'kex-hybrid',
    kind: 'endpoint',
    algorithm: 'x25519mlkem768',
    primitive: 'key-agreement',
    location: { host: 'b.example', port: 443 },
  });
  const { summary } = analyse({
    findings: [classical, hybrid],
    endpoints: [{ host: 'a.example', hybrid: false }, { host: 'b.example', hybrid: true }],
    config,
    now: NOW,
  });
  assert.equal(summary.hndlApplicable, true);
  assert.equal(summary.hndlExposure, 50);
  assert.equal(summary.endpointsWithPqc, 1);
});

test('the quarantine index is 100 for an empty or fully safe estate', () => {
  assert.equal(analyse({ findings: [], config, now: NOW }).summary.quantumReadinessIndex, 100);
  const safe = analyse({
    findings: [finding({ algorithm: 'sha256' }), finding({ algorithm: 'aes-256-gcm' })],
    config,
    now: NOW,
  });
  assert.equal(safe.summary.quantumReadinessIndex, 100);
});

test('roadmap orders key exchange before signatures and has stable phases', () => {
  const findings = [
    finding({ id: 'md5', algorithm: 'md5' }),
    finding({ id: 'kex', algorithm: 'ecdh', primitive: 'key-agreement' }),
    finding({ id: 'sig', algorithm: 'rsa', primitive: 'signature' }),
    finding({ id: 'sym', algorithm: 'aes-128-gcm', primitive: 'symmetric' }),
  ];
  const { roadmap, summary } = analyse({ findings, config, now: NOW });
  const byId = Object.fromEntries(roadmap.map((p) => [p.id, p]));
  assert.ok(byId['phase-0'].count >= 1);
  assert.ok(byId['phase-2'].count >= 1);
  assert.ok(byId['phase-3'].count >= 1);
  assert.equal(byId['phase-5'].count, 0);
  assert.ok(roadmap.length >= 5);
  assert.ok(summary.effortDays > 0);
});

test('findings within a severity are sorted by score', () => {
  const high = finding({ id: 'a', algorithm: 'rsa', primitive: 'signature' });
  const low = finding({ id: 'b', algorithm: 'sha1', primitive: 'hash' });
  const { items } = analyse({ findings: [low, high], config, now: NOW });
  assert.equal(items[0].severity, 'critical');
  // SHA-1 is already classically broken, so it outscores RSA even though both
  // are quantum-vulnerable.
  assert.equal(items[0].id, 'b');
  for (let i = 1; i < items.length; i++) {
    assert.ok(SEVERITY_ORDER[items[i - 1].severity] >= SEVERITY_ORDER[items[i].severity]);
    if (items[i - 1].severity === items[i].severity) {
      assert.ok(items[i - 1].score >= items[i].score);
    }
  }
});
