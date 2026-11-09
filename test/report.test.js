/**
 * Report tests: the CBOM must be valid CycloneDX 1.6, the SARIF must be
 * consumable by GitHub code scanning, and the HTML must be genuinely
 * self-contained and injection-safe.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { analyse } from '../src/analysis/risk.js';
import { DEFAULT_CONFIG } from '../src/config.js';
import { buildCbom } from '../src/report/cbom.js';
import { buildSarif } from '../src/report/sarif.js';
import { buildHtmlReport } from '../src/report/html.js';

const config = { ...DEFAULT_CONFIG, crqcYear: 2033 };
const NOW = new Date('2026-01-01T00:00:00Z');

function findings() {
  return [
    {
      id: 'js-md5',
      kind: 'source',
      title: 'MD5 — hashing',
      algorithm: 'md5',
      primitive: 'hash',
      location: { file: 'src/a.js', line: 4, column: 11 },
      confidence: 'high',
      note: 'MD5 is broken.',
    },
    {
      id: 'py-md5',
      kind: 'source',
      title: 'MD5 — hashing',
      algorithm: 'md5',
      primitive: 'hash',
      location: { file: 'svc/b.py', line: 9, column: 3 },
      confidence: 'high',
    },
    {
      id: 'js-sha256',
      kind: 'source',
      title: 'SHA-256 — hashing',
      algorithm: 'sha256',
      primitive: 'hash',
      location: { file: 'src/a.js', line: 8, column: 3 },
      confidence: 'high',
    },
    {
      id: 'nginx-rc4',
      kind: 'config',
      title: 'RC4 — cipher policy',
      algorithm: 'rc4',
      primitive: 'symmetric',
      location: { file: 'infra/nginx.conf', line: 18, column: 1 },
      confidence: 'high',
    },
  ];
}

function analysis() {
  return analyse({ findings: findings(), config, now: NOW });
}

function endpoint(overrides = {}) {
  return {
    host: 'example.com',
    port: 443,
    reachable: true,
    protocol: 'TLS 1.3',
    cipher: 'TLS_AES_256_GCM_SHA384',
    group: 'X25519MLKEM768',
    hybrid: true,
    groupLabel: 'X25519+ML-KEM-768',
    certificate: {
      subject: 'CN=example.com',
      issuer: 'CN=Test CA',
      notBefore: new Date('2026-01-01T00:00:00Z'),
      notAfter: new Date('2027-01-01T00:00:00Z'),
      signature: { algorithm: 'ecdsa', name: 'ecdsa-with-SHA256' },
      publicKey: { algorithm: 'ecdsa', label: 'ECDSA P-256', bits: 256 },
      daysRemaining: 365,
    },
    ...overrides,
  };
}

test('CBOM is CycloneDX 1.6 with cryptographic assets', () => {
  const a = analysis();
  a.endpoints = [];
  const bom = buildCbom({ analysis: a, projectName: 'demo', version: '2.0.0', toolVersion: '1.0.0' });

  assert.equal(bom.bomFormat, 'CycloneDX');
  assert.equal(bom.specVersion, '1.6');
  assert.match(bom.serialNumber, /^urn:uuid:[0-9a-f-]{36}$/);
  assert.equal(bom.version, 1);
  assert.equal(bom.metadata.tools.components[0].name, 'mosca');
  assert.equal(bom.metadata.component.name, 'demo');
  assert.ok(Array.isArray(bom.components) && bom.components.length >= 3);

  for (const component of bom.components) {
    assert.equal(component.type, 'cryptographic-asset');
    assert.ok(component['bom-ref']);
    assert.ok(component.cryptoProperties);
  }
});

test('CBOM deduplicates an algorithm and counts occurrences', () => {
  const a = analysis();
  a.endpoints = [];
  const bom = buildCbom({ analysis: a });

  const md5 = bom.components.find((c) => c['bom-ref'] === 'crypto/algorithm/md5');
  assert.ok(md5, 'md5 component missing');
  assert.equal(md5.evidence.occurrences, 2);
  assert.equal(md5.cryptoProperties.assetType, 'algorithm');
  assert.equal(md5.cryptoProperties.algorithmProperties.primitive, 'hash');
  assert.equal(md5.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel, 0);

  const props = Object.fromEntries(md5.properties.map((p) => [p.name, p.value]));
  assert.equal(props['mosca:quantumStatus'], 'broken');
  assert.equal(props['mosca:replacement'], 'sha256');
  assert.ok(props['mosca:moscaInequality']);
});

test('CBOM records certificates and protocols observed on endpoints', () => {
  const a = analysis();
  a.endpoints = [endpoint()];
  const bom = buildCbom({ analysis: a });

  const cert = bom.components.find((c) => c.cryptoProperties.assetType === 'certificate');
  assert.ok(cert, 'certificate component missing');
  assert.equal(cert.cryptoProperties.certificateProperties.subjectName, 'CN=example.com');
  assert.equal(cert.cryptoProperties.certificateProperties.certificateFormat, 'X.509');

  const protocol = bom.components.find((c) => c.cryptoProperties.assetType === 'protocol');
  assert.ok(protocol, 'protocol component missing');
  assert.equal(protocol.cryptoProperties.protocolProperties.type, 'tls');
  assert.equal(protocol.cryptoProperties.protocolProperties.version, '1.3');

  const hndl = bom.metadata.properties.find((p) => p.name === 'mosca:harvestNowDecryptLaterExposure');
  assert.ok(hndl);
});

test('SARIF is 2.1.0 with one result per actionable code finding', () => {
  const a = analysis();
  const sarif = buildSarif({ analysis: a, root: 'C:/repo', toolVersion: '1.0.0' });

  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs.length, 1);
  const run = sarif.runs[0];
  assert.equal(run.tool.driver.name, 'MOSCA');
  assert.equal(run.tool.driver.version, '1.0.0');
  assert.ok(run.tool.driver.rules.length >= 3);
  assert.equal(run.results.length, 3, 'sha256 is positive and must be skipped');

  for (const result of run.results) {
    assert.ok(result.ruleId.startsWith('mosca/'));
    assert.ok(['error', 'warning', 'note'].includes(result.level));
    assert.equal(result.locations.length, 1);
    assert.ok(result.locations[0].physicalLocation.artifactLocation.uri.length > 0);
    assert.ok(result.partialFingerprints.moscaFingerprint);
  }

  const md5 = run.results.find((r) => r.ruleId === 'mosca/js-md5');
  assert.equal(md5.level, 'error');
  assert.equal(md5.properties.algorithm, 'md5');
  assert.equal(md5.properties.moscaInequality, '7 + 1.8 > 7');
  assert.equal(md5.locations[0].physicalLocation.region.startLine, 4);
});

test('HTML report is self-contained', () => {
  const html = buildHtmlReport({ analysis: analysis(), meta: { durationMs: 42 }, projectName: 'demo' });
  assert.match(html, /^<!doctype html>/);
  assert.ok(html.includes('Post-quantum exposure report'));
  assert.ok(html.includes('demo'));
  assert.ok(html.includes('X25519MLKEM768'));
  assert.ok(html.includes('id="mosca-data"'));
  assert.ok(!/<script[^>]+\bsrc=/i.test(html), 'must not load external scripts');
  assert.ok(!/<link[^>]+\bhref=["']https?:/i.test(html), 'must not load external styles');
  assert.ok(!/url\(\s*["']?https?:/i.test(html), 'must not load external resources from CSS');
});

test('HTML escapes user-controlled project names', () => {
  const html = buildHtmlReport({
    analysis: analysis(),
    meta: { durationMs: 1 },
    projectName: '<img src=x onerror=alert(1)>',
  });
  assert.ok(!html.includes('<img src=x onerror=alert(1)>'));
  assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'));
});

test('HTML renders endpoint cards and hides unreachable errors safely', () => {
  const a = analysis();
  const html = buildHtmlReport({
    analysis: a,
    meta: { durationMs: 1 },
    endpoints: [endpoint(), { host: 'down.example', port: 443, reachable: false, error: '<b>bad</b>' }],
  });
  assert.ok(html.includes('X25519+ML-KEM-768'));
  assert.ok(html.includes('unreachable'));
  assert.ok(!html.includes('<b>bad</b>'));
});
