/**
 * Compliance gates answer a different question from the QRI: which named
 * control fails, on which finding, and what does the auditor need to see
 * fixed. These tests pin the mapping for each standard.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { analyse } from '../src/analysis/risk.js';
import {
  COMPLIANCE_IDS,
  COMPLIANCE_STANDARDS,
  evaluateCompliance,
  evaluateAllCompliance,
  resolveStandard,
  complianceVerdict,
} from '../src/analysis/compliance.js';
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

const control = (result, id) => result.controls.find((c) => c.id === id);
const analyseFindings = (findings) => analyse({ findings, config, now: NOW });

test('the four standards are registered with unique controls', () => {
  assert.deepEqual(COMPLIANCE_IDS, ['cnsa2', 'nist-2030', 'pci-dss', 'hipaa']);
  for (const id of COMPLIANCE_IDS) {
    const standard = COMPLIANCE_STANDARDS[id];
    assert.equal(standard.id, id);
    assert.ok(standard.controls.length >= 4);
    const seen = new Set();
    for (const c of standard.controls) {
      assert.ok(!seen.has(c.id), `duplicate control ${c.id}`);
      seen.add(c.id);
      assert.ok(c.remediation, `${c.id} has no remediation`);
    }
  }
});

test('a vulnerable estate fails every standard on named controls', () => {
  const analysis = analyseFindings([
    finding({ algorithm: 'md5', primitive: 'hash' }),
    finding({ algorithm: 'rc4', primitive: 'symmetric', id: 'nginx-rc4' }),
    finding({ algorithm: 'rsa-1024', primitive: 'signature', id: 'js-rsa-modulus' }),
    finding({ algorithm: 'tls-1.0', primitive: 'protocol', id: 'nginx-ssl-protocols-legacy' }),
  ]);

  const cnsa = evaluateCompliance(analysis, 'cnsa2');
  assert.equal(cnsa.status, 'fail');
  assert.equal(control(cnsa, 'cnsa2-hash').status, 'fail');
  assert.equal(control(cnsa, 'cnsa2-symmetric').status, 'fail');
  assert.equal(control(cnsa, 'cnsa2-signatures').status, 'fail');
  assert.ok(cnsa.violationCount >= 3);

  const nist = evaluateCompliance(analysis, 'nist-2030');
  assert.equal(control(nist, 'nist-hash-256').status, 'fail');
  assert.equal(control(nist, 'nist-asymmetric-2030').status, 'fail');
  assert.equal(control(nist, 'nist-symmetric-128').status, 'fail');
  assert.equal(control(nist, 'nist-pqc-agility').status, 'fail');

  const pci = evaluateCompliance(analysis, 'pci-dss');
  assert.equal(control(pci, 'pci-tls-version').status, 'fail');
  assert.equal(control(pci, 'pci-weak-ciphers').status, 'fail');
  assert.equal(control(pci, 'pci-key-length').status, 'fail');
  assert.equal(control(pci, 'pci-hash').status, 'fail');

  const hipaa = evaluateCompliance(analysis, 'hipaa');
  assert.equal(control(hipaa, 'hipaa-transit').status, 'fail');
  assert.equal(control(hipaa, 'hipaa-at-rest').status, 'fail');
  assert.equal(control(hipaa, 'hipaa-integrity').status, 'fail');
});

test('a clean post-quantum estate passes all four gates', () => {
  const analysis = analyseFindings([
    finding({
      id: 'dependency-pqc-ready',
      kind: 'dependency',
      algorithm: 'ml-kem-768',
      primitive: 'key-agreement',
      location: { file: 'package-lock.json', line: 12, column: 1 },
      positive: true,
    }),
    finding({
      id: 'safe-hash',
      algorithm: 'sha384',
      primitive: 'hash',
      location: { file: 'src/app.js', line: 4, column: 1 },
    }),
  ]);

  for (const id of COMPLIANCE_IDS) {
    const result = evaluateCompliance(analysis, id);
    assert.equal(result.status, 'pass', `${id}: ${JSON.stringify(result.controls.filter((c) => c.status !== 'pass'))}`);
    assert.equal(result.score, 100);
    assert.equal(result.violationCount, 0);
    assert.equal(complianceVerdict(result), 'PASS');
  }
});

test('endpoint key exchange drives CNSA 2.0 and HNDL controls', () => {
  const analysis = analyseFindings([
    finding({
      id: 'starttls-classical-kex',
      kind: 'endpoint',
      algorithm: 'x25519',
      primitive: 'key-agreement',
      location: { host: 'mail.example.com', port: 587, target: 'smtp://mail.example.com' },
    }),
  ]);

  const cnsa = evaluateCompliance(analysis, 'cnsa2');
  assert.equal(control(cnsa, 'cnsa2-key-establishment').status, 'fail');

  const pci = evaluateCompliance(analysis, 'pci-dss');
  assert.equal(control(pci, 'pci-hndl').status, 'fail');

  const hipaa = evaluateCompliance(analysis, 'hipaa');
  assert.equal(control(hipaa, 'hipaa-hndl').status, 'fail');
  assert.equal(control(hipaa, 'hipaa-transit').status, 'pass');
});

test('the NIST agility control needs evidence of a PQC capability', () => {
  const debt = analyseFindings([finding({ algorithm: 'rsa-2048', primitive: 'signature' })]);
  assert.equal(control(evaluateCompliance(debt, 'nist-2030'), 'nist-pqc-agility').status, 'fail');

  const agile = analyseFindings([
    finding({ algorithm: 'rsa-2048', primitive: 'signature' }),
    finding({ id: 'dependency-pqc-ready', kind: 'dependency', algorithm: 'ml-kem-768', primitive: 'key-agreement', positive: true }),
  ]);
  assert.equal(control(evaluateCompliance(agile, 'nist-2030'), 'nist-pqc-agility').status, 'pass');
});

test('violations carry the finding identity and location for the report', () => {
  const analysis = analyseFindings([finding({ algorithm: 'md5', primitive: 'hash' })]);
  const result = evaluateCompliance(analysis, 'pci-dss');
  const hash = control(result, 'pci-hash');
  assert.equal(hash.violations.length, 1);
  assert.equal(hash.violations[0].algorithm, 'md5');
  assert.equal(hash.violations[0].location.file, 'src/app.js');
  assert.ok(hash.violations[0].fingerprint);
  assert.match(complianceVerdict(result), /FAIL/);
});

test('selection resolves all, one, or rejects an unknown standard', () => {
  const analysis = analyseFindings([finding({ algorithm: 'md5', primitive: 'hash' })]);
  assert.equal(resolveStandard('all'), 'all');
  assert.equal(resolveStandard('PCI-DSS'), 'pci-dss');
  assert.equal(resolveStandard('unknown'), null);
  assert.equal(evaluateAllCompliance(analysis).length, 4);
  assert.equal(evaluateAllCompliance(analysis, 'all').length, 4);
  assert.deepEqual(evaluateAllCompliance(analysis, 'hipaa').map((r) => r.id), ['hipaa']);
  assert.throws(() => evaluateAllCompliance(analysis, 'fedramp'), /unknown compliance standard/);
  assert.throws(() => evaluateCompliance(analysis, 'fedramp'), /unknown compliance standard/);
});
