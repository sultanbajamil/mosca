/**
 * v3 reporting surfaces: the compliance gate in SARIF, library components in
 * the CBOM, and the simulator/chain/compliance sections of the HTML report.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { analyse } from '../src/analysis/risk.js';
import { evaluateAllCompliance } from '../src/analysis/compliance.js';
import { buildCbom } from '../src/report/cbom.js';
import { buildSarif } from '../src/report/sarif.js';
import { buildHtmlReport } from '../src/report/html.js';
import { DEFAULT_CONFIG } from '../src/config.js';

const NOW = new Date('2026-01-01T00:00:00Z');
const config = { ...DEFAULT_CONFIG, crqcYear: 2033, scenario: 'moderate' };

function finding(overrides = {}) {
  return {
    id: 'js-md5',
    kind: 'source',
    title: 'MD5 — hashing',
    algorithm: 'md5',
    primitive: 'hash',
    location: { file: 'src/app.js', line: 4, column: 1 },
    confidence: 'high',
    matched: "createHash('md5')",
    snippet: "crypto.createHash('md5')",
    ...overrides,
  };
}

function baseAnalysis() {
  const analysis = analyse({ findings: [finding()], config, now: NOW });
  analysis.compliance = evaluateAllCompliance(analysis);
  analysis.endpoints = [];
  analysis.sshEndpoints = [];
  analysis.dependencies = {
    packages: [
      { name: 'node-forge', version: '1.3.0', ecosystem: 'npm', status: 'quantum-vulnerable', algorithm: 'rsa', file: 'package-lock.json' },
      { name: '@noble/post-quantum', version: '0.2.0', ecosystem: 'npm', status: 'quantum-safe', algorithm: 'ml-kem-768', file: 'package-lock.json' },
    ],
  };
  analysis.artifacts = { findings: [] };
  return analysis;
}

test('CBOM adds library components and a dependency graph', () => {
  const bom = buildCbom({ analysis: baseAnalysis() });
  const libraries = bom.components.filter((c) => c.type === 'library');
  assert.equal(libraries.length, 2);
  const forge = libraries.find((c) => c.name === 'node-forge');
  assert.ok(forge);
  assert.equal(forge.version, '1.3.0');
  const props = Object.fromEntries(forge.properties.map((p) => [p.name, p.value]));
  assert.equal(props['mosca:cryptoPackageStatus'], 'quantum-vulnerable');

  assert.deepEqual(bom.dependencies[0].dependsOn.sort(), [
    'pkg/npm/@noble/post-quantum@0.2.0',
    'pkg/npm/node-forge@1.3.0',
  ]);
  assert.equal(bom.metadata.component['bom-ref'], 'application');
});

test('SARIF carries compliance results and per-finding controls', () => {
  const analysis = baseAnalysis();
  const sarif = buildSarif({ analysis, root: 'C:/repo', toolVersion: '3.0.0' });
  const run = sarif.runs[0];

  assert.deepEqual(
    run.properties.compliance.map((c) => c.standard),
    ['cnsa2', 'nist-2030', 'pci-dss', 'hipaa'],
  );
  assert.ok(run.properties.compliance.every((c) => c.status === 'fail'));

  const md5 = run.results.find((r) => r.ruleId === 'mosca/js-md5');
  assert.ok(md5.properties.compliance.some((c) => c.control === 'cnsa2-hash'));
  assert.ok(md5.properties.compliance.some((c) => c.standard === 'hipaa'));
});

test('HTML renders compliance, simulator, chains and supply chain', () => {
  const analysis = baseAnalysis();
  analysis.endpoints = [
    {
      host: 'example.com',
      port: 443,
      reachable: true,
      protocol: 'TLS 1.3',
      group: 'x25519',
      hybrid: false,
      cipher: 'TLS_AES_128_GCM_SHA256',
      certificate: {
        subject: 'CN=example.com',
        issuer: 'CN=Example CA',
        notBefore: new Date('2025-01-01T00:00:00Z'),
        notAfter: new Date('2026-01-01T00:00:00Z'),
        daysRemaining: 0,
        signature: { name: 'sha256WithRSAEncryption', algorithm: 'rsa' },
        publicKey: { label: 'RSA', bits: 2048, algorithm: 'rsa' },
      },
      chainAnalysis: {
        length: 2,
        entries: [
          { role: 'leaf', subject: 'example.com', keyLabel: 'RSA', keyBits: 2048, signatureAlgorithm: 'SHA-256', daysRemaining: 30, quantum: 'broken' },
          { role: 'intermediate', subject: 'Example CA', keyLabel: 'RSA', keyBits: 4096, signatureAlgorithm: 'SHA-256', daysRemaining: 900, quantum: 'broken' },
        ],
      },
      pqcHandshake: { worst: { label: 'ML-DSA-65', totalBytes: 16000, exceeds: true } },
      findings: [],
    },
  ];
  const html = buildHtmlReport({ analysis, meta: { durationMs: 10 }, projectName: 'demo', toolVersion: '3.0.0' });

  assert.match(html, /id="compliance"/);
  assert.match(html, /id="simulator"/);
  assert.match(html, /id="chains"/);
  assert.match(html, /id="supply-chain"/);
  assert.match(html, /CNSA 2\.0/);
  assert.match(html, /Example CA/);
  assert.match(html, /exceeds the 14 KB initial window/);
  assert.match(html, /node-forge/);
  assert.match(html, /id="sim-crqc"/);
  assert.match(html, /id="sim-lead"/);
  assert.match(html, /crypto-agility simulator/i);
  // Still self-contained.
  assert.ok(!/<script[^>]+\bsrc=/i.test(html));
});
