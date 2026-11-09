/**
 * v2 behaviour that spans modules: sensitivity analysis, SSH-aware HNDL,
 * stable SARIF fingerprints and SSH assets in the CBOM.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { analyse, computeSensitivity } from '../src/analysis/risk.js';
import { DEFAULT_CONFIG } from '../src/config.js';
import { lookup } from '../src/rules/algorithms.js';
import { buildSarif } from '../src/report/sarif.js';
import { buildCbom } from '../src/report/cbom.js';
import { parseArgs } from '../src/cli.js';

test('sensitivity shows how the exposed set shrinks as the CRQC recedes', () => {
  const items = [
    { positive: false, severity: 'high', shelfLife: 10, leadTime: 2 },
    { positive: false, severity: 'medium', shelfLife: 3, leadTime: 1 },
    { positive: true, severity: 'info', shelfLife: 30, leadTime: 4 },
  ];
  const rows = computeSensitivity(items, 2026);
  assert.deepEqual(rows.map((r) => r.year), [2029, 2033, 2038, 2045]);
  assert.equal(rows[0].exposedItems, 2);
  assert.equal(rows[1].exposedItems, 1);
  assert.equal(rows[2].exposedItems, 0);
  assert.equal(rows[3].exposedItems, 0);
  assert.equal(rows[2].totalActionable, 2);
});

test('SSH key exchange contributes to the HNDL exposure ratio', () => {
  const config = { ...DEFAULT_CONFIG, weights: { ...DEFAULT_CONFIG.weights } };
  const findings = [
    {
      id: 'endpoint-classical-kex',
      kind: 'endpoint',
      algorithm: 'x25519',
      primitive: 'key-agreement',
      location: { host: 'tls.example', port: 443 },
      title: 'classical TLS',
      confidence: 'high',
    },
    {
      id: 'ssh-hybrid-kex',
      kind: 'endpoint',
      algorithm: 'mlkem768x25519-sha256',
      primitive: 'key-agreement',
      location: { host: 'ssh.example', port: 22 },
      title: 'hybrid SSH',
      confidence: 'high',
      positive: true,
    },
  ];
  const result = analyse({
    findings,
    endpoints: [{ host: 'tls.example', port: 443, hybrid: false }],
    sshEndpoints: [{ host: 'ssh.example', port: 22, hybrid: true }],
    config,
    now: new Date('2026-01-01T00:00:00Z'),
  });
  assert.equal(result.summary.endpointsInspected, 2);
  assert.equal(result.summary.tlsEndpoints, 1);
  assert.equal(result.summary.sshEndpoints, 1);
  assert.equal(result.summary.endpointsWithPqc, 1);
  assert.equal(result.summary.hndlExposure, 50);
});

test('SSH wire names resolve through the shared registry', () => {
  assert.equal(lookup('sntrup761x25519-sha512@openssh.com').id, 'sntrup761x25519-sha512');
  assert.equal(lookup('curve25519-sha256').id, 'x25519');
  assert.equal(lookup('hmac-sha2-256-etm@openssh.com').id, 'hmac-sha256');
  assert.equal(lookup('aes256-gcm@openssh.com').id, 'aes-256-gcm');
});

test('SARIF carries a stable fingerprint and baseline state', () => {
  const item = {
    id: 'js-hash-md5',
    kind: 'source',
    algorithm: 'md5',
    primitive: 'hash',
    severity: 'critical',
    positive: false,
    title: 'MD5',
    location: { file: 'src/app.js', line: 10, column: 1 },
    snippet: "crypto.createHash('md5')",
    fingerprint: '0123456789abcdef0123456789abcdef',
    baselineStatus: 'new',
    mosca: { exposed: true, inequality: '7 + 1 > 7' },
    priority: 'P0',
  };
  const analysis = {
    items: [item],
    summary: { generatedAt: '2026-01-01T00:00:00.000Z', quantumReadinessIndex: 10, crqcYear: 2033 },
  };
  const sarif = buildSarif({ analysis, root: process.cwd() });
  const result = sarif.runs[0].results[0];
  assert.equal(result.partialFingerprints.moscaFingerprint, item.fingerprint);
  assert.equal(result.baselineState, 'new');
  assert.equal(result.properties.baselineStatus, 'new');
});

test('the CBOM includes SSH servers as protocol assets', () => {
  const analysis = {
    items: [],
    sshEndpoints: [
      {
        host: 'bastion.example.com',
        port: 22,
        reachable: true,
        software: 'OpenSSH_9.9p1',
        banner: 'SSH-2.0-OpenSSH_9.9p1',
        hybrid: true,
        kexAlgorithms: ['mlkem768x25519-sha256'],
        serverHostKeyAlgorithms: ['ssh-ed25519'],
        encryption: ['aes256-gcm@openssh.com'],
        macs: ['hmac-sha2-256'],
      },
    ],
    summary: { generatedAt: '2026-01-01T00:00:00.000Z', quantumReadinessIndex: 50, crqcYear: 2033, hndlApplicable: true, hndlExposure: 0 },
  };
  const cbom = buildCbom({ analysis });
  const ssh = cbom.components.find((c) => c.cryptoProperties?.protocolProperties?.type === 'ssh');
  assert.ok(ssh, 'SSH protocol component missing');
  assert.equal(ssh.properties.find((p) => p.name === 'mosca:hybridKeyExchange').value, 'true');
});

test('CLI grammar accepts baseline and SSH options', () => {
  const args = parseArgs([
    'scan',
    '.',
    '--ssh',
    'git.example.com:2222',
    '--baseline',
    '.mosca-baseline.json',
    '--write-baseline',
    'next.json',
    '--fail-on',
    'high',
  ]);
  assert.equal(args.ssh, 'git.example.com:2222');
  assert.equal(args.baseline, '.mosca-baseline.json');
  assert.equal(args['write-baseline'], 'next.json');
  assert.equal(args['fail-on'], 'high');
});
