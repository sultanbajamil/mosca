/**
 * `mosca fix` is a suggestion engine, not a codemod. These tests pin the
 * boundary: hashes, MACs and AES size upgrades produce reviewable hunks;
 * everything involving protocol, keys or certificates produces an advisory.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { analyse } from '../src/analysis/risk.js';
import { buildFixPlan, buildAutoReplace, buildPatch, renderFixReport } from '../src/fix.js';
import { DEFAULT_CONFIG } from '../src/config.js';

const NOW = new Date('2026-01-01T00:00:00Z');
const config = { ...DEFAULT_CONFIG, crqcYear: 2033, scenario: 'moderate' };

function finding(overrides = {}) {
  return {
    id: 'js-createHash',
    kind: 'source',
    title: 'MD5 — hashing',
    algorithm: 'md5',
    primitive: 'hash',
    location: { file: 'src/app.js', line: 1, column: 1 },
    confidence: 'high',
    matched: "createHash('md5')",
    snippet: "const digest = crypto.createHash('md5').update(data).digest('hex');",
    ...overrides,
  };
}

const planFor = (findings) => buildFixPlan(analyse({ findings, config, now: NOW }));

test('broken hashes and MACs become automatic literal swaps', () => {
  const plan = planFor([
    finding(),
    finding({
      id: 'js-createHmac',
      algorithm: 'hmac-sha1',
      primitive: 'mac',
      matched: "createHmac('sha1', key)",
      snippet: "crypto.createHmac('sha1', key).update(data).digest('hex');",
    }),
    finding({
      id: 'js-createCipheriv',
      algorithm: 'aes-128-cbc',
      primitive: 'symmetric',
      matched: "createCipheriv('aes-128-cbc'",
      snippet: "crypto.createCipheriv('aes-128-cbc', key, iv);",
    }),
  ]);

  assert.equal(plan.summary.automatic, 3);
  const byAlgo = Object.fromEntries(plan.automatic.map((e) => [e.algorithm, e]));
  assert.equal(byAlgo.md5.replacement, 'sha256');
  assert.equal(byAlgo['hmac-sha1'].replacement, 'sha256');
  // The AES mode is preserved; CBC does not silently become GCM.
  assert.equal(byAlgo['aes-128-cbc'].replacement, 'aes-256-cbc');
  assert.equal(byAlgo['aes-128-cbc'].target, 'aes-256-cbc');
  assert.match(byAlgo.md5.note, /stored digest/);
});

test('Java and C# formatting follows the language convention', () => {
  const java = buildAutoReplace({
    algorithm: 'sha1',
    primitive: 'hash',
    language: 'java',
    matched: 'MessageDigest.getInstance("SHA-1")',
  });
  assert.equal(java.replacement, 'SHA-256');

  const csharp = buildAutoReplace({
    algorithm: 'md5',
    primitive: 'hash',
    language: 'csharp',
    matched: 'HashAlgorithm.Create("MD5")',
  });
  assert.equal(csharp.replacement, 'SHA256');

  const node = buildAutoReplace({
    algorithm: 'sha1',
    primitive: 'hash',
    language: 'javascript',
    matched: "createHash('sha1')",
  });
  assert.equal(node.replacement, 'sha256');
});

test('family changes and asymmetric findings stay advisory', () => {
  const plan = planFor([
    finding({ id: 'nginx-rc4', algorithm: 'rc4', primitive: 'symmetric', matched: "createCipheriv('rc4'", location: { file: 'src/legacy.js', line: 3, column: 1 } }),
    finding({ id: 'js-rsa', algorithm: 'rsa-2048', primitive: 'signature', matched: "generateKeyPair('rsa'", location: { file: 'src/keys.js', line: 8, column: 1 } }),
    finding({
      id: 'starttls-kex',
      kind: 'endpoint',
      algorithm: 'x25519',
      primitive: 'key-agreement',
      location: { host: 'mail.example.com', port: 587, target: 'smtp://mail.example.com' },
      matched: null,
      snippet: null,
    }),
  ]);

  assert.equal(plan.summary.automatic, 0);
  assert.equal(plan.summary.manual, 3);
  const rc4 = plan.manual.find((m) => m.algorithm === 'rc4');
  assert.match(rc4.advisory, /IV, authentication tag/);
  const rsa = plan.manual.find((m) => m.algorithm === 'rsa-2048' || m.algorithm === 'rsa');
  assert.match(rsa.advisory, /ML-DSA/);
  const kex = plan.manual.find((m) => m.primitive === 'key-agreement');
  assert.match(kex.advisory, /X25519MLKEM768/);
  assert.equal(kex.location.host, 'mail.example.com');
});

test('the same algorithm is only advised once, with an occurrence count', () => {
  const plan = planFor([
    finding({ id: 'rsa-1', algorithm: 'rsa-2048', primitive: 'signature', location: { file: 'a.js', line: 1 } }),
    finding({ id: 'rsa-2', algorithm: 'rsa-2048', primitive: 'signature', location: { file: 'b.js', line: 2 } }),
  ]);
  assert.equal(plan.manual.length, 1);
  assert.equal(plan.manual[0].occurrences, 2);
});

test('buildPatch emits a unified diff and never touches the file', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mosca-fix-'));
  const file = path.join(root, 'src', 'app.js');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const original = ["import crypto from 'node:crypto';", '', "const HASH = 'md5';", 'const digest = crypto.createHash(HASH).update(data).digest();', ''].join('\n');
  fs.writeFileSync(file, original);

  const plan = planFor([
    finding({
      location: { file: 'src/app.js', line: 4, column: 1 },
      matched: "createHash(HASH)",
      snippet: 'const digest = crypto.createHash(HASH).update(data).digest();',
      // A constant hides the algorithm from the literal swap; prove the
      // builder refuses to invent a change.
    }),
  ]);
  // Nothing to swap: HASH is not a literal.
  assert.equal(plan.summary.automatic, 0);

  const direct = planFor([
    finding({
      location: { file: 'src/app.js', line: 4, column: 1 },
      matched: "'md5'",
      snippet: 'const digest = crypto.createHash(HASH).update(data).digest();',
    }),
  ]);
  // The matched literal is not on the reported line, so the hunk is skipped.
  const missed = buildPatch(direct, { root });
  assert.equal(missed.applied.length, 0);
  assert.equal(missed.skipped[0].reason, 'literal "md5" not found');

  fs.writeFileSync(
    file,
    ["import crypto from 'node:crypto';", '', "const digest = crypto.createHash('md5').update(data).digest();", ''].join('\n'),
  );
  const real = planFor([
    finding({
      location: { file: 'src/app.js', line: 3, column: 1 },
      matched: "'md5'",
      snippet: "const digest = crypto.createHash('md5').update(data).digest();",
    }),
  ]);
  const result = buildPatch(real, { root });
  assert.equal(result.applied.length, 1);
  assert.equal(result.applied[0].edits, 1);
  assert.match(result.patch, /^--- a\/src\/app\.js/m);
  assert.match(result.patch, /^\+\+\+ b\/src\/app\.js/m);
  assert.match(result.patch, /^@@ -\d+,\d+ \+\d+,\d+ @@/m);
  assert.match(result.patch, /-const digest = crypto\.createHash\('md5'\)/);
  assert.match(result.patch, /\+const digest = crypto\.createHash\('sha256'\)/);
  // The file on disk is unchanged.
  assert.equal(fs.readFileSync(file, 'utf8'), ["import crypto from 'node:crypto';", '', "const digest = crypto.createHash('md5').update(data).digest();", ''].join('\n'));
});

test('multiple edits in one file share a hunk list and preserve CRLF', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mosca-fix-'));
  const file = path.join(root, 'svc.py');
  fs.writeFileSync(file, ["import hashlib", "a = hashlib.new('md5')", "b = hashlib.new('sha1')", ''].join('\r\n'));

  const plan = planFor([
    finding({
      language: 'python',
      algorithm: 'md5',
      primitive: 'hash',
      matched: "'md5'",
      location: { file: 'svc.py', line: 2, column: 1 },
      snippet: "a = hashlib.new('md5')",
    }),
    finding({
      language: 'python',
      algorithm: 'sha1',
      primitive: 'hash',
      matched: "'sha1'",
      location: { file: 'svc.py', line: 3, column: 1 },
      snippet: "b = hashlib.new('sha1')",
    }),
  ]);
  const result = buildPatch(plan, { root });
  assert.equal(result.applied[0].edits, 2);
  assert.match(result.patch, /\r\n/);
  assert.match(result.patch, /\+b = hashlib\.new\('sha256'\)/);
});

test('protocol implementations and test vectors are never patched in place', () => {
  const protocol = buildAutoReplace({
    algorithm: 'aes-128-gcm',
    primitive: 'symmetric',
    matched: "createCipheriv('aes-128-gcm'",
    location: { file: 'src/net/quic.js', line: 12 },
  });
  assert.equal(protocol, null);

  const testVector = buildAutoReplace({
    algorithm: 'aes-128-gcm',
    primitive: 'symmetric',
    matched: "createCipheriv('aes-128-gcm'",
    location: { file: 'test/quic.test.js', line: 12 },
  });
  assert.equal(testVector, null);

  const application = buildAutoReplace({
    algorithm: 'aes-128-gcm',
    primitive: 'symmetric',
    matched: "createCipheriv('aes-128-gcm'",
    location: { file: 'src/storage/encrypt.js', line: 12 },
  });
  assert.equal(application.replacement, 'aes-256-gcm');
});

test('the rendered report separates automatic edits from advisories', () => {
  const plan = planFor([
    finding(),
    finding({ id: 'js-rsa', algorithm: 'rsa-2048', primitive: 'signature', matched: "generateKeyPair('rsa'", location: { file: 'src/keys.js', line: 8 } }),
  ]);
  const report = renderFixReport(plan);
  assert.match(report, /^MOSCA fix plan/m);
  assert.match(report, /AUTOMATIC/);
  assert.match(report, /MANUAL/);
  assert.match(report, /md5 -> sha256/);
  assert.match(report, /Nothing is applied automatically/);
  assert.match(report, /ML-DSA/);
  assert.equal(plan.summary.algorithms, 2);
});
