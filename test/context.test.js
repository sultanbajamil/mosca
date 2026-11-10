/**
 * Contextual static analysis: file-local constant propagation and the
 * distinction between raw occurrences and unique migration sites.
 *
 * Real code hides algorithms behind constants. These tests prove the scanner
 * follows a single-assignment constant into a cryptographic call, refuses to
 * guess when the constant is reassigned, and counts a repeated wrapper once
 * when estimating migration effort.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { scanSourceContent } from '../src/scan/source.js';
import { collectConstants, resolveConstantAlgorithm } from '../src/scan/constants.js';
import { analyse, migrationSiteKey, baseEffortDays } from '../src/analysis/risk.js';
import { DEFAULT_CONFIG } from '../src/config.js';

const NOW = new Date('2026-01-01T00:00:00Z');
const config = { ...DEFAULT_CONFIG, crqcYear: 2033, scenario: 'moderate' };

const scan = (content, language = 'javascript', rel = 'app.js') =>
  scanSourceContent({ content, rel, language });
const algorithms = (findings) => findings.map((f) => f.algorithm);

test('a JavaScript constant is propagated into crypto calls', () => {
  const content = [
    "const HASH = 'md5';",
    'crypto.createHash(HASH).update(payload);',
    "const CIPHER = 'aes-128-cbc';",
    'crypto.createCipheriv(CIPHER, key, iv);',
    "const MAC = 'sha1';",
    'crypto.createHmac(MAC, key);',
  ].join('\n');
  const found = scan(content);
  assert.ok(algorithms(found).includes('md5'));
  assert.ok(algorithms(found).includes('aes-128-cbc'));
  assert.ok(algorithms(found).includes('hmac-sha1'));
  for (const finding of found) {
    assert.equal(finding.kind, 'source');
    assert.equal(finding.confidence, 'medium');
    assert.ok(finding.evidence?.constant);
  }
});

test('a constant and its refinement merge into one RSA finding', () => {
  const content = ["const KEY_TYPE = 'rsa';", 'crypto.generateKeyPairSync(KEY_TYPE, { modulusLength: 2048 });'].join('\n');
  const found = scan(content);
  const rsa = found.filter((f) => f.algorithm === 'rsa' || f.algorithm.startsWith('rsa-'));
  assert.equal(rsa.length, 1);
  assert.equal(rsa[0].algorithm, 'rsa-2048');
});

test('a reassigned or ambiguous constant is not trusted', () => {
  const reassigned = scan(["let HASH = 'md5';", "HASH = 'sha256';", 'crypto.createHash(HASH);'].join('\n'));
  assert.deepEqual(reassigned, []);

  const ambiguous = scan(["const A = 'md5';", "const A = 'sha256';", 'crypto.createHash(A);'].join('\n'));
  assert.deepEqual(ambiguous, []);
});

test('commented declarations and non-crypto uses do not create findings', () => {
  const content = [
    "// const HASH = 'md5';",
    "const HASH = 'md5';",
    "const LABEL = 'md5';",
    'console.log(LABEL);',
    'crypto.createHash(HASH);',
  ].join('\n');
  const found = scan(content);
  assert.deepEqual(algorithms(found), ['md5']);
  assert.equal(found[0].location.line, 5);
});

test('Python, Java and C# constants resolve through their APIs', () => {
  const py = scan(["HASH = 'md5'", 'hashlib.new(HASH)'].join('\n'), 'python', 'svc.py');
  assert.deepEqual(algorithms(py), ['md5']);

  const java = scan(
    ['private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";', 'Cipher.getInstance(TRANSFORMATION);'].join('\n'),
    'java',
    'Svc.java',
  );
  assert.ok(algorithms(java).includes('aes-128'));

  const javaDigest = scan(
    ['static final String ALGO = "SHA-1";', 'MessageDigest.getInstance(ALGO);'].join('\n'),
    'java',
    'Svc.java',
  );
  assert.ok(algorithms(javaDigest).includes('sha1'));

  const csharp = scan(
    ['const string ALGO = "MD5";', 'HashAlgorithm.Create(ALGO);'].join('\n'),
    'csharp',
    'Svc.cs',
  );
  assert.ok(algorithms(csharp).includes('md5'));
});

test('an indirect finding can be suppressed like any other line', () => {
  const content = [
    "const HASH = 'md5';",
    'crypto.createHash(HASH); // mosca-ignore-line -- legacy compatibility',
    'crypto.createHash(HASH);',
  ].join('\n');
  const found = scan(content);
  assert.equal(found.length, 1);
  assert.equal(found[0].location.line, 3);
});

test('constant collection rejects interpolation and long values', () => {
  const constants = collectConstants("const A = 'md5';\nconst B = `${x}`;\nconst C = 'sha'.toUpperCase();", 'javascript');
  assert.equal(constants.get('A'), 'md5');
  assert.equal(constants.has('B'), false);
  assert.equal(constants.has('C'), false);
  assert.equal(resolveConstantAlgorithm('AES/CBC/PKCS5Padding')?.id, 'aes-128');
  assert.equal(resolveConstantAlgorithm('nonsense-token'), null);
});

test('repeated identical calls count once as a migration site', () => {
  const findings = [];
  for (let line = 1; line <= 4; line++) {
    findings.push({
      id: 'js-createHash',
      kind: 'source',
      title: 'MD5 — hashing',
      algorithm: 'md5',
      primitive: 'hash',
      location: { file: 'src/wrapper.js', line, column: 3 },
      snippet: "return crypto.createHash('md5').update(data).digest('hex');",
      matched: "createHash('md5')",
      confidence: 'high',
    });
  }
  // A genuinely different call in another file is a second site.
  findings.push({
    id: 'js-createHash',
    kind: 'source',
    title: 'MD5 — hashing',
    algorithm: 'md5',
    primitive: 'hash',
    location: { file: 'src/other.js', line: 9, column: 1 },
    snippet: "crypto.createHash('md5')",
    matched: "createHash('md5')",
    confidence: 'high',
  });

  const analysis = analyse({ findings, config, now: NOW });
  const summary = analysis.summary;
  assert.equal(summary.rawOccurrences, 5);
  assert.equal(summary.uniqueMigrationSites, 2);
  assert.equal(summary.duplicateOccurrences, 3);
  assert.equal(summary.migrationSpread, 2.5);
  // Two sites of 0.5 day each, plus a damped spread for the duplicates.
  assert.ok(summary.effortDays >= 1);
  assert.ok(summary.effortDays < 5, 'effort must not scale linearly with occurrences');
});

test('site keys are stable across line moves and helper exports agree', () => {
  const item = (line) => ({
    kind: 'source',
    algorithm: 'md5',
    location: { file: 'src/app.js', line },
    matched: "createHash('md5')",
  });
  assert.equal(migrationSiteKey(item(1)), migrationSiteKey(item(99)));
  assert.equal(baseEffortDays({ kind: 'endpoint', quantum: 'broken' }), 3);
  assert.equal(baseEffortDays({ kind: 'source', quantum: 'broken' }), 0.5);
  assert.equal(baseEffortDays({ kind: 'artifact', quantum: 'weakened' }), 0.5);
});
