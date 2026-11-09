/**
 * Rule-level tests. Each case is a small, realistic snippet that either must
 * be found (a true positive) or must stay silent (a false positive we have
 * already shipped once).
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { scanSourceContent, scanSourceContentDetailed, detectLanguage } from '../src/scan/source.js';
import { scanConfigContent } from '../src/scan/config.js';
import { CONFIG_RULES, isConfigFile } from '../src/rules/config.js';
import { RULES, RULE_COUNT } from '../src/rules/source.js';

function scanSource(content, language = 'javascript', rel = 'app.js') {
  return scanSourceContent({ content, rel, language });
}

const algorithms = (findings) => findings.map((f) => f.algorithm);
const ids = (findings) => findings.map((f) => f.id);

test('the rule inventory covers the languages we claim', () => {
  assert.ok(RULE_COUNT >= 100, `only ${RULE_COUNT} source rules`);
  assert.ok(CONFIG_RULES.length >= 20);
  for (const language of ['javascript', 'typescript', 'python', 'go', 'java', 'c', 'cpp', 'rust', 'php', 'ruby', 'csharp', 'kotlin', 'swift', 'scala', 'shell', 'powershell']) {
    assert.ok(RULES[language]?.length > 0, `no rules for ${language}`);
  }
});

test('language detection maps extensions', () => {
  assert.equal(detectLanguage('src/app.js'), 'javascript');
  assert.equal(detectLanguage('src/app.ts'), 'typescript');
  assert.equal(detectLanguage('svc/main.go'), 'go');
  assert.equal(detectLanguage('README.md'), null);
});

test('finds hashing, ciphers and key generation in JavaScript', () => {
  const content = [
    "const digest = crypto.createHash('md5').update(data).digest('hex');",
    "const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);",
    "const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });",
  ].join('\n');
  const found = scanSource(content);
  assert.ok(algorithms(found).includes('md5'));
  assert.ok(algorithms(found).includes('aes-128-cbc'));
  assert.ok(algorithms(found).includes('rsa-2048'));

  const md5 = found.find((f) => f.algorithm === 'md5');
  assert.equal(md5.location.line, 1);
  assert.equal(md5.location.column > 0, true);
  assert.match(md5.snippet, /createHash/);
  assert.equal(md5.kind, 'source');
});

test('one call is reported once, with the more specific key size', () => {
  const found = scanSource("crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });");
  const rsa = found.filter((f) => f.algorithm === 'rsa' || f.algorithm.startsWith('rsa-'));
  assert.equal(rsa.length, 1, 'key generation should not be double-reported');
  assert.equal(rsa[0].algorithm, 'rsa-2048');
});

test('comments are not findings', () => {
  const content = [
    "// crypto.createHash('md5') is banned",
    '/*',
    " * legacy: crypto.createCipheriv('des-ede3-cbc', key, iv)",
    ' */',
    "const ok = crypto.createHash('sha256');",
  ].join('\n');
  const found = scanSource(content);
  assert.deepEqual(algorithms(found), ['sha256']);
});

test('TLS policy rules only flag legacy floors and caps', () => {
  assert.deepEqual(scanSource("minVersion: 'TLSv1.2',"), []);
  assert.deepEqual(scanSource("minVersion: 'TLSv1.3',"), []);

  const oneOne = scanSource("minVersion: 'TLSv1.1',");
  assert.deepEqual(algorithms(oneOne), ['tls-1.1']);

  const oneOh = scanSource("minVersion: 'TLSv1',");
  assert.deepEqual(algorithms(oneOh), ['tls-1.0']);

  const capped = scanSource("maxVersion: 'TLSv1.2',");
  assert.deepEqual(algorithms(capped), ['tls-1.2']);
});

test('Go TLS rules distinguish floor from ceiling', () => {
  assert.deepEqual(scanSource('MinVersion: tls.VersionTLS12,', 'go', 'main.go'), []);
  assert.deepEqual(scanSource('MinVersion: tls.VersionTLS13,', 'go', 'main.go'), []);
  assert.deepEqual(algorithms(scanSource('MinVersion: tls.VersionTLS10,', 'go', 'main.go')), ['tls-1.0']);
  assert.deepEqual(algorithms(scanSource('MaxVersion: tls.VersionTLS12,', 'go', 'main.go')), ['tls-1.2']);
});

test('Python and Java rules resolve real API names', () => {
  const py = scanSource('hashlib.md5(payload)', 'python', 'svc.py');
  assert.deepEqual(algorithms(py), ['md5']);

  const pyRsa = scanSource('rsa.generate_private_key(public_exponent=65537, key_size=2048)', 'python', 'svc.py');
  assert.deepEqual(algorithms(pyRsa), ['rsa-2048']);

  const java = scanSource('KeyPairGenerator.getInstance("RSA");', 'java', 'Svc.java');
  assert.deepEqual(algorithms(java), ['rsa']);

  const javaMd5 = scanSource('MessageDigest.getInstance("MD5")', 'java', 'Svc.java');
  assert.deepEqual(algorithms(javaMd5), ['md5']);
});

test('nginx: a negated cipher list is not a NULL cipher policy', () => {
  const found = scanConfigContent({
    rel: 'infra/nginx.conf',
    content: 'ssl_ciphers HIGH:!aNULL:!MD5:RC4-SHA:DES-CBC3-SHA;',
  });
  assert.ok(!ids(found).includes('nginx-null'), '!aNULL must not be read as NULL');
  assert.deepEqual(algorithms(found).sort(), ['3des', 'rc4']);
});

test('nginx: TLS 1.2-only policy is clean, legacy policy is not', () => {
  const safe = scanConfigContent({ rel: 'nginx.conf', content: 'ssl_protocols TLSv1.2 TLSv1.3;' });
  assert.deepEqual(safe, []);

  const legacy = scanConfigContent({ rel: 'nginx.conf', content: 'ssl_protocols TLSv1 TLSv1.1 TLSv1.2;' });
  assert.deepEqual(algorithms(legacy), ['tls-1.0']);
});

test('nginx: curve and hybrid group policy is detected', () => {
  const curve = scanConfigContent({ rel: 'nginx.conf', content: 'ssl_ecdh_curve secp256r1;' });
  assert.deepEqual(algorithms(curve), ['ecdh']);

  const hybrid = scanConfigContent({
    rel: 'nginx.conf',
    content: 'ssl_conf_command Groups X25519MLKEM768:X25519;',
  });
  assert.deepEqual(algorithms(hybrid), ['x25519mlkem768']);
});

test('sshd: weak kex, MACs and ciphers are found', () => {
  const kex = scanConfigContent({
    rel: 'infra/sshd_config',
    content: 'KexAlgorithms diffie-hellman-group1-sha1,curve25519-sha256',
  });
  assert.deepEqual(algorithms(kex), ['dh']);

  const macs = scanConfigContent({ rel: 'infra/sshd_config', content: 'MACs hmac-sha1,hmac-sha2-256' });
  assert.deepEqual(algorithms(macs), ['hmac-sha1']);

  const ciphers = scanConfigContent({ rel: 'infra/sshd_config', content: 'Ciphers aes128-ctr,3des-cbc' });
  assert.deepEqual(algorithms(ciphers), ['3des']);
});

test('openssl config: default_md and MinProtocol', () => {
  const md = scanConfigContent({ rel: 'infra/openssl.cnf', content: 'default_md = sha1' });
  assert.deepEqual(algorithms(md), ['sha1']);

  const min = scanConfigContent({ rel: 'infra/openssl.cnf', content: 'MinProtocol = TLSv1' });
  assert.deepEqual(algorithms(min), ['tls-1.0']);

  const good = scanConfigContent({ rel: 'infra/openssl.cnf', content: 'MinProtocol = TLSv1.3' });
  assert.deepEqual(good, []);
});

test('config detection does not swallow package manifests', () => {
  assert.equal(isConfigFile('infra/nginx.conf'), true);
  assert.equal(isConfigFile('infra/sshd_config'), true);
  assert.equal(isConfigFile('deploy/app.yaml'), true);
  assert.equal(isConfigFile('src/app.js'), false);
});

test('inline suppressions silence one line with an auditable reason', () => {
  const content = [
    "crypto.createHash('md5'); // mosca-ignore-line -- legacy fixture",
    "crypto.createHash('sha1');",
  ].join('\n');
  const { findings, suppressed } = scanSourceContentDetailed({ content, rel: 'a.js', language: 'javascript' });
  assert.deepEqual(algorithms(findings), ['sha1']);
  assert.equal(suppressed, 1);
});

test('mosca-ignore-next-line silences only the following line', () => {
  const content = [
    '// mosca-ignore-next-line -- probe deliberately offers legacy TLS',
    "minVersion: 'TLSv1',",
    "minVersion: 'TLSv1',",
  ].join('\n');
  const { findings, suppressed } = scanSourceContentDetailed({ content, rel: 'a.js', language: 'javascript' });
  assert.equal(suppressed, 1);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].location.line, 3);
});

test('mosca-ignore-file silences the whole file', () => {
  const content = [
    '// mosca-ignore-file -- generated vendor bundle',
    "crypto.createHash('md5');",
    "crypto.createHash('sha1');",
  ].join('\n');
  const { findings, suppressed } = scanSourceContentDetailed({ content, rel: 'vendor.js', language: 'javascript' });
  assert.deepEqual(findings, []);
  assert.equal(suppressed, 2);
});

test('a suppression without a reason is still honoured', () => {
  const content = "crypto.createHash('md5'); // mosca-ignore-line";
  const { findings, suppressed } = scanSourceContentDetailed({ content, rel: 'a.js', language: 'javascript' });
  assert.deepEqual(findings, []);
  assert.equal(suppressed, 1);
});
