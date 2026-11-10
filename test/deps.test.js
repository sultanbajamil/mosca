/**
 * The supply-chain scanner must read every major lockfile dialect without
 * installing anything. Each fixture is a small but genuine excerpt of the
 * format, including scoped npm names, TOML package blocks and go.sum's
 * /go.mod duplicate lines.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  parsePackageLock,
  parseYarnLock,
  parsePnpmLock,
  parseCargoLock,
  parseGoSum,
  parseRequirements,
  parsePomXml,
  scanDependencyContent,
  scanDependenciesDirectory,
  packageFinding,
} from '../src/scan/deps.js';
import { CRYPTO_PACKAGES, packageRule, versionLessThan } from '../src/rules/crypto-packages.js';

test('package-lock v3 maps scoped and ordinary packages', () => {
  const content = JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'app', version: '1.0.0' },
      'node_modules/crypto-js': { version: '3.1.9' },
      'node_modules/node-rsa': { version: '1.1.1' },
      'node_modules/@noble/post-quantum': { version: '0.2.1' },
      'node_modules/left-pad': { version: '1.3.0' },
    },
  });
  const packages = parsePackageLock(content);
  assert.equal(packages.length, 4);
  const result = scanDependencyContent({ content, rel: 'package-lock.json' });
  const ids = result.findings.map((f) => f.id);
  assert.ok(ids.includes('dependency-deprecated'));
  assert.ok(ids.includes('dependency-quantum-vulnerable'));
  assert.ok(ids.includes('dependency-pqc-ready'));
  assert.equal(result.findings.find((f) => f.package.name === '@noble/post-quantum').positive, true);
  assert.equal(result.findings.some((f) => f.package.name === 'left-pad'), false);
});

test('yarn.lock handles quoted scoped names and Berry version syntax', () => {
  const content = [
    '"@noble/post-quantum@^0.2.0":',
    '  version "0.2.1"',
    '  resolved "https://registry.yarnpkg.com/@noble/post-quantum/-/post-quantum-0.2.1.tgz"',
    '',
    'elliptic@^6.5.0:',
    '  version: 6.5.4',
    '',
  ].join('\n');
  const packages = parseYarnLock(content);
  assert.equal(packages.length, 2);
  const result = scanDependencyContent({ content, rel: 'yarn.lock' });
  assert.equal(result.findings.length, 2);
  assert.equal(result.findings[0].package.name, '@noble/post-quantum');
  assert.equal(result.findings[1].algorithm, 'ecdsa');
});

test('pnpm-lock.yaml reads both v6 and v9 entry shapes', () => {
  const content = [
    'lockfileVersion: 9.0',
    'packages:',
    "  '@noble/post-quantum@0.2.1':",
    '    resolution: {integrity: sha512-abc}',
    '  /tweetnacl@1.0.3:',
    '    resolution: {integrity: sha512-def}',
    '',
  ].join('\n');
  const packages = parsePnpmLock(content);
  assert.equal(packages.length, 2);
  assert.deepEqual(packages.map((p) => p.name), ['@noble/post-quantum', 'tweetnacl']);
});

test('Cargo.lock and poetry.lock share the [[package]] parser', () => {
  const cargo = [
    '[[package]]',
    'name = "rsa"',
    'version = "0.9.6"',
    '',
    '[[package]]',
    'name = "ml-kem"',
    'version = "0.2.1"',
    '',
  ].join('\n');
  const packages = parseCargoLock(cargo, 'Cargo.lock');
  assert.equal(packages.length, 2);
  const result = scanDependencyContent({ content: cargo, rel: 'Cargo.lock' });
  assert.deepEqual(result.findings.map((f) => f.id), ['dependency-quantum-vulnerable', 'dependency-pqc-ready']);
});

test('go.sum deduplicates /go.mod lines and gates old x/crypto', () => {
  const content = [
    'golang.org/x/crypto v0.1.0 h1:abc',
    'golang.org/x/crypto v0.1.0/go.mod h1:def',
    'golang.org/x/crypto v0.40.0 h1:ghi',
    'github.com/cloudflare/circl v1.3.9 h1:jkl',
    '',
  ].join('\n');
  const packages = parseGoSum(content);
  assert.equal(packages.length, 3);
  const result = scanDependencyContent({ content, rel: 'go.sum' });
  const ids = result.findings.map((f) => f.id);
  // v0.1.0 is below the ML-KEM threshold; v0.40.0 is not flagged.
  assert.equal(ids.filter((id) => id === 'dependency-quantum-vulnerable').length, 1);
  assert.ok(ids.includes('dependency-pqc-ready'));
});

test('requirements.txt and pom.xml are parsed without installing', () => {
  const req = ['pycrypto==2.6.1', 'pqcrypto==0.3.4', 'requests==2.31.0', '# comment'].join('\n');
  const result = scanDependencyContent({ content: req, rel: 'requirements.txt' });
  assert.equal(result.findings.length, 2);
  assert.equal(result.findings[0].id, 'dependency-classically-broken');
  assert.equal(result.findings[1].id, 'dependency-pqc-ready');

  const pom = [
    '<project><dependencies>',
    '<dependency><groupId>com.nimbusds</groupId><artifactId>nimbus-jose-jwt</artifactId><version>9.37</version></dependency>',
    '<dependency><groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk15on</artifactId><version>1.70</version></dependency>',
    '</dependencies></project>',
  ].join('');
  const packages = parsePomXml(pom);
  assert.equal(packages.length, 2);
  const maven = scanDependencyContent({ content: pom, rel: 'pom.xml' });
  assert.equal(maven.findings.length, 2);
});

test('package rules are version-gated and deterministic', () => {
  assert.equal(versionLessThan('0.1.0', '0.33.0'), true);
  assert.equal(versionLessThan('0.40.0', '0.33.0'), false);
  assert.equal(packageRule('golang.org/x/crypto/ssh')?.ecosystem, 'go');
  assert.equal(packageRule('@noble/post-quantum')?.status, 'quantum-safe');
  assert.equal(packageRule('left-pad'), null);
  assert.ok(CRYPTO_PACKAGES.pqcrypto);

  const old = packageFinding({ name: 'golang.org/x/crypto', version: 'v0.2.0', ecosystem: 'go', file: 'go.sum', line: 3 });
  assert.ok(old);
  const current = packageFinding({ name: 'golang.org/x/crypto', version: 'v0.40.0', ecosystem: 'go', file: 'go.sum', line: 3 });
  assert.equal(current, null);
});

test('the directory scan reads lockfiles the default ignore list hides', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mosca-deps-'));
  try {
    fs.writeFileSync(
      path.join(tmp, 'package-lock.json'),
      JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/node-rsa': { version: '1.1.1' } } }),
    );
    fs.writeFileSync(path.join(tmp, 'requirements.txt'), 'pycrypto==2.6.1\n');
    const result = scanDependenciesDirectory(tmp);
    assert.equal(result.findings.length, 2);
    assert.equal(result.stats.filesScanned, 2);
    assert.ok(result.packages.length >= 2);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
