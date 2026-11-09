/**
 * The algorithm registry is the single source of truth for every judgement
 * MOSCA makes. If an entry is malformed, every downstream score is wrong, so
 * these tests are deliberately strict about the shape of the data.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  ALGORITHMS,
  QUANTUM,
  CLASSICAL,
  lookup,
  normaliseName,
  rsaVariant,
  replacementFor,
  tlsVersionId,
  isQuantumWeak,
  isQuantumBroken,
} from '../src/rules/algorithms.js';

test('every registry entry is well formed', () => {
  const entries = Object.entries(ALGORITHMS);
  assert.ok(entries.length >= 80, `expected a broad registry, got ${entries.length}`);

  for (const [key, algo] of entries) {
    assert.equal(algo.id, key, `id mismatch for ${key}`);
    assert.equal(typeof algo.label, 'string');
    assert.ok(algo.label.length > 0, `${key} has no label`);
    assert.ok(Array.isArray(algo.primitives) && algo.primitives.length > 0, `${key} has no primitives`);
    assert.ok(Object.values(QUANTUM).includes(algo.quantum), `${key} has quantum=${algo.quantum}`);
    assert.ok(Object.values(CLASSICAL).includes(algo.classical), `${key} has classical=${algo.classical}`);
  }
});

test('every replacement points at a real registry entry', () => {
  for (const [key, algo] of Object.entries(ALGORITHMS)) {
    if (!algo.replacement) continue;
    assert.ok(ALGORITHMS[algo.replacement], `${key} -> ${algo.replacement} is not in the registry`);
  }
});

test('the replacement graph has no cycles', () => {
  for (const start of Object.keys(ALGORITHMS)) {
    const seen = new Set();
    let id = start;
    let steps = 0;
    while (ALGORITHMS[id]?.replacement) {
      assert.ok(!seen.has(id), `replacement cycle starting at ${start}`);
      seen.add(id);
      id = ALGORITHMS[id].replacement;
      assert.ok(++steps <= 10, `replacement chain for ${start} is too long`);
    }
  }
});

test('lookup normalises vendor spellings and API casing', () => {
  assert.equal(lookup('SHA-256').id, 'sha256');
  assert.equal(lookup('sha_256').id, 'sha256');
  assert.equal(lookup('AES-256-GCM').id, 'aes-256-gcm');
  assert.equal(lookup('RS256').id, 'rsa');
  assert.equal(lookup('sha256WithRSA').id, 'rsa');
  assert.equal(lookup('prime256v1').id, 'ecdh');
  assert.equal(lookup('not-a-real-algorithm').id, 'unknown');
  assert.equal(lookup('').id, 'unknown');
  assert.equal(normaliseName('  TLS 1.3 '), 'tls-1.3');
});

test('rsaVariant rounds a key size to the closest registry entry', () => {
  assert.equal(rsaVariant(1024).id, 'rsa-1024');
  assert.equal(rsaVariant(2048).id, 'rsa-2048');
  assert.equal(rsaVariant(2050).id, 'rsa-3072');
  assert.equal(rsaVariant(3072).id, 'rsa-3072');
  assert.equal(rsaVariant(4096).id, 'rsa-4096');
  assert.equal(rsaVariant(8192).id, 'rsa-4096');
  assert.equal(rsaVariant(null).id, 'rsa');
});

test('replacementFor respects how the primitive is used', () => {
  const rsa = ALGORITHMS.rsa;
  assert.equal(replacementFor(rsa, 'signature'), 'ml-dsa-65');
  assert.equal(replacementFor(rsa, 'pke'), 'ml-kem-768');
  assert.equal(replacementFor(ALGORITHMS.ecdh, 'key-agreement'), 'x25519mlkem768');
  assert.equal(replacementFor(ALGORITHMS.ed25519, 'signature'), 'ml-dsa-65');
  assert.equal(replacementFor(ALGORITHMS['ml-kem-768'], 'pke'), 'ml-kem-768');
  assert.equal(replacementFor(ALGORITHMS.unknown, 'pke'), null);
});

test('tlsVersionId understands every dialect the rules emit', () => {
  assert.equal(tlsVersionId('TLSv1'), 'tls-1.0');
  assert.equal(tlsVersionId('TLSv1.1'), 'tls-1.1');
  assert.equal(tlsVersionId('TLSv1.2'), 'tls-1.2');
  assert.equal(tlsVersionId('TLSv1.3'), 'tls-1.3');
  assert.equal(tlsVersionId('TLS1_2_VERSION'), 'tls-1.2');
  assert.equal(tlsVersionId('VersionTLS13'), 'tls-1.3');
  assert.equal(tlsVersionId('PROTOCOL_TLSv1_1'), 'tls-1.1');
  assert.equal(tlsVersionId('SSLv3'), 'tls-1.0');
});

test('quantum helpers separate broken from merely weakened', () => {
  assert.equal(isQuantumBroken(ALGORITHMS.rsa), true);
  assert.equal(isQuantumBroken(ALGORITHMS['ml-kem-768']), false);
  assert.equal(isQuantumWeak(ALGORITHMS['aes-128']), true);
  assert.equal(isQuantumWeak(ALGORITHMS['aes-256']), false);
  assert.equal(isQuantumWeak(ALGORITHMS.sha256), false);
});
