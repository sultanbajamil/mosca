/**
 * Chain analysis is where MOSCA stops auditing one certificate and starts
 * auditing the trust hierarchy. These tests use the real example.com leaf
 * fixture plus synthetic chain entries so every branch (weak intermediate,
 * long-lived root, PQC bloat) is exercised deterministically.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  INITIAL_CWND,
  PQC_SIZES,
  analyseChain,
  classifyCertificate,
  estimatePqcHandshake,
  keyAlgorithmId,
  longLivedClassical,
  weakestLink,
  deriveChainFindings,
} from '../src/net/x509-chain.js';
import { parseCertificate } from '../src/net/x509.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const der = Buffer.from(fs.readFileSync(path.join(here, 'fixtures', 'example-com.der.b64'), 'utf8').trim(), 'base64');
const NOW = new Date('2026-01-01T00:00:00Z');

function yearsFrom(base, years) {
  return new Date(base.getTime() + years * 365.25 * 86400000);
}

/** A parsed-certificate-shaped object, without needing DER for every case. */
function synthetic({
  cn = 'Leaf',
  issuer = 'Issuer',
  isCA = false,
  keyAlgo = 'ecdsa',
  bits = 256,
  sigAlgo = 'ecdsa',
  sigHash = 'sha256',
  validityYears = 1,
  derLength = 900,
  publicKeyBytes = 91,
  signatureBytes = 72,
  notBefore = NOW,
  notAfter = yearsFrom(NOW, validityYears),
} = {}) {
  return {
    subject: { CN: cn },
    issuer: { CN: issuer },
    isCA,
    notBefore,
    notAfter,
    sigAlgOid: '1.2.840.10045.4.3.2',
    sigAlgName: `${sigAlgo}With${sigHash}`,
    sigAlgo,
    sigHash,
    publicKey: { algorithm: keyAlgo, bits, curve: null, keyBytes: publicKeyBytes },
    san: [],
    derLength,
    signatureBytes,
  };
}

test('classifyCertificate turns the real fixture into a posture', () => {
  const entry = classifyCertificate(parseCertificate(der), 0, NOW);
  assert.equal(entry.role, 'leaf');
  assert.equal(entry.keyAlgorithm, 'ecdsa');
  assert.equal(entry.quantum, 'broken');
  assert.equal(entry.classical, 'strong');
  assert.equal(entry.legacySignature, false);
});

test('keyAlgorithmId rounds RSA sizes and keeps curve families', () => {
  assert.equal(keyAlgorithmId({ algorithm: 'rsa', bits: 1024 }), 'rsa-1024');
  assert.equal(keyAlgorithmId({ algorithm: 'rsa', bits: 2048 }), 'rsa-2048');
  assert.equal(keyAlgorithmId({ algorithm: 'rsa', bits: 4096 }), 'rsa-4096');
  assert.equal(keyAlgorithmId({ algorithm: 'ecdsa', bits: 256 }), 'ecdsa');
  assert.equal(keyAlgorithmId({ algorithm: 'ed25519' }), 'ed25519');
  assert.equal(keyAlgorithmId(null), 'unknown');
});

test('the weakest link is found above a stronger leaf', () => {
  const entries = [
    classifyCertificate(synthetic({ cn: 'Leaf', keyAlgo: 'ecdsa' }), 0, NOW),
    classifyCertificate(synthetic({ cn: 'Legacy Intermediate', issuer: 'Root', keyAlgo: 'rsa', bits: 2048, sigAlgo: 'rsa' }), 1, NOW),
    classifyCertificate(synthetic({ cn: 'Root', issuer: 'Root', isCA: true, keyAlgo: 'rsa', bits: 4096, sigAlgo: 'rsa' }), 2, NOW),
  ];
  const weak = weakestLink(entries);
  assert.equal(weak.index, 1);
  assert.equal(weak.role, 'intermediate');
  assert.equal(weak.isChainWeakness, true);
  assert.ok(weak.delta > 0);
});

test('a chain whose leaf is the weakest does not report a chain weakness', () => {
  const entries = [
    classifyCertificate(synthetic({ cn: 'Leaf', keyAlgo: 'rsa', bits: 2048, sigAlgo: 'rsa' }), 0, NOW),
    classifyCertificate(synthetic({ cn: 'Root', issuer: 'Root', isCA: true, keyAlgo: 'rsa', bits: 4096, sigAlgo: 'rsa' }), 1, NOW),
  ];
  const weak = weakestLink(entries);
  assert.equal(weak.index, 0);
  assert.equal(weak.isChainWeakness, false);
});

test('SHA-1 signatures are marked classically broken', () => {
  const entry = classifyCertificate(synthetic({ sigHash: 'sha1', sigAlgo: 'rsa' }), 1, NOW);
  assert.equal(entry.legacySignature, true);
  assert.equal(entry.classical, 'broken');
});

test('long-lived classical roots are flagged as structural exposure', () => {
  const entries = [
    classifyCertificate(synthetic({ cn: 'Leaf' }), 0, NOW),
    classifyCertificate(
      synthetic({ cn: 'Root', issuer: 'Root', isCA: true, keyAlgo: 'rsa', bits: 4096, sigAlgo: 'rsa', validityYears: 25 }),
      1,
      NOW,
    ),
  ];
  const root = longLivedClassical(entries, { now: NOW, yearsToCRQC: 7 });
  assert.equal(root.longLived, true);
  assert.equal(root.classical, true);
  assert.equal(root.exposed, true);
  assert.ok(root.remainingYears >= 24);
});

test('PQC handshake estimate crosses the 14 KB initial congestion window', () => {
  const entries = [
    classifyCertificate(synthetic({ cn: 'Leaf' }), 0, NOW),
    classifyCertificate(synthetic({ cn: 'Intermediate', issuer: 'Root' }), 1, NOW),
    classifyCertificate(synthetic({ cn: 'Root', issuer: 'Root', isCA: true }), 2, NOW),
  ];
  const estimate = estimatePqcHandshake(entries);
  assert.equal(estimate.threshold, INITIAL_CWND);
  assert.equal(INITIAL_CWND, 14336);
  assert.ok(estimate.projections['ml-dsa-65']);
  assert.equal(estimate.projections['ml-dsa-65'].label, 'ML-DSA-65');
  assert.ok(estimate.projections['ml-dsa-65'].totalBytes > INITIAL_CWND);
  assert.equal(estimate.projections['ml-dsa-65'].exceeds, true);
  assert.equal(estimate.exceeds, true);
  assert.ok(PQC_SIZES['ml-dsa-65'].signature === 3309);
});

test('a short chain fits the congestion window under ML-DSA-65', () => {
  const entries = [classifyCertificate(synthetic({ derLength: 700, publicKeyBytes: 91, signatureBytes: 72 }), 0, NOW)];
  const estimate = estimatePqcHandshake(entries);
  assert.equal(estimate.projections['ml-dsa-65'].totalBytes < INITIAL_CWND, true);
  assert.equal(estimate.projections['ml-dsa-65'].exceeds, false);
  // SLH-DSA is the largest option and is allowed to exceed on its own.
  assert.equal(estimate.projections['slh-dsa-128s'].exceeds, true);
});

test('analyseChain handles the real fixture and an unparseable entry', () => {
  const chain = analyseChain([der, Buffer.from('not a certificate')], { now: NOW, yearsToCRQC: 7 });
  assert.equal(chain.length, 1);
  assert.equal(chain.entries[0].role, 'leaf');
  assert.equal(chain.errors.length, 1);
  assert.ok(chain.pqc.projections['ml-dsa-65']);
});

test('deriveChainFindings reports the weak link, the root and the bloat', () => {
  const chain = analyseChain(
    [
      synthetic({ cn: 'Leaf' }),
      synthetic({ cn: 'Legacy Intermediate', issuer: 'Root', keyAlgo: 'rsa', bits: 2048, sigAlgo: 'rsa', sigHash: 'sha1' }),
      synthetic({ cn: 'Root', issuer: 'Root', isCA: true, keyAlgo: 'rsa', bits: 4096, sigAlgo: 'rsa', validityYears: 25 }),
    ],
    { now: NOW, yearsToCRQC: 7 },
  );
  const findings = deriveChainFindings(chain, { host: 'example.com', port: 443 }, { yearsToCRQC: 7 });
  const ids = findings.map((f) => f.id);
  assert.ok(ids.includes('chain-weakest-link'));
  assert.ok(ids.includes('chain-legacy-signature'));
  assert.ok(ids.includes('chain-long-lived-root'));
  assert.ok(ids.includes('chain-pqc-bloat'));
  for (const finding of findings) {
    assert.equal(finding.kind, 'chain');
    assert.equal(finding.location.host, 'example.com');
  }
});
