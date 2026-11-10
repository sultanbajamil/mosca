/**
 * Artifact scanning has two jobs: find the keys, and never copy them.
 * These tests generate real keys in memory, feed the scanner real PEM, JWK,
 * OpenSSH and DER inputs, and assert that findings contain metadata only.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

import {
  scanArtifactFile,
  scanArtifactsDirectory,
  scanDerArtifact,
  scanJwkContent,
  scanSshKeyContent,
  parsePkcs8Algorithm,
  parseOpenSshPrivateKey,
} from '../src/scan/artifacts.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const certDer = Buffer.from(fs.readFileSync(path.join(here, 'fixtures', 'example-com.der.b64'), 'utf8').trim(), 'base64');
const certPem = `-----BEGIN CERTIFICATE-----\n${certDer.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;

const { publicKey: rsaPublic, privateKey: rsaPrivate } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 1024,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
const edPublic = crypto.generateKeyPairSync('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
}).publicKey;

const b64url = (buf) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function sshString(buf) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(buf.length);
  return Buffer.concat([length, buf]);
}

test('a PEM certificate is classified without exposing the body', () => {
  const findings = scanDerArtifact(certDer, { rel: 'certs/example.pem', format: 'PEM' });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, 'artifact-certificate');
  assert.equal(findings[0].artifact.type, 'certificate');
  assert.equal(findings[0].evidence.subject, 'example.com');
  assert.ok(!JSON.stringify(findings[0]).includes(certDer.toString('base64').slice(0, 40)));
});

test('an RSA public key PEM reports the exact size', () => {
  const findings = scanSshKeyContent; // keep the import surface honest
  assert.equal(typeof findings, 'function');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mosca-art-'));
  try {
    const file = path.join(tmp, 'rsa.pem');
    fs.writeFileSync(file, rsaPublic);
    const found = scanArtifactFile(file, 'rsa.pem');
    const key = found.find((f) => f.id === 'artifact-public-key');
    assert.ok(key);
    assert.equal(key.algorithm, 'rsa-1024');
    assert.equal(key.evidence.keyBits, 1024);
    assert.ok(!JSON.stringify(key).includes('BEGIN PUBLIC KEY'));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('a PKCS#8 private key yields algorithm metadata, not key material', () => {
  const der = crypto.createPrivateKey(rsaPrivate).export({ type: 'pkcs8', format: 'der' });
  const info = parsePkcs8Algorithm(der);
  assert.equal(info.algorithm, 'rsa');
  assert.equal(info.oid, '1.2.840.113549.1.1.1');

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mosca-art-'));
  try {
    const file = path.join(tmp, 'server.key');
    fs.writeFileSync(file, rsaPrivate);
    const found = scanArtifactFile(file, 'server.key');
    const key = found.find((f) => f.id === 'artifact-private-key');
    assert.ok(key);
    assert.equal(key.algorithm, 'rsa');
    assert.equal(key.artifact.type, 'private-key');
    assert.equal(key.evidence.encrypted, null);
    assert.ok(!JSON.stringify(key).includes('PRIVATE KEY'));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('an Ed25519 public key resolves through the registry', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mosca-art-'));
  try {
    const file = path.join(tmp, 'id_ed25519.pub');
    fs.writeFileSync(file, 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterialForTesting user@host\n');
    const found = scanArtifactFile(file, 'id_ed25519.pub');
    assert.equal(found.length, 1);
    assert.equal(found[0].algorithm, 'ssh-ed25519');
    assert.equal(found[0].artifact.type, 'ssh-public-key');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('the Ed25519 SPKI PEM is parsed', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mosca-art-'));
  try {
    const file = path.join(tmp, 'ed.pem');
    fs.writeFileSync(file, edPublic);
    const found = scanArtifactFile(file, 'ed.pem');
    assert.equal(found[0].algorithm, 'ed25519');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('JWK and JWKS keys are mapped by kty, crv and alg', () => {
  const jwk = JSON.stringify({ kty: 'RSA', alg: 'RS256', n: b64url(Buffer.alloc(256, 0x41)), e: 'AQAB' });
  const rsa = scanJwkContent(jwk, 'jwks.json');
  assert.equal(rsa.length, 1);
  assert.equal(rsa[0].algorithm, 'rsa-2048');
  assert.equal(rsa[0].artifact.type, 'jwk');

  const jwks = JSON.stringify({
    keys: [
      { kty: 'EC', crv: 'P-256', alg: 'ES256', x: 'abc', y: 'def' },
      { kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA', x: 'ghi' },
      { kty: 'oct', alg: 'HS256', k: 'secret' },
    ],
  });
  const set = scanJwkContent(jwks, 'keys.json');
  assert.equal(set.length, 3);
  assert.equal(set[0].algorithm, 'ecdsa');
  assert.equal(set[1].algorithm, 'ed25519');
  assert.equal(set[2].algorithm, 'hmac-sha256');
  assert.ok(!JSON.stringify(set).includes('secret'));
});

test('authorized_keys and known_hosts lines are found', () => {
  const text = [
    '# comment',
    'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQExampleKeyMaterialForTesting user@host',
    'host.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterialForTesting',
    'command="echo hi" ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYExampleKey user@host',
  ].join('\n');
  const findings = scanSshKeyContent(text, 'authorized_keys');
  assert.equal(findings.length, 3);
  assert.deepEqual(findings.map((f) => f.algorithm), ['ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-nistp256']);
  assert.equal(findings[0].location.line, 2);
});

test('an OpenSSH private key exposes only the public blob metadata', () => {
  const magic = Buffer.from('openssh-key-v1\u0000', 'latin1');
  const publicBlob = Buffer.concat([
    sshString(Buffer.from('ssh-ed25519', 'latin1')),
    sshString(Buffer.alloc(32, 0x42)),
  ]);
  const der = Buffer.concat([
    magic,
    sshString(Buffer.from('none')),
    sshString(Buffer.from('none')),
    sshString(Buffer.alloc(0)),
    Buffer.from([0, 0, 0, 1]), // one key
    sshString(publicBlob),
    sshString(Buffer.alloc(0)), // private section placeholder
  ]);
  const info = parseOpenSshPrivateKey(der);
  assert.equal(info.type, 'ssh-ed25519');
  assert.equal(info.bits, 256);
  assert.equal(info.encrypted, false);
  assert.ok(!JSON.stringify(info).includes('AAAC'));
});

test('the directory scan sees files the default ignore list hides', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mosca-art-'));
  try {
    fs.mkdirSync(path.join(tmp, 'certs'));
    fs.writeFileSync(path.join(tmp, 'certs', 'server.pem'), certPem);
    fs.writeFileSync(path.join(tmp, 'server.key'), rsaPrivate);
    const result = scanArtifactsDirectory(tmp);
    const ids = result.findings.map((f) => f.id);
    assert.ok(ids.includes('artifact-certificate'));
    assert.ok(ids.includes('artifact-private-key'));
    assert.ok(result.stats.filesScanned >= 2);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
