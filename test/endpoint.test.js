/**
 * Endpoint logic that does not need the network: target parsing, protocol
 * normalisation, certificate summaries and finding derivation.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseTarget, normaliseProtocol, summariseCertificate, deriveEndpointFindings } from '../src/net/tls.js';
import { parseCertificate } from '../src/net/x509.js';

const here = path.dirname(fileURLToPath(import.meta.url));

test('parseTarget handles URLs, ports, IPv4 and IPv6', () => {
  assert.deepEqual(parseTarget('example.com'), { host: 'example.com', port: 443, servername: 'example.com' });
  assert.deepEqual(parseTarget('https://example.com:8443/path?q=1'), {
    host: 'example.com',
    port: 8443,
    servername: 'example.com',
  });
  assert.deepEqual(parseTarget('1.2.3.4:993'), { host: '1.2.3.4', port: 993, servername: undefined });
  assert.deepEqual(parseTarget('[2001:db8::1]:8443'), {
    host: '2001:db8::1',
    port: 8443,
    servername: undefined,
  });
});

test('normaliseProtocol matches the report spelling', () => {
  assert.equal(normaliseProtocol('TLSv1.3'), 'TLS 1.3');
  assert.equal(normaliseProtocol('TLSv1.2'), 'TLS 1.2');
  assert.equal(normaliseProtocol('SSLv3'), 'SSL 3');
  assert.equal(normaliseProtocol(null), null);
});

test('summariseCertificate classifies a real certificate', () => {
  const der = Buffer.from(
    fs.readFileSync(path.join(here, 'fixtures', 'example-com.der.b64'), 'utf8').trim(),
    'base64',
  );
  const cert = summariseCertificate(parseCertificate(der));
  assert.equal(cert.subject, 'example.com');
  assert.equal(cert.signature.algorithm, 'ecdsa');
  assert.equal(cert.signature.name, 'ecdsa-with-SHA256');
  assert.equal(cert.publicKey.algorithm, 'ecdsa');
  assert.equal(cert.publicKey.bits, 256);
  assert.equal(typeof cert.daysRemaining, 'number');
  assert.ok(cert.san.includes('example.com'));
  assert.equal(cert.isCA, false);
});

test('a hybrid TLS 1.3 endpoint yields one positive finding', () => {
  const findings = deriveEndpointFindings({
    host: 'example.com',
    port: 443,
    reachable: true,
    protocol: 'TLS 1.3',
    cipher: 'TLS_AES_256_GCM_SHA384',
    group: 'X25519MLKEM768',
    groupLabel: 'X25519+ML-KEM-768',
    hybrid: true,
    legacyTls: [],
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, 'endpoint-hybrid-kex');
  assert.equal(findings[0].positive, true);
  assert.equal(findings[0].algorithm, 'x25519mlkem768');
});

test('a classical endpoint reports kex, legacy protocol and legacy acceptance', () => {
  const findings = deriveEndpointFindings({
    host: 'legacy.example',
    port: 443,
    reachable: true,
    protocol: 'TLS 1.1',
    cipher: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
    group: 'x25519',
    groupLabel: 'X25519',
    hybrid: false,
    legacyTls: ['TLS 1.1'],
    certificate: null,
  });
  const ids = findings.map((f) => f.id);
  assert.ok(ids.includes('endpoint-classical-kex'));
  assert.ok(ids.includes('endpoint-legacy-protocol'));
  assert.ok(ids.includes('endpoint-accepts-legacy-tls'));
});

test('a TLS 1.3 endpoint is never labelled a legacy protocol', () => {
  const findings = deriveEndpointFindings({
    host: 'modern.example',
    port: 443,
    reachable: true,
    protocol: 'TLS 1.3',
    cipher: 'TLS_AES_256_GCM_SHA384',
    group: 'X25519MLKEM768',
    groupLabel: 'X25519+ML-KEM-768',
    hybrid: true,
    legacyTls: [],
  });
  assert.ok(!findings.some((f) => f.id === 'endpoint-legacy-protocol'));
});

test('unreachable endpoints produce no findings', () => {
  assert.deepEqual(deriveEndpointFindings({ reachable: false, host: 'x', port: 443 }), []);
});
