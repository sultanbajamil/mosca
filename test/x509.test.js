/**
 * The X.509 parser exists so MOSCA can classify a live endpoint's certificate
 * without pulling in a dependency. The fixture is a real DER certificate for
 * example.com, captured with the `tls` module, so the test proves the parser
 * against the encoding the public web actually uses.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  parseCertificate,
  readTLV,
  decodeOID,
  decodeInteger,
  decodeString,
  decodeTime,
  sigAlgFromOid,
  TAG,
  OID,
} from '../src/net/x509.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = path.join(here, 'fixtures', 'example-com.der.b64');
const der = Buffer.from(fs.readFileSync(fixture, 'utf8').trim(), 'base64');

test('reads a real DER certificate', () => {
  const cert = parseCertificate(der);
  assert.equal(cert.version, 3);
  assert.equal(cert.subject.CN, 'example.com');
  assert.match(cert.issuer.CN, /Cloudflare|SSL/);
  assert.ok(cert.notBefore instanceof Date);
  assert.ok(cert.notAfter instanceof Date);
  assert.ok(cert.notAfter > cert.notBefore);
  assert.equal(cert.sigAlgName, 'ecdsa-with-SHA256');
  assert.equal(cert.sigAlgo, 'ecdsa');
  assert.equal(cert.sigHash, 'sha256');
  assert.equal(cert.publicKey.algorithm, 'ecdsa');
  assert.equal(cert.publicKey.bits, 256);
  assert.match(cert.publicKey.curve, /P-256/);
  assert.deepEqual(cert.san, ['example.com', '*.example.com']);
  assert.equal(cert.isCA, false);
  assert.equal(cert.derLength, der.length);
  assert.ok(cert.signatureBytes > 0);
});

test('rejects input that is not a certificate', () => {
  assert.throws(() => parseCertificate(Buffer.from('not a certificate')), /DER|X\.509/);
  assert.throws(() => parseCertificate(Buffer.from([0x02, 0x01, 0x01])), /DER|X\.509/);
});

test('TLV reader handles short and long form lengths', () => {
  const short = readTLV(Buffer.from([0x04, 0x03, 0x61, 0x62, 0x63]), 0);
  assert.equal(short.tag, TAG.OCTET_STRING);
  assert.equal(short.length, 3);
  assert.equal(short.headerLen, 2);

  const long = Buffer.concat([Buffer.from([0x04, 0x81, 0x80]), Buffer.alloc(128)]);
  const parsed = readTLV(long, 0);
  assert.equal(parsed.length, 128);
  assert.equal(parsed.headerLen, 3);
  assert.equal(parsed.valueStart, 3);
});

test('primitive decoders work on real fields', () => {
  const cert = parseCertificate(der);
  assert.equal(typeof cert.serialNumber, 'string');
  assert.ok(cert.serialNumber.length > 0);
  assert.equal(sigAlgFromOid('1.2.840.10045.4.3.2').name, 'ecdsa-with-SHA256');
  assert.equal(sigAlgFromOid('1.2.840.113549.1.1.11').name, 'sha256WithRSAEncryption');
  assert.ok(OID['1.2.840.10045.2.1']);
  assert.equal(OID['1.2.840.10045.2.1'].algo, 'ecdsa');
});

test('integer and string decoders handle length boundaries', () => {
  const intBuf = Buffer.from([0x02, 0x01, 0x2a]);
  assert.equal(decodeInteger(intBuf, readTLV(intBuf, 0)), 42n);

  const strBuf = Buffer.from([0x0c, 0x02, 0x68, 0x69]);
  assert.equal(decodeString(strBuf, readTLV(strBuf, 0)), 'hi');

  const timeBuf = Buffer.from('20260101120000Z', 'latin1');
  const timeNode = {
    tag: TAG.UTC_TIME,
    valueStart: 0,
    valueEnd: timeBuf.length,
  };
  const date = decodeTime(timeBuf, timeNode);
  assert.equal(date.toISOString(), '2026-01-01T12:00:00.000Z');
});
