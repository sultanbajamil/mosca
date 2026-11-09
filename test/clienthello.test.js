/**
 * The raw prober is the part of MOSCA that Node's own TLS stack cannot do:
 * build a ClientHello that offers X25519MLKEM768 and read back the group the
 * server chose. These tests exercise the wire format without a network.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import {
  buildClientHello,
  parseServerHello,
  parseServerFlight,
  canonicalMlKemEk,
  groupPosture,
  versionName,
  GROUPS,
  OFFERED_GROUPS,
} from '../src/net/clienthello.js';

const u16 = (n) => {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n, 0);
  return b;
};

function readClientHello(buf) {
  assert.equal(buf[0], 0x16, 'record type must be handshake');
  assert.equal(buf.readUInt16BE(1), 0x0301, 'legacy record version');
  assert.equal(buf[5], 0x01, 'handshake type must be ClientHello');
  const hsLen = (buf[6] << 16) | (buf[7] << 8) | buf[8];

  let p = 9;
  const legacyVersion = buf.readUInt16BE(p);
  p += 2;
  const random = buf.subarray(p, p + 32);
  p += 32;
  const sidLen = buf[p];
  p += 1 + sidLen;
  const cipherLen = buf.readUInt16BE(p);
  p += 2;
  const cipherBytes = buf.subarray(p, p + cipherLen);
  p += cipherLen;
  const compLen = buf[p];
  p += 1 + compLen;
  const extLen = buf.readUInt16BE(p);
  p += 2;
  const extEnd = p + extLen;

  const extensions = [];
  while (p + 4 <= extEnd) {
    const type = buf.readUInt16BE(p);
    const len = buf.readUInt16BE(p + 2);
    p += 4;
    extensions.push({ type, data: buf.subarray(p, p + len) });
    p += len;
  }

  return { legacyVersion, random, cipherBytes, extensions, hsLen, declaredExtLen: extLen, extEnd };
}

function extensionOf(extensions, type) {
  return extensions.find((e) => e.type === type)?.data || null;
}

function syntheticServerHello({ version = 0x0304, group = 0x11ec, alpn = 'h2', hrr = false } = {}) {
  const exts = [];
  if (group !== null) exts.push(Buffer.concat([u16(0x0033), u16(2), u16(group)]));
  if (version !== null) exts.push(Buffer.concat([u16(0x002b), u16(2), u16(version)]));
  if (alpn) {
    const label = Buffer.from(alpn, 'latin1');
    const inner = Buffer.concat([u16(label.length + 1), Buffer.from([label.length]), label]);
    exts.push(Buffer.concat([u16(0x0010), u16(inner.length), inner]));
  }
  const extBlock = Buffer.concat(exts);
  const random = hrr ? Buffer.from('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c', 'hex') : crypto.randomBytes(32);

  return Buffer.concat([
    u16(0x0303),
    random,
    Buffer.from([0]), // empty session id
    u16(0x1302),
    Buffer.from([0]), // null compression
    u16(extBlock.length),
    extBlock,
  ]);
}

test('ClientHello is a well-formed TLS handshake record', () => {
  const buf = buildClientHello({ host: 'example.com' });
  const parsed = readClientHello(buf);
  assert.equal(parsed.legacyVersion, 0x0303);
  assert.equal(parsed.random.length, 32);
  // The body length declared in the handshake header must match the record.
  assert.equal(9 + parsed.hsLen, buf.length);
  assert.equal(parsed.extEnd, buf.length);
});

test('ClientHello offers SNI, protocols, groups and a full key share', () => {
  const buf = buildClientHello({ host: 'mosca.example' });
  const { extensions } = readClientHello(buf);

  const sni = extensionOf(extensions, 0x0000);
  assert.ok(sni, 'server_name extension missing');
  assert.ok(sni.includes(Buffer.from('mosca.example')), 'SNI host missing');

  const versions = extensionOf(extensions, 0x002b);
  assert.ok(versions);
  assert.equal(versions[0], 4, 'two supported versions');
  assert.equal(versions.readUInt16BE(1), 0x0304);

  const groups = extensionOf(extensions, 0x000a);
  assert.ok(groups);
  const groupLen = groups.readUInt16BE(0);
  const offered = [];
  for (let i = 2; i < 2 + groupLen; i += 2) offered.push(groups.readUInt16BE(i));
  assert.equal(offered[0], 0x11ec, 'X25519MLKEM768 must be first');
  assert.deepEqual(offered, OFFERED_GROUPS);

  // key_share: list length, then [group, length, payload] per group.
  const share = extensionOf(extensions, 0x0033);
  assert.ok(share);
  let p = 2;
  const sizes = new Map();
  while (p < share.length) {
    const group = share.readUInt16BE(p);
    const len = share.readUInt16BE(p + 2);
    sizes.set(group, len);
    p += 4 + len;
  }
  assert.equal(sizes.get(0x11ec), 1216, 'ML-KEM-768 ek (1184) + X25519 (32)');
  assert.equal(sizes.get(0x001d), 32);
  assert.equal(sizes.get(0x0017), 65);
  assert.equal(p, share.length, 'key_share list length is consistent');
});

test('ML-KEM encapsulation keys are canonical', () => {
  const ek = canonicalMlKemEk(1184);
  assert.equal(ek.length, 1184);
  const coeffBytes = ek.length - 32;
  let checked = 0;
  for (let i = 0; i + 2 < coeffBytes; i += 3) {
    const a = ek[i] | ((ek[i + 1] & 0x0f) << 8);
    const b = (ek[i + 1] >> 4) | (ek[i + 2] << 4);
    assert.ok(a < 3329, `coefficient ${a} at ${i} is not canonical`);
    assert.ok(b < 3329, `coefficient ${b} at ${i + 1} is not canonical`);
    checked += 2;
  }
  assert.equal(checked, 768, 'ML-KEM-768 has 768 coefficients');
});

test('parseServerHello reads version, cipher, group and ALPN', () => {
  const body = syntheticServerHello({ version: 0x0304, group: 0x11ec, alpn: 'h2' });
  const parsed = parseServerHello(body);
  assert.equal(parsed.version, 0x0304);
  assert.equal(parsed.cipherSuite, 0x1302);
  assert.equal(parsed.group, 0x11ec);
  assert.equal(parsed.alpn, 'h2');
  assert.equal(parsed.hrr, false);
});

test('parseServerHello detects a HelloRetryRequest', () => {
  const body = syntheticServerHello({ hrr: true, group: null, version: null });
  const parsed = parseServerHello(body);
  assert.equal(parsed.hrr, true);
});

test('parseServerFlight walks records and finds an alert', () => {
  const sh = syntheticServerHello({ group: 0x11ec });
  const handshake = Buffer.concat([Buffer.from([0x02]), Buffer.from([0, 0, sh.length]), sh]);
  const record = Buffer.concat([Buffer.from([0x16]), u16(0x0303), u16(handshake.length), handshake]);

  const parsed = parseServerFlight(record);
  assert.ok(parsed.serverHello);
  assert.equal(parsed.serverHello.group, 0x11ec);
  assert.equal(parsed.serverHello.version, 0x0304);

  const alert = parseServerFlight(Buffer.from([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]));
  assert.deepEqual(alert.alert, { level: 2, description: 40 });
});

test('group posture distinguishes hybrid from classical', () => {
  const hybrid = groupPosture(0x11ec);
  assert.equal(hybrid.hybrid, true);
  assert.equal(hybrid.status, 'safe');
  assert.equal(hybrid.label, 'X25519+ML-KEM-768');

  const classical = groupPosture(0x001d);
  assert.equal(classical.hybrid, false);
  assert.equal(classical.status, 'broken');

  assert.equal(groupPosture(null).hybrid, false);
  assert.equal(groupPosture(0xabcd).status, 'unknown');
});

test('versionName covers the TLS ladder', () => {
  assert.equal(versionName(0x0301), 'TLS 1.0');
  assert.equal(versionName(0x0303), 'TLS 1.2');
  assert.equal(versionName(0x0304), 'TLS 1.3');
  assert.equal(versionName(null), 'unknown');
  assert.equal(GROUPS[0x11ec].name, 'X25519MLKEM768');
});
