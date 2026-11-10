/**
 * QUIC Initial protection is easy to get subtly wrong and impossible to
 * debug against a live server. The tests therefore pin the implementation to
 * the RFC 9001 Appendix A.1 key schedule, then round-trip a packet and parse
 * a synthetic server Initial carrying a hybrid ServerHello.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import {
  QUIC_V1_SALT,
  deriveInitialKeys,
  hkdfExtract,
  hkdfExpandLabel,
  headerProtectionMask,
  protectInitialPacket,
  unprotectInitialPacket,
  parseFrames,
  parseCryptoHandshake,
  parseServerInitial,
  deriveQuicFindings,
} from '../src/net/quic.js';
import { quicVarint } from '../src/net/clienthello.js';

const u16 = (n) => {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n, 0);
  return b;
};

function syntheticServerHelloBody({ version = 0x0304, group = 0x11ec } = {}) {
  const exts = [
    Buffer.concat([u16(0x0033), u16(2), u16(group)]),
    Buffer.concat([u16(0x002b), u16(2), u16(version)]),
  ];
  const extBlock = Buffer.concat(exts);
  return Buffer.concat([
    u16(0x0303),
    crypto.randomBytes(32),
    Buffer.from([0]),
    u16(0x1302),
    Buffer.from([0]),
    u16(extBlock.length),
    extBlock,
  ]);
}

function cryptoFrame(data) {
  return Buffer.concat([Buffer.from([0x06]), quicVarint(0), quicVarint(data.length), data]);
}

test('RFC 9001 Appendix A.1 initial keys are reproduced exactly', () => {
  const dcid = Buffer.from('8394c8f03e515708', 'hex');
  const keys = deriveInitialKeys(dcid);
  assert.equal(QUIC_V1_SALT.length, 20);
  assert.equal(keys.client.secret.toString('hex'), 'c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea');
  assert.equal(keys.client.key.toString('hex'), '1f369613dd76d5467730efcbe3b1a22d');
  assert.equal(keys.client.iv.toString('hex'), 'fa044b2f42a3fd3b46fb255c');
  assert.equal(keys.client.hp.toString('hex'), '9f50449e04a0e810283a1e9933adedd2');
  assert.equal(keys.server.secret.toString('hex'), '3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b');
  assert.equal(keys.server.key.toString('hex'), 'cf3a5331653c364c88f0f379b6067e37');
  assert.equal(keys.server.iv.toString('hex'), '0ac1493ca1905853b0bba03e');
  assert.equal(keys.server.hp.toString('hex'), 'c206b8d9b9f0f37644430b490eeaa314');
});

test('HKDF helpers agree with the key schedule', () => {
  const dcid = Buffer.from('8394c8f03e515708', 'hex');
  const initial = hkdfExtract(QUIC_V1_SALT, dcid);
  assert.equal(initial.toString('hex'), '7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44');
  assert.equal(hkdfExpandLabel(initial, 'client in', Buffer.alloc(0), 32).toString('hex'), 'c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea');
});

test('header protection mask is a 16-byte AES-ECB block', () => {
  const dcid = Buffer.from('8394c8f03e515708', 'hex');
  const { hp } = deriveInitialKeys(dcid).client;
  const mask = headerProtectionMask(hp, Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex'));
  assert.equal(mask.length, 16);
});

test('Initial packet protection round-trips and restores the payload', () => {
  const dcid = crypto.randomBytes(8);
  const scid = crypto.randomBytes(8);
  const keys = deriveInitialKeys(dcid).client;
  const payload = cryptoFrame(Buffer.from('hello quic'));
  const { packet, pnOffset } = protectInitialPacket({ payload, dcid, scid, keys, packetNumber: 0, pnLength: 4 });
  assert.equal(packet[0] & 0x80, 0x80, 'long header bit');
  assert.equal(packet.readUInt32BE(1), 1, 'QUIC v1');

  const parsed = unprotectInitialPacket(packet, keys);
  assert.equal(parsed.type, 'initial');
  assert.equal(parsed.packetNumber, 0);
  assert.deepEqual(parsed.payload, payload);
  assert.ok(pnOffset > 0);
});

test('CRYPTO frames and TLS handshake messages are reassembled', () => {
  const hello = Buffer.concat([Buffer.from([0x02]), Buffer.from([0, 0, 4]), Buffer.from('body')]);
  const frames = parseFrames(cryptoFrame(hello));
  assert.deepEqual(frames.crypto, hello);
  const messages = parseCryptoHandshake(frames.crypto);
  assert.equal(messages.length, 1);
  assert.equal(messages[0].type, 0x02);
});

test('a synthetic server Initial yields the negotiated hybrid group', () => {
  const clientDcid = crypto.randomBytes(8);
  const serverKeys = deriveInitialKeys(clientDcid).server;
  const helloBody = syntheticServerHelloBody({ group: 0x11ec });
  const handshake = Buffer.concat([Buffer.from([0x02]), Buffer.from([0, 0, helloBody.length]), helloBody]);
  const payload = cryptoFrame(handshake);

  const { packet } = protectInitialPacket({
    payload,
    dcid: crypto.randomBytes(8),
    scid: crypto.randomBytes(8),
    keys: serverKeys,
    packetNumber: 1,
    pnLength: 4,
  });

  const parsed = parseServerInitial(packet, clientDcid);
  assert.equal(parsed.type, 'initial');
  assert.ok(parsed.serverHello);
  assert.equal(parsed.serverHello.group, 0x11ec);
  assert.equal(parsed.serverHello.version, 0x0304);
});

test('a Version Negotiation packet is recognised', () => {
  const dcid = Buffer.from('0102030405060708', 'hex');
  const scid = Buffer.from('1112131415161718', 'hex');
  const packet = Buffer.concat([
    Buffer.from([0xc0, 0, 0, 0, 0]),
    Buffer.from([dcid.length]),
    dcid,
    Buffer.from([scid.length]),
    scid,
    Buffer.from([0, 0, 0, 1, 0x6b, 0x33, 0x43, 0xcf]),
  ]);
  const parsed = unprotectInitialPacket(packet, {});
  assert.equal(parsed.type, 'version-negotiation');
  assert.deepEqual(parsed.versions, [1, 0x6b3343cf]);
});

test('QUIC findings distinguish hybrid from classical', () => {
  const hybrid = deriveQuicFindings({
    reachable: true,
    host: 'example.com',
    port: 443,
    target: 'quic://example.com',
    group: 0x11ec,
    groupLabel: 'X25519+ML-KEM-768',
    hybrid: true,
  });
  assert.equal(hybrid[0].id, 'quic-hybrid-kex');
  assert.equal(hybrid[0].positive, true);

  const classical = deriveQuicFindings({
    reachable: true,
    host: 'example.com',
    port: 443,
    target: 'quic://example.com',
    group: 0x001d,
    groupLabel: 'X25519',
    hybrid: false,
  });
  assert.equal(classical[0].id, 'quic-classical-kex');
  assert.equal(classical[0].algorithm, 'x25519');
});
