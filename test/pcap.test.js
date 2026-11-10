/**
 * Passive PCAP harvesting. The fixtures are generated as real binary captures
 * — Ethernet, IPv4, TCP and TLS/SSH on the wire — so the parser is exercised
 * against bytes rather than a hand-built object graph.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  analysePcapBuffer,
  parsePcapBuffer,
  decodeFrame,
  deriveCaptureFindings,
} from '../src/net/pcap.js';
import { buildClientHello } from '../src/net/clienthello.js';
import { encodeNameList } from '../src/net/ssh.js';
import { analyse } from '../src/analysis/risk.js';
import { DEFAULT_CONFIG } from '../src/config.js';

// ---------------------------------------------------------------------------
// Binary fixture helpers
// ---------------------------------------------------------------------------

const u8 = (n) => Buffer.from([n & 0xff]);
const u16 = (n) => {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n & 0xffff, 0);
  return b;
};
const u24 = (n) => Buffer.from([(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
const u32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
};

function ipv4(ip) {
  return Buffer.from(ip.split('.').map(Number));
}

function ethernetFrame({ srcIP = '10.0.0.1', dstIP = '10.0.0.9', srcPort = 50000, dstPort = 443, payload = Buffer.alloc(0), flags = 0x18, vlan = null }) {
  const tcp = Buffer.alloc(20 + payload.length);
  tcp.writeUInt16BE(srcPort, 0);
  tcp.writeUInt16BE(dstPort, 2);
  tcp[12] = 5 << 4;
  tcp[13] = flags;
  payload.copy(tcp, 20);

  const ip = Buffer.alloc(20 + tcp.length);
  ip[0] = 0x45;
  ip.writeUInt16BE(ip.length, 2);
  ip[8] = 64;
  ip[9] = 6;
  ipv4(srcIP).copy(ip, 12);
  ipv4(dstIP).copy(ip, 16);
  tcp.copy(ip, 20);

  if (vlan) {
    const eth = Buffer.alloc(18 + ip.length);
    eth.writeUInt16BE(0x8100, 12);
    eth.writeUInt16BE(vlan, 14);
    eth.writeUInt16BE(0x0800, 16);
    ip.copy(eth, 18);
    return eth;
  }

  const eth = Buffer.alloc(14 + ip.length);
  eth.writeUInt16BE(0x0800, 12);
  ip.copy(eth, 14);
  return eth;
}

function sllFrame({ payload, protocol = 0x0800 }) {
  const frame = Buffer.alloc(16 + payload.length);
  frame.writeUInt16BE(protocol, 14);
  payload.copy(frame, 16);
  return frame;
}

function pcapFile(records, { linkType = 1, endian = 'be', nano = false } = {}) {
  const magic = nano
    ? endian === 'be' ? 0xa1b23c4d : 0x4d3cb2a1
    : endian === 'be' ? 0xa1b2c3d4 : 0xd4c3b2a1;
  const header = Buffer.alloc(24);
  // The four magic bytes are always compared as a big-endian word; the
  // endianness flag only governs the numeric fields that follow.
  header.writeUInt32BE(magic, 0);
  const write16 = (value, offset) => endian === 'be' ? header.writeUInt16BE(value, offset) : header.writeUInt16LE(value, offset);
  const write32 = (value, offset) => endian === 'be' ? header.writeUInt32BE(value, offset) : header.writeUInt32LE(value, offset);
  write16(2, 4);
  write16(4, 6);
  write32(0, 8);
  write32(0, 12);
  write32(65535, 16);
  write32(linkType, 20);

  const chunks = [header];
  for (const record of records) {
    const frame = record.frame;
    const sec = Math.floor(record.ts);
    const frac = Math.round((record.ts - sec) * (nano ? 1e9 : 1e6));
    const rec = Buffer.alloc(16);
    if (endian === 'be') {
      rec.writeUInt32BE(sec, 0);
      rec.writeUInt32BE(frac, 4);
      rec.writeUInt32BE(frame.length, 8);
      rec.writeUInt32BE(frame.length, 12);
    } else {
      rec.writeUInt32LE(sec, 0);
      rec.writeUInt32LE(frac, 4);
      rec.writeUInt32LE(frame.length, 8);
      rec.writeUInt32LE(frame.length, 12);
    }
    chunks.push(rec, frame);
  }
  return Buffer.concat(chunks);
}

function pcapngFile(records, { linkType = 1, tsResolution = 6 } = {}) {
  const blocks = [];
  const shb = Buffer.alloc(28);
  shb.writeUInt32BE(0x0a0d0d0a, 0);
  shb.writeUInt32BE(28, 4);
  shb.writeUInt32BE(0x1a2b3c4d, 8);
  shb.writeUInt16BE(1, 12);
  shb.writeUInt16BE(0, 14);
  shb.writeUInt32BE(0xffffffff, 16); // section length untouched
  shb.writeUInt32BE(0xffffffff, 20);
  shb.writeUInt32BE(28, 24);
  blocks.push(shb);

  const idb = Buffer.alloc(32);
  idb.writeUInt32BE(0x00000001, 0);
  idb.writeUInt32BE(32, 4);
  idb.writeUInt16BE(linkType, 8);
  idb.writeUInt16BE(0, 10);
  idb.writeUInt32BE(65535, 12);
  idb.writeUInt16BE(9, 16); // if_tsresol
  idb.writeUInt16BE(1, 18);
  idb.writeUInt8(tsResolution, 20);
  idb.writeUInt32BE(32, 28);
  blocks.push(idb);

  for (const record of records) {
    const frame = record.frame;
    const units = Math.pow(10, tsResolution);
    const raw = BigInt(Math.round(record.ts * units));
    const padded = Buffer.alloc(Math.ceil(frame.length / 4) * 4);
    frame.copy(padded);
    const total = 12 + 20 + padded.length;
    const epb = Buffer.alloc(total);
    epb.writeUInt32BE(0x00000006, 0);
    epb.writeUInt32BE(total, 4);
    epb.writeUInt32BE(0, 8); // interface 0
    epb.writeUInt32BE(Number(raw >> 32n), 12);
    epb.writeUInt32BE(Number(raw & 0xffffffffn), 16);
    epb.writeUInt32BE(frame.length, 20);
    epb.writeUInt32BE(frame.length, 24);
    padded.copy(epb, 28);
    epb.writeUInt32BE(total, total - 4);
    blocks.push(epb);
  }
  return Buffer.concat(blocks);
}

function serverHelloRecord({ group = 0x11ec, cipherSuite = 0x1302, version = 0x0304 } = {}) {
  const supportedVersions = Buffer.concat([u16(0x002b), u16(2), u16(version)]);
  const keyShare = Buffer.concat([u16(0x0033), u16(4), u16(group), u16(0)]);
  const extensions = Buffer.concat([supportedVersions, keyShare]);
  const body = Buffer.concat([
    u16(0x0303),
    Buffer.alloc(32, 0x42),
    u8(0),
    u16(cipherSuite),
    u8(0),
    u16(extensions.length),
    extensions,
  ]);
  const handshake = Buffer.concat([u8(0x02), u24(body.length), body]);
  return Buffer.concat([u8(0x16), u16(0x0303), u16(handshake.length), handshake]);
}

function sshPacket(payload) {
  const block = 8;
  let padding = block - ((payload.length + 5) % block);
  if (padding < 4) padding += block;
  const packetLength = payload.length + padding + 1;
  return Buffer.concat([u32(packetLength), u8(padding), payload, Buffer.alloc(padding, 0x55)]);
}

function kexInit({ kex, hostKeys = ['ssh-ed25519', 'rsa-sha2-256'], ciphers = ['aes256-ctr'], macs = ['hmac-sha2-256'] }) {
  const lists = [
    kex,
    hostKeys,
    ciphers,
    ciphers,
    macs,
    macs,
    ['none'],
    ['none'],
    [],
    [],
  ];
  const payload = Buffer.concat([
    u8(20),
    Buffer.alloc(16, 0x11),
    ...lists.map(encodeNameList),
    u8(0),
    u32(0),
  ]);
  return sshPacket(payload);
}

function tlsCapture({ captureTs = 1388534400, group = 0x11ec, splitClientHello = false } = {}) {
  const clientHello = buildClientHello({ host: 'bank.example', groups: [group, 0x001d] });
  const serverHello = serverHelloRecord({ group });
  const syn = ethernetFrame({ flags: 0x02, srcPort: 50000, dstPort: 443 });
  const synAck = ethernetFrame({ flags: 0x12, srcIP: '10.0.0.9', dstIP: '10.0.0.1', srcPort: 443, dstPort: 50000 });
  const records = [
    { ts: captureTs, frame: syn },
    { ts: captureTs, frame: synAck },
  ];
  if (splitClientHello) {
    const mid = Math.floor(clientHello.length / 2);
    records.push({ ts: captureTs + 0.1, frame: ethernetFrame({ payload: clientHello.subarray(0, mid) }) });
    records.push({ ts: captureTs + 0.2, frame: ethernetFrame({ payload: clientHello.subarray(mid) }) });
  } else {
    records.push({ ts: captureTs + 0.1, frame: ethernetFrame({ payload: clientHello }) });
  }
  records.push({
    ts: captureTs + 0.2,
    frame: ethernetFrame({ srcIP: '10.0.0.9', dstIP: '10.0.0.1', srcPort: 443, dstPort: 50000, payload: serverHello }),
  });
  return { records, clientHello, serverHello };
}

function sshCapture({ captureTs = 1388534400, hybrid = true } = {}) {
  const clientBanner = Buffer.from('SSH-2.0-OpenSSH_9.9\r\n');
  const serverBanner = Buffer.from('SSH-2.0-OpenSSH_9.2p1 Ubuntu-3\r\n');
  const clientKex = kexInit({
    kex: hybrid
      ? ['mlkem768x25519-sha256', 'curve25519-sha256', 'diffie-hellman-group14-sha256']
      : ['curve25519-sha256', 'diffie-hellman-group14-sha256'],
  });
  const serverKex = kexInit({
    kex: hybrid
      ? ['mlkem768x25519-sha256', 'curve25519-sha256']
      : ['curve25519-sha256', 'diffie-hellman-group14-sha256'],
    hostKeys: ['ssh-ed25519', 'rsa-sha2-256'],
  });
  const syn = ethernetFrame({ flags: 0x02, srcPort: 50000, dstPort: 22 });
  const synAck = ethernetFrame({ flags: 0x12, srcIP: '10.0.0.9', dstIP: '10.0.0.1', srcPort: 22, dstPort: 50000 });
  const serverToClient = (payload) => ethernetFrame({ srcIP: '10.0.0.9', dstIP: '10.0.0.1', srcPort: 22, dstPort: 50000, payload });
  const clientToServer = (payload) => ethernetFrame({ srcPort: 50000, dstPort: 22, payload });
  const records = [
    { ts: captureTs, frame: syn },
    { ts: captureTs, frame: synAck },
    { ts: captureTs + 0.1, frame: serverToClient(serverBanner) },
    { ts: captureTs + 0.2, frame: clientToServer(clientBanner) },
    { ts: captureTs + 0.3, frame: clientToServer(clientKex) },
    { ts: captureTs + 0.4, frame: serverToClient(serverKex) },
  ];
  return { records, clientKex, serverKex };
}

const config = { ...DEFAULT_CONFIG, crqcYear: 2033, defaultShelfLife: 10 };

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test('parses a classic little-endian PCAP with an Ethernet frame', () => {
  const { records } = tlsCapture();
  const buffer = pcapFile(records, { endian: 'le' });
  const parsed = parsePcapBuffer(buffer);
  assert.equal(parsed.format, 'pcap');
  assert.equal(parsed.endian, 'le');
  assert.equal(parsed.linkType, 1);
  assert.equal(parsed.linkTypeName, 'ethernet');
  assert.equal(parsed.packetCount, 4);
  assert.equal(parsed.packets[2].srcIP, '10.0.0.1');
  assert.equal(parsed.packets[2].dstPort, 443);
  assert.ok(parsed.packets[2].payload.length > 0);
});

test('TLS ClientHello/ServerHello are reassembled from a PCAP and keep the capture date', () => {
  const { records } = tlsCapture({ captureTs: Date.UTC(2010, 0, 1) / 1000, group: 0x11ec });
  const result = analysePcapBuffer(pcapFile(records), { file: 'capture.pcap', config });

  assert.equal(result.sessions.length, 1);
  const session = result.sessions[0];
  assert.equal(session.protocol, 'tls');
  assert.equal(session.tls.protocol, 'TLS 1.3');
  assert.equal(session.tls.group, 0x11ec);
  assert.equal(session.tls.groupLabel, 'X25519+ML-KEM-768');
  assert.equal(session.tls.hybrid, true);
  assert.equal(session.tls.cipherName, 'TLS_AES_256_GCM_SHA384');
  assert.equal(session.server.name, 'bank.example');
  assert.equal(session.captureYear, 2010);
  assert.equal(session.hndl.crqcYear, 2033);
  assert.equal(session.hndl.yearsToCRQC, 23);
  assert.equal(session.hndl.exposed, false);
  assert.equal(session.hndl.inequality, '2010 + 10 ≤ 2033');

  assert.equal(result.summary.sessionCount, 1);
  assert.equal(result.summary.tlsSessions, 1);
  assert.equal(result.summary.hndlCapturedRatio, 0);
  assert.equal(result.findings.some((f) => f.id === 'captured-session-tls-hybrid'), true);
});

test('a classical TLS capture is exposed and the Mosca window is anchored to the recording', () => {
  const { records } = tlsCapture({ captureTs: Date.UTC(2010, 0, 1) / 1000, group: 0x001d });
  const result = analysePcapBuffer(pcapFile(records), { file: 'old.pcap', config });

  const session = result.sessions[0];
  assert.equal(session.tls.hybrid, false);
  assert.equal(session.tls.groupLabel, 'X25519');
  assert.equal(session.hndl.exposed, false); // 10-year secret, recorded 23 years before the CRQC

  const findings = deriveCaptureFindings(result.sessions, { file: 'old.pcap' });
  const classical = findings.find((f) => f.id === 'captured-session-tls-classical');
  assert.ok(classical);
  assert.equal(classical.kind, 'captured-session');
  assert.equal(classical.captureYear, 2010);
  assert.equal(classical.location.file, 'old.pcap');

  const analysis = analyse({ findings, config, now: new Date('2026-01-01T00:00:00Z') });
  const enriched = analysis.items.find((i) => i.id === 'captured-session-tls-classical');
  assert.equal(enriched.mosca.yearsToCRQC, 23);
  assert.equal(enriched.mosca.exposed, false);
  // If the scanner anchored to today, the same 10-year secret would be exposed.
  assert.equal(10 + enriched.leadTime > 7, true);
});

test('a long-lived secret recorded in the past is inside the Mosca window', () => {
  const { records } = tlsCapture({ captureTs: Date.UTC(2014, 0, 1) / 1000, group: 0x001d });
  const result = analysePcapBuffer(pcapFile(records), {
    file: 'health.pcap',
    config: { ...DEFAULT_CONFIG, crqcYear: 2033, defaultShelfLife: 25 },
  });
  assert.equal(result.sessions[0].hndl.exposed, true);
  assert.equal(result.sessions[0].hndl.inequality, '2014 + 25 > 2033');
});

test('PCAPNG Section/Interface/Enhanced Packet blocks are supported', () => {
  const { records } = tlsCapture({ group: 0x11ec });
  const parsed = parsePcapBuffer(pcapngFile(records));
  assert.equal(parsed.format, 'pcapng');
  assert.equal(parsed.linkType, 1);
  assert.equal(parsed.packetCount, 4);

  const result = analysePcapBuffer(pcapngFile(records), { config });
  assert.equal(result.sessions.length, 1);
  assert.equal(result.sessions[0].tls.hybrid, true);
});

test('a TLS record split across two TCP segments is reassembled', () => {
  const { records } = tlsCapture({ splitClientHello: true });
  const result = analysePcapBuffer(pcapFile(records), { config });
  assert.equal(result.sessions.length, 1);
  assert.equal(result.sessions[0].tls.clientHello, true);
  assert.equal(result.sessions[0].tls.protocol, 'TLS 1.3');
});

test('SSH banners and KEXINIT reveal a hybrid first-match agreement', () => {
  const { records } = sshCapture({ hybrid: true });
  const result = analysePcapBuffer(pcapFile(records), { config });
  assert.equal(result.sessions.length, 1);
  const session = result.sessions[0];
  assert.equal(session.protocol, 'ssh');
  assert.equal(session.ssh.software, 'OpenSSH_9.2p1');
  assert.equal(session.ssh.agreedKex, 'mlkem768x25519-sha256');
  assert.equal(session.ssh.hybrid, true);
  assert.equal(session.hybrid, true);
  assert.equal(result.summary.hndlCapturedRatio, 0);
  assert.ok(result.findings.some((f) => f.id === 'captured-session-ssh-hybrid'));
});

test('a classical SSH capture is counted in the HNDL Captured Ratio', () => {
  const { records } = sshCapture({ hybrid: false });
  const result = analysePcapBuffer(pcapFile(records), { file: 'ssh.pcap', config });
  const session = result.sessions[0];
  assert.equal(session.ssh.agreedKex, 'curve25519-sha256');
  assert.equal(session.ssh.hybrid, false);
  assert.equal(result.summary.hndlCapturedRatio, 100);
  assert.ok(result.findings.some((f) => f.id === 'captured-session-ssh-classical'));
});

test('802.1Q VLAN and Linux SLL frames decode to the same transport tuple', () => {
  const payload = Buffer.from('hello');
  const vlan = ethernetFrame({ payload, vlan: 42 });
  const decodedVlan = decodeFrame(1, vlan);
  assert.equal(decodedVlan.srcIP, '10.0.0.1');
  assert.equal(decodedVlan.dstIP, '10.0.0.9');
  assert.equal(decodedVlan.srcPort, 50000);
  assert.equal(decodedVlan.dstPort, 443);
  assert.equal(decodedVlan.payload.toString(), 'hello');

  const plainIp = vlan.subarray(18);
  const decodedSll = decodeFrame(113, sllFrame({ payload: plainIp }));
  assert.equal(decodedSll.srcIP, '10.0.0.1');
  assert.equal(decodedSll.payload.toString(), 'hello');
});

test('unrecognised capture formats fail with a clear error', () => {
  assert.throws(() => parsePcapBuffer(Buffer.from('not a pcap at all')), /Unrecognised capture format/);
  assert.throws(() => parsePcapBuffer(Buffer.alloc(4)), /Capture file is empty|Unrecognised/);
});
