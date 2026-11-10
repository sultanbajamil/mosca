/**
 * STARTTLS probes are only useful if they speak each protocol's preamble
 * correctly. These tests run a local SMTP and PostgreSQL server, perform the
 * real upgrade exchange, and assert that the raw ClientHello still reaches
 * the server and its ServerHello is parsed.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import crypto from 'node:crypto';

import { inspectStarttls, parseStarttlsTarget, deriveStarttlsFindings, STARTTLS_PROTOCOLS } from '../src/net/starttls.js';

const u16 = (n) => {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n, 0);
  return b;
};

function syntheticServerHello({ version = 0x0304, group = 0x11ec } = {}) {
  const exts = [
    Buffer.concat([u16(0x0033), u16(2), u16(group)]),
    Buffer.concat([u16(0x002b), u16(2), u16(version)]),
  ];
  const extBlock = Buffer.concat(exts);
  const body = Buffer.concat([
    u16(0x0303),
    crypto.randomBytes(32),
    Buffer.from([0]),
    u16(0x1302),
    Buffer.from([0]),
    u16(extBlock.length),
    extBlock,
  ]);
  const handshake = Buffer.concat([Buffer.from([0x02]), Buffer.from([0, 0, body.length]), body]);
  return Buffer.concat([Buffer.from([0x16]), u16(0x0303), u16(handshake.length), handshake]);
}

function listen(server) {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

test('parseStarttlsTarget understands schemes, defaults and explicit ports', () => {
  assert.deepEqual(parseStarttlsTarget('smtp://mail.example.com'), {
    protocol: 'smtp',
    host: 'mail.example.com',
    port: 587,
    servername: 'mail.example.com',
  });
  const imap = parseStarttlsTarget('imap://127.0.0.1:1143');
  assert.equal(imap.protocol, 'imap');
  assert.equal(imap.port, 1143);
  assert.equal(imap.servername, undefined);

  const postgres = parseStarttlsTarget('db.example.com:5433', 'postgres');
  assert.equal(postgres.protocol, 'postgres');
  assert.equal(postgres.port, 5433);
  assert.equal(STARTTLS_PROTOCOLS.ldap.defaultPort, 389);
  assert.throws(() => parseStarttlsTarget('gopher://x'), /unsupported STARTTLS protocol/);
});

test('SMTP upgrade is negotiated before the raw ClientHello', async () => {
  const server = net.createServer((socket) => {
    let text = '';
    let ehlo = false;
    let starttls = false;
    let tls = false;
    socket.write('220 mosca.test ESMTP\r\n');
    socket.on('data', (chunk) => {
      if (tls) {
        socket.write(syntheticServerHello());
        return;
      }
      text += chunk.toString('latin1');
      if (!ehlo && text.includes('EHLO')) {
        ehlo = true;
        socket.write('250-mosca.test\r\n250 STARTTLS\r\n');
      }
      if (ehlo && !starttls && text.includes('STARTTLS')) {
        starttls = true;
        socket.write('220 2.0.0 Ready to start TLS\r\n');
        tls = true;
      }
    });
  });
  const port = await listen(server);
  try {
    const result = await inspectStarttls(`smtp://127.0.0.1:${port}`, { timeout: 3000 });
    assert.equal(result.reachable, true);
    assert.equal(result.upgraded, true);
    assert.equal(result.version, 0x0304);
    assert.equal(result.group, 0x11ec);
    assert.equal(result.hybrid, true);
    assert.ok(result.findings.some((f) => f.id === 'starttls-hybrid-kex' && f.positive));
    assert.match(result.banner, /ESMTP/);
  } finally {
    server.close();
  }
});

test('PostgreSQL SSLRequest is binary and a refusal is reported', async () => {
  const server = net.createServer((socket) => {
    socket.once('data', (chunk) => {
      assert.equal(chunk.length, 8);
      assert.equal(chunk.readUInt32BE(0), 8);
      assert.equal(chunk.readUInt32BE(4), 80877103);
      socket.write('N');
    });
  });
  const port = await listen(server);
  try {
    const result = await inspectStarttls(`postgres://127.0.0.1:${port}`, { timeout: 3000 });
    assert.equal(result.reachable, true);
    assert.equal(result.upgraded, false);
    assert.match(result.error, /refused TLS/);
  } finally {
    server.close();
  }
});

test('classical STARTTLS key exchange becomes an actionable finding', () => {
  const findings = deriveStarttlsFindings({
    reachable: true,
    upgraded: true,
    protocol: 'imap',
    protocolLabel: 'IMAP',
    host: 'mail.example.com',
    port: 143,
    target: 'imap://mail.example.com',
    group: 0x001d,
    groupLabel: 'X25519',
    hybrid: false,
    chainAnalysis: null,
  });
  const kex = findings.find((f) => f.id === 'starttls-classical-kex');
  assert.ok(kex);
  assert.equal(kex.algorithm, 'x25519');
  assert.equal(kex.location.protocol, 'imap');
});
