/**
 * SSH wire format and classification. These tests use synthetic packets so
 * they run without a network and without an SSH server.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildKexInit,
  parsePacket,
  parseKexInit,
  parseBanner,
  parseSshTarget,
  opensshVersion,
  classifySshKex,
  deriveSshFindings,
  HYBRID_KEX,
} from '../src/net/ssh.js';

test('parseSshTarget defaults to 22 and accepts ssh:// and explicit ports', () => {
  assert.deepEqual(parseSshTarget('git.example.com'), { host: 'git.example.com', port: 22 });
  assert.deepEqual(parseSshTarget('git.example.com:2222'), { host: 'git.example.com', port: 2222 });
  assert.deepEqual(parseSshTarget('ssh://git.example.com:2222/repo'), { host: 'git.example.com', port: 2222 });
  assert.deepEqual(parseSshTarget('[2001:db8::1]:2222'), { host: '2001:db8::1', port: 2222 });
});

test('parseBanner understands SSH 2.0 and 1.99 identification strings', () => {
  const modern = parseBanner('SSH-2.0-OpenSSH_9.9p1 Ubuntu-3ubuntu2');
  assert.equal(modern.protocol, 'SSH-2.0');
  assert.equal(modern.software, 'OpenSSH_9.9p1');
  assert.equal(modern.comments, 'Ubuntu-3ubuntu2');

  const compat = parseBanner('SSH-1.99-dropbear_2022.83');
  assert.equal(compat.protocol, 'SSH-1.99');
  assert.equal(compat.software, 'dropbear_2022.83');

  assert.equal(parseBanner('not ssh').protocol, null);
});

test('opensshVersion extracts a comparable version', () => {
  assert.deepEqual(opensshVersion('OpenSSH_9.9p1'), { major: 9, minor: 9, patch: 1, text: 'OpenSSH_9.9p1' });
  assert.deepEqual(opensshVersion('OpenSSH_8.8'), { major: 8, minor: 8, patch: 0, text: 'OpenSSH_8.8' });
  assert.equal(opensshVersion('dropbear'), null);
});

test('buildKexInit produces a well-formed binary packet and KEXINIT payload', () => {
  const packet = buildKexInit();
  const parsed = parsePacket(packet);
  assert.ok(parsed, 'packet must be complete');
  assert.equal(parsed.consumed, packet.length);
  assert.equal((parsed.packetLength + 4) % 8, 0, 'packet length must align to the 8-byte block');
  assert.ok(parsed.paddingLength >= 4);

  const kex = parseKexInit(parsed.payload);
  assert.equal(kex.kexAlgorithms[0], 'diffie-hellman-group14-sha256');
  assert.ok(kex.serverHostKeyAlgorithms.includes('ssh-ed25519'));
  assert.equal(kex.encryptionC2S[0], 'aes128-ctr');
  assert.equal(kex.reserved, 0);
  assert.equal(kex.firstKexPacketFollows, false);
});

test('parseKexInit rejects a payload that is not a KEXINIT', () => {
  assert.throws(() => parseKexInit(Buffer.from([1, 2, 3])), /not an SSH_MSG_KEXINIT/);
});

test('SSH KEX names map onto the shared algorithm registry', () => {
  assert.equal(classifySshKex('curve25519-sha256'), 'x25519');
  assert.equal(classifySshKex('ecdh-sha2-nistp256'), 'ecdh');
  assert.equal(classifySshKex('diffie-hellman-group14-sha256'), 'dh');
  assert.equal(classifySshKex('mlkem768x25519-sha256'), 'mlkem768x25519-sha256');
  assert.equal(classifySshKex('sntrup761x25519-sha512@openssh.com'), 'sntrup761x25519-sha512');
});

test('a hybrid SSH server yields a positive KEX finding', () => {
  const findings = deriveSshFindings({
    reachable: true,
    host: 'bastion.example.com',
    port: 22,
    target: 'bastion.example.com:22',
    hybrid: true,
    hybridAlgorithm: 'mlkem768x25519-sha256',
    kexAlgorithms: ['mlkem768x25519-sha256', 'curve25519-sha256'],
    serverHostKeyAlgorithms: ['ssh-ed25519'],
    encryption: ['aes256-gcm@openssh.com'],
    macs: ['hmac-sha2-256'],
  });
  const hybrid = findings.find((f) => f.id === 'ssh-hybrid-kex');
  assert.ok(hybrid);
  assert.equal(hybrid.positive, true);
  assert.equal(hybrid.algorithm, 'mlkem768x25519-sha256');
  assert.ok(findings.some((f) => f.id === 'ssh-classical-hostkey'));
});

test('a classical SSH server reports KEX, host key, weak cipher and MAC debt', () => {
  const findings = deriveSshFindings({
    reachable: true,
    host: 'legacy.example.com',
    port: 2222,
    target: 'legacy.example.com:2222',
    hybrid: false,
    kexAlgorithms: ['diffie-hellman-group14-sha1', 'curve25519-sha256'],
    serverHostKeyAlgorithms: ['ssh-rsa', 'ssh-ed25519'],
    encryption: ['3des-cbc', 'aes128-ctr'],
    macs: ['hmac-sha1', 'hmac-sha2-256'],
  });
  const ids = findings.map((f) => f.id);
  assert.ok(ids.includes('ssh-classical-kex'));
  assert.ok(ids.includes('ssh-weak-kex'));
  assert.ok(ids.includes('ssh-legacy-hostkey'));
  assert.ok(ids.includes('ssh-weak-cipher'));
  assert.ok(ids.includes('ssh-weak-mac'));
  assert.ok(!ids.includes('ssh-hybrid-kex'));

  const legacy = findings.find((f) => f.id === 'ssh-legacy-hostkey');
  assert.equal(legacy.algorithm, 'ssh-rsa');
  assert.equal(legacy.kind, 'endpoint');
});

test('unreachable SSH endpoints produce no findings', () => {
  assert.deepEqual(deriveSshFindings({ reachable: false, host: 'x', port: 22 }), []);
});

test('the hybrid list includes both OpenSSH spellings', () => {
  assert.ok(HYBRID_KEX.includes('mlkem768x25519-sha256'));
  assert.ok(HYBRID_KEX.includes('sntrup761x25519-sha512@openssh.com'));
});
