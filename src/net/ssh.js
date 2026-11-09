/**
 * MOSCA — raw SSH endpoint probe
 * ==============================
 *
 * TLS is not the only recorded handshake that a future quantum computer can
 * open. SSH protects backups, source control, routers and bastions, often for
 * far longer than a TLS session. OpenSSH shipped hybrid post-quantum key
 * exchange years ago; whether a given server offers it is visible in the
 * clear, before authentication.
 *
 * This module speaks just enough of RFC 4253 to:
 *
 *   1. exchange identification strings,
 *   2. send a minimal SSH_MSG_KEXINIT,
 *   3. read the server's SSH_MSG_KEXINIT and parse its algorithm name-lists.
 *
 * It never authenticates, never offers credentials, and never completes key
 * exchange. The server's advertised algorithms are the whole answer.
 */

import net from 'node:net';
import crypto from 'node:crypto';
import { lookup } from '../rules/algorithms.js';

/** KEX methods that carry a post-quantum KEM. */
export const HYBRID_KEX = [
  'mlkem768x25519-sha256',
  'sntrup761x25519-sha512@openssh.com',
  'sntrup761x25519-sha512',
  'sntrup761x25519-sha512@libssh.org',
];

/** Key exchanges that are weak even before quantum computers. */
export const WEAK_KEX = new Set([
  'diffie-hellman-group1-sha1',
  'diffie-hellman-group14-sha1',
  'diffie-hellman-group-exchange-sha1',
]);

/** Host-key algorithms withdrawn or classically broken. */
export const LEGACY_HOST_KEYS = new Set(['ssh-rsa', 'ssh-dss']);

/** Ciphers with a classical weakness (CBC modes, 64-bit blocks, RC4). */
export const WEAK_CIPHERS = new Set([
  '3des-cbc',
  'blowfish-cbc',
  'cast128-cbc',
  'arcfour',
  'arcfour128',
  'arcfour256',
  'aes128-cbc',
  'aes192-cbc',
  'aes256-cbc',
  'rijndael-cbc@lysator.liu.se',
]);

/** MACs whose collision or forgery resistance is below current guidance. */
export const WEAK_MACS = new Set([
  'hmac-md5',
  'hmac-md5-96',
  'hmac-sha1',
  'hmac-sha1-96',
  'hmac-ripemd160',
  'umac-64@openssh.com',
]);

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

const u32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
};

/** Encode an SSH name-list (RFC 4251 §5). */
export function encodeNameList(names) {
  const body = Buffer.from(names.join(','), 'ascii');
  return Buffer.concat([u32(body.length), body]);
}

/** Decode a name-list at `offset`; returns the list and the new offset. */
export function decodeNameList(buf, offset) {
  const length = buf.readUInt32BE(offset);
  const start = offset + 4;
  const end = start + length;
  if (end > buf.length) throw new Error('truncated SSH name-list');
  const text = buf.subarray(start, end).toString('ascii');
  return { list: text ? text.split(',') : [], offset: end };
}

/**
 * Build a minimal, syntactically valid SSH_MSG_KEXINIT packet.
 * The algorithm choices do not matter: the probe hangs up before negotiation.
 */
export function buildKexInit() {
  const lists = [
    ['diffie-hellman-group14-sha256', 'curve25519-sha256'],
    ['ssh-ed25519', 'rsa-sha2-256'],
    ['aes128-ctr'],
    ['aes128-ctr'],
    ['hmac-sha2-256'],
    ['hmac-sha2-256'],
    ['none'],
    ['none'],
    [],
    [],
  ];
  const payload = Buffer.concat([
    Buffer.from([20]), // SSH_MSG_KEXINIT
    crypto.randomBytes(16), // cookie
    ...lists.map(encodeNameList),
    Buffer.from([0]), // first_kex_packet_follows
    u32(0), // reserved
  ]);

  const block = 8;
  let paddingLength = block - ((payload.length + 5) % block);
  if (paddingLength < 4) paddingLength += block;
  const packetLength = payload.length + paddingLength + 1;
  return Buffer.concat([
    u32(packetLength),
    Buffer.from([paddingLength]),
    payload,
    crypto.randomBytes(paddingLength),
  ]);
}

/**
 * Parse one SSH binary packet from the start of `buf`.
 * Returns null when more bytes are needed.
 * @param {Buffer} buf
 */
export function parsePacket(buf) {
  if (buf.length < 4) return null;
  const packetLength = buf.readUInt32BE(0);
  if (packetLength < 5 || packetLength > 1024 * 1024) {
    throw new Error(`implausible SSH packet length ${packetLength}`);
  }
  const total = 4 + packetLength;
  if (buf.length < total) return null;
  const paddingLength = buf[4];
  const payloadLength = packetLength - paddingLength - 1;
  if (payloadLength < 0 || 5 + payloadLength > total) {
    throw new Error('invalid SSH packet padding');
  }
  return {
    packetLength,
    paddingLength,
    payload: buf.subarray(5, 5 + payloadLength),
    consumed: total,
  };
}

/**
 * Parse an SSH_MSG_KEXINIT payload (message type 20).
 * @param {Buffer} payload
 */
export function parseKexInit(payload) {
  if (!Buffer.isBuffer(payload) || payload.length < 17 || payload[0] !== 20) {
    throw new Error('not an SSH_MSG_KEXINIT payload');
  }
  let p = 1;
  const cookie = payload.subarray(p, p + 16).toString('hex');
  p += 16;

  const lists = [];
  for (let i = 0; i < 10; i++) {
    const { list, offset } = decodeNameList(payload, p);
    lists.push(list);
    p = offset;
  }
  if (p + 5 > payload.length) throw new Error('truncated SSH_MSG_KEXINIT');
  const firstKexPacketFollows = payload[p] === 1;
  p += 1;
  const reserved = payload.readUInt32BE(p);

  return {
    cookie,
    kexAlgorithms: lists[0],
    serverHostKeyAlgorithms: lists[1],
    encryptionC2S: lists[2],
    encryptionS2C: lists[3],
    macC2S: lists[4],
    macS2C: lists[5],
    compressionC2S: lists[6],
    compressionS2C: lists[7],
    languagesC2S: lists[8],
    languagesS2C: lists[9],
    firstKexPacketFollows,
    reserved,
  };
}

/** Parse an SSH identification line. */
export function parseBanner(line) {
  const raw = String(line || '').trim();
  const m = /^SSH-(1\.99|2\.0)-([^\s]+)(?:\s+(.*))?$/.exec(raw);
  if (!m) return { raw, protocol: null, software: null, comments: null };
  return { raw, protocol: `SSH-${m[1]}`, software: m[2], comments: m[3] || null };
}

/** Extract an OpenSSH version, when the banner is one. */
export function opensshVersion(software) {
  const m = /^OpenSSH[_-](\d+)\.(\d+)(?:p(\d+))?/i.exec(String(software || ''));
  if (!m) return null;
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3] || 0), text: m[0] };
}

// ---------------------------------------------------------------------------
// Probe
// ---------------------------------------------------------------------------

/** Parse an SSH target like `host`, `host:2222` or `ssh://host:2222`. */
export function parseSshTarget(target) {
  let raw = String(target).trim().replace(/^ssh:\/\//i, '').split('/')[0];
  let port = 22;
  const bracket = /^\[([^\]]+)\](?::(\d+))?$/.exec(raw);
  if (bracket) return { host: bracket[1], port: bracket[2] ? Number(bracket[2]) : 22 };
  const parts = raw.split(':');
  if (parts.length === 2 && /^\d+$/.test(parts[1])) {
    port = Number(parts[1]);
    raw = parts[0];
  }
  return { host: raw, port };
}

/**
 * Connect to an SSH server and read its advertised algorithms.
 *
 * @param {{host:string, port?:number, timeout?:number, clientVersion?:string}} opts
 * @returns {Promise<object>}
 */
export function probeSsh({ host, port = 22, timeout = 8000, clientVersion = 'MOSCA_2.0' } = {}) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port });
    const base = {
      target: `${host}:${port}`,
      host,
      port,
      reachable: false,
      error: null,
      protocol: null,
      banner: null,
      software: null,
      comments: null,
      kexAlgorithms: [],
      serverHostKeyAlgorithms: [],
      encryption: [],
      macs: [],
      compression: [],
      hybrid: false,
      hybridAlgorithm: null,
      cookie: null,
    };

    let buffer = Buffer.alloc(0);
    let bannerSeen = false;
    let sentKex = false;
    let settled = false;

    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      fn(value);
    };

    socket.setTimeout(timeout, () => {
      finish(reject, new Error(`SSH probe timed out after ${timeout}ms`));
    });

    socket.on('error', (err) => finish(reject, err));

    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);

      // ------------------------------------------------------- identification
      if (!bannerSeen) {
        let nl = buffer.indexOf(0x0a);
        while (nl !== -1) {
          const line = buffer.subarray(0, nl).toString('latin1').replace(/\r$/, '');
          buffer = buffer.subarray(nl + 1);
          if (/^SSH-(1\.99|2\.0)-/.test(line)) {
            const parsed = parseBanner(line);
            base.protocol = parsed.protocol;
            base.banner = parsed.raw;
            base.software = parsed.software;
            base.comments = parsed.comments;
            bannerSeen = true;
            socket.write(`SSH-2.0-${clientVersion}\r\n`);
            socket.write(buildKexInit());
            sentKex = true;
            break;
          }
          nl = buffer.indexOf(0x0a);
        }
        if (!bannerSeen) return;
      }

      // --------------------------------------------------------------- KEXINIT
      try {
        let packet = parsePacket(buffer);
        // Servers may emit SSH_MSG_EXT_INFO or other packets first; skip until
        // KEXINIT, with a small bound so a chatty endpoint cannot hang us.
        let hops = 0;
        while (packet && packet.payload[0] !== 20 && hops < 4) {
          buffer = buffer.subarray(packet.consumed);
          packet = parsePacket(buffer);
          hops += 1;
        }
        if (!packet || packet.payload[0] !== 20) return;
        const kex = parseKexInit(packet.payload);
        base.reachable = true;
        base.cookie = kex.cookie;
        base.kexAlgorithms = kex.kexAlgorithms;
        base.serverHostKeyAlgorithms = kex.serverHostKeyAlgorithms;
        base.encryption = [...new Set([...kex.encryptionC2S, ...kex.encryptionS2C])];
        base.macs = [...new Set([...kex.macC2S, ...kex.macS2C])];
        base.compression = [...new Set([...kex.compressionC2S, ...kex.compressionS2C])];
        const hybrid = kex.kexAlgorithms.find((name) => HYBRID_KEX.includes(name));
        base.hybrid = Boolean(hybrid);
        base.hybridAlgorithm = hybrid || null;
        finish(resolve, base);
      } catch (err) {
        finish(reject, err);
      }
    });

    socket.on('close', () => {
      if (settled) return;
      if (!base.reachable) {
        const detail = !bannerSeen
          ? 'connection closed before the SSH identification string'
          : sentKex
            ? 'connection closed before SSH_MSG_KEXINIT'
            : 'connection closed';
        finish(reject, new Error(detail));
      }
    });
  });
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/** Map an SSH KEX method onto a registry id. */
export function classifySshKex(name) {
  const algo = lookup(name);
  if (algo.id !== 'unknown') return algo.id;
  if (/^diffie-hellman/i.test(name)) return 'dh';
  if (/^curve25519/i.test(name)) return 'x25519';
  if (/^ecdh/i.test(name)) return 'ecdh';
  return 'dh';
}

function classifySshCipher(name) {
  const algo = lookup(name);
  if (algo.id !== 'unknown') return algo.id;
  if (/arcfour|rc4/i.test(name)) return 'rc4';
  if (/3des|des-ede3/i.test(name)) return '3des';
  if (/cbc/i.test(name)) return 'aes-128-cbc';
  return 'unknown';
}

function classifySshMac(name) {
  const algo = lookup(name);
  if (algo.id !== 'unknown') return algo.id;
  if (/md5/i.test(name)) return 'hmac-md5';
  if (/sha1/i.test(name)) return 'hmac-sha1';
  return 'hmac-sha256';
}

/**
 * Turn one SSH endpoint record into findings.
 * @param {object} ep
 */
export function deriveSshFindings(ep) {
  if (!ep || !ep.reachable) return [];
  const findings = [];
  const where = { host: ep.host, port: ep.port, target: ep.target };
  const kex = ep.kexAlgorithms || [];
  const hostKeys = ep.serverHostKeyAlgorithms || [];
  const ciphers = ep.encryption || [];
  const macs = ep.macs || [];

  // --------------------------------------------------------- key exchange
  if (ep.hybrid && ep.hybridAlgorithm) {
    const algorithm = HYBRID_KEX.includes(ep.hybridAlgorithm) && ep.hybridAlgorithm.startsWith('mlkem')
      ? 'mlkem768x25519-sha256'
      : 'sntrup761x25519-sha512';
    findings.push({
      id: 'ssh-hybrid-kex',
      kind: 'endpoint',
      title: `Post-quantum hybrid SSH key exchange enabled (${ep.hybridAlgorithm})`,
      algorithm,
      primitive: 'key-agreement',
      location: where,
      confidence: 'high',
      positive: true,
      note: 'The server advertises a hybrid KEM for SSH. Recorded sessions are protected against harvest-now-decrypt-later.',
      evidence: { algorithm: ep.hybridAlgorithm },
    });
  } else if (kex.length > 0) {
    const first = kex[0];
    findings.push({
      id: 'ssh-classical-kex',
      kind: 'endpoint',
      title: `Classical-only SSH key exchange (${first})`,
      algorithm: classifySshKex(first),
      primitive: 'key-agreement',
      location: where,
      confidence: 'high',
      note: 'No hybrid KEM is advertised. A recorded SSH session can be decrypted once a CRQC exists. Enable mlkem768x25519-sha256 or sntrup761x25519-sha512@openssh.com.',
      evidence: { algorithms: kex.slice(0, 12) },
    });
  }

  const weakKex = kex.filter((name) => WEAK_KEX.has(name));
  if (weakKex.length > 0) {
    findings.push({
      id: 'ssh-weak-kex',
      kind: 'endpoint',
      title: `Weak SSH key exchange offered (${weakKex.join(', ')})`,
      algorithm: 'dh',
      primitive: 'key-agreement',
      location: where,
      confidence: 'high',
      classical: 'weak',
      note: 'SHA-1 group key exchange is deprecated. Remove it from KexAlgorithms.',
      evidence: { algorithms: weakKex },
    });
  }

  // ---------------------------------------------------------- host key auth
  const legacyHostKey = hostKeys.find((name) => LEGACY_HOST_KEYS.has(name));
  if (legacyHostKey) {
    findings.push({
      id: 'ssh-legacy-hostkey',
      kind: 'endpoint',
      title: `Legacy SSH host key offered (${legacyHostKey})`,
      algorithm: legacyHostKey,
      primitive: 'signature',
      location: where,
      confidence: 'high',
      note: 'ssh-rsa uses SHA-1 and ssh-dss uses DSA; both are withdrawn. Remove them and publish an Ed25519 plus an ML-DSA host key.',
      evidence: { algorithms: hostKeys.slice(0, 12) },
    });
  } else if (hostKeys.length > 0) {
    const first = hostKeys[0];
    findings.push({
      id: 'ssh-classical-hostkey',
      kind: 'endpoint',
      title: `SSH host key is ${first}`,
      algorithm: lookup(first).id === 'unknown' ? 'rsa' : lookup(first).id,
      primitive: 'signature',
      location: where,
      confidence: 'high',
      note: 'All currently deployed SSH host-key algorithms are quantum-vulnerable. Add an ML-DSA host key and pin it during the transition.',
      evidence: { algorithms: hostKeys.slice(0, 12) },
    });
  }

  // --------------------------------------------------------------- ciphers
  const weakCiphers = ciphers.filter((name) => WEAK_CIPHERS.has(name));
  if (weakCiphers.length > 0) {
    findings.push({
      id: 'ssh-weak-cipher',
      kind: 'endpoint',
      title: `Weak SSH cipher offered (${weakCiphers.join(', ')})`,
      algorithm: classifySshCipher(weakCiphers[0]),
      primitive: 'symmetric',
      location: where,
      confidence: 'high',
      classical: 'weak',
      note: 'CBC-mode and 64-bit-block ciphers are obsolete. Restrict Ciphers to aes256-gcm@openssh.com, chacha20-poly1305@openssh.com or aes256-ctr.',
      evidence: { algorithms: weakCiphers },
    });
  }

  // ------------------------------------------------------------------- MACs
  const weakMacs = macs.filter((name) => WEAK_MACS.has(name));
  if (weakMacs.length > 0) {
    findings.push({
      id: 'ssh-weak-mac',
      kind: 'endpoint',
      title: `Weak SSH MAC offered (${weakMacs.join(', ')})`,
      algorithm: classifySshMac(weakMacs[0]),
      primitive: 'mac',
      location: where,
      confidence: 'high',
      classical: 'weak',
      note: 'Remove MD5 and SHA-1 MACs; prefer hmac-sha2-256-etm@openssh.com or hmac-sha2-512-etm@openssh.com.',
      evidence: { algorithms: weakMacs },
    });
  }

  return findings;
}
