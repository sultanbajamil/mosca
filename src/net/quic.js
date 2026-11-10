/**
 * MOSCA — QUIC v1 Initial packet prober
 * =====================================
 *
 * HTTP/3 runs over QUIC, which encrypts almost everything from the first
 * flight. One thing stays readable: the Initial packet, protected with keys
 * derived from the client's Destination Connection ID and a salt fixed in
 * RFC 9001. That makes a QUIC server's TLS ServerHello — including the key
 * exchange group — observable without completing a handshake.
 *
 * This module implements the Initial packet protection itself:
 *
 *   HKDF-SHA256  ->  client/server key, IV, header-protection key
 *   AES-128-GCM  ->  AEAD over the CRYPTO frames
 *   AES-128-ECB  ->  header protection mask
 *
 * No dependencies, no QUIC library. The RFC 9001 Appendix A.1 vectors are
 * covered by test/quic.test.js, and the live probe is a single 1200-byte
 * datagram followed by one reply.
 */

import dgram from 'node:dgram';
import net from 'node:net';
import crypto from 'node:crypto';
import { buildClientHello, parseServerHello, quicVarint, versionName, CIPHER_SUITES, GROUPS } from './clienthello.js';

/** QUIC v1 initial salt, RFC 9001 §5.2. */
export const QUIC_V1_SALT = Buffer.from('38762cf7f55934b34d179ae6a4c80cadccbb7f0a', 'hex');
export const QUIC_V1 = 0x00000001;

const u8 = (n) => Buffer.from([n & 0xff]);
const u32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
};

/** HKDF-Extract with SHA-256. */
export function hkdfExtract(salt, ikm) {
  return crypto.createHmac('sha256', salt).update(ikm).digest();
}

/** HKDF-Expand with SHA-256. */
export function hkdfExpand(prk, info, length) {
  const chunks = [];
  let previous = Buffer.alloc(0);
  let counter = 1;
  let total = 0;
  while (total < length) {
    previous = crypto
      .createHmac('sha256', prk)
      .update(Buffer.concat([previous, info, u8(counter)]))
      .digest();
    chunks.push(previous);
    total += previous.length;
    counter += 1;
  }
  return Buffer.concat(chunks).subarray(0, length);
}

/** TLS 1.3 HKDF-Expand-Label, RFC 8446 §7.1. */
export function hkdfExpandLabel(secret, label, context, length) {
  const fullLabel = Buffer.from(`tls13 ${label}`, 'latin1');
  const info = Buffer.concat([
    Buffer.from([(length >> 8) & 0xff, length & 0xff]),
    u8(fullLabel.length),
    fullLabel,
    u8(context.length),
    context,
  ]);
  return hkdfExpand(secret, info, length);
}

/**
 * Derive the QUIC v1 Initial keys from a Destination Connection ID.
 * @param {Buffer} dcid
 * @param {number} [version]
 */
export function deriveInitialKeys(dcid, version = QUIC_V1) {
  if (version !== QUIC_V1) throw new Error(`unsupported QUIC version 0x${version.toString(16)}`);
  const initialSecret = hkdfExtract(QUIC_V1_SALT, dcid);
  const clientSecret = hkdfExpandLabel(initialSecret, 'client in', Buffer.alloc(0), 32);
  const serverSecret = hkdfExpandLabel(initialSecret, 'server in', Buffer.alloc(0), 32);

  const expand = (secret) => ({
    secret,
    key: hkdfExpandLabel(secret, 'quic key', Buffer.alloc(0), 16),
    iv: hkdfExpandLabel(secret, 'quic iv', Buffer.alloc(0), 12),
    hp: hkdfExpandLabel(secret, 'quic hp', Buffer.alloc(0), 16),
  });

  return { initialSecret, client: expand(clientSecret), server: expand(serverSecret) };
}

/** AES-128-ECB header-protection mask. */
export function headerProtectionMask(hp, sample) {
  const cipher = crypto.createCipheriv('aes-128-ecb', hp, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(sample), cipher.final()]);
}

/** Build the AEAD nonce: IV XOR the packet number. */
export function buildNonce(iv, packetNumber) {
  const nonce = Buffer.from(iv);
  const pn = Buffer.alloc(8);
  pn.writeBigUInt64BE(BigInt(packetNumber));
  for (let i = 0; i < 8; i++) nonce[nonce.length - 8 + i] ^= pn[i];
  return nonce;
}

/**
 * Encode a QUIC v1 Initial packet, including header protection.
 *
 * @param {{payload:Buffer, dcid:Buffer, scid:Buffer, packetNumber?:number, pnLength?:number, keys:object}} opts
 */
export function protectInitialPacket({ payload, dcid, scid, packetNumber = 0, pnLength = 4, keys, version = QUIC_V1 }) {
  const firstByte = 0xc0 | ((pnLength - 1) & 0x03);
  const length = pnLength + payload.length + 16;
  const lengthField = quicVarint(length);
  const pn = Buffer.alloc(pnLength);
  pn.writeUIntBE(packetNumber, 0, pnLength);

  const headerPrefix = Buffer.concat([
    u8(firstByte),
    u32(version),
    u8(dcid.length),
    dcid,
    u8(scid.length),
    scid,
    quicVarint(0), // token length
    lengthField,
  ]);
  const pnOffset = headerPrefix.length;
  const header = Buffer.concat([headerPrefix, pn]);

  const cipher = crypto.createCipheriv('aes-128-gcm', keys.key, buildNonce(keys.iv, packetNumber));
  cipher.setAAD(header);
  const ciphertext = Buffer.concat([cipher.update(payload), cipher.final(), cipher.getAuthTag()]);
  const packet = Buffer.concat([header, ciphertext]);

  if (packet.length < pnOffset + 4 + 16) {
    throw new Error('QUIC Initial payload too short for header protection');
  }
  const sample = packet.subarray(pnOffset + 4, pnOffset + 4 + 16);
  const mask = headerProtectionMask(keys.hp, sample);
  packet[0] ^= mask[0] & 0x0f;
  for (let i = 0; i < pnLength; i++) packet[pnOffset + i] ^= mask[1 + i];
  return { packet, pnOffset, length };
}

/** Read a QUIC variable-length integer. */
export function readQuicVarint(buf, offset) {
  if (offset >= buf.length) throw new Error('QUIC varint: past end');
  const first = buf[offset];
  const length = 1 << (first >> 6);
  if (offset + length > buf.length) throw new Error('QUIC varint: truncated');
  let value = first & 0x3f;
  for (let i = 1; i < length; i++) value = value * 256 + buf[offset + i];
  return { value, length };
}

/**
 * Decode and remove header protection from a long-header packet.
 * @param {Buffer} packet
 * @param {object} keys
 */
export function unprotectInitialPacket(packet, keys) {
  if (packet.length < 7 || !(packet[0] & 0x80)) throw new Error('not a QUIC long-header packet');
  const version = packet.readUInt32BE(1);
  if (version === 0) {
    let p = 5;
    const dcidLen = packet[p++];
    const dcid = packet.subarray(p, p + dcidLen);
    p += dcidLen;
    const scidLen = packet[p++];
    const scid = packet.subarray(p, p + scidLen);
    p += scidLen;
    const versions = [];
    for (; p + 4 <= packet.length; p += 4) versions.push(packet.readUInt32BE(p));
    return { type: 'version-negotiation', version, versions, dcid, scid };
  }

  const type = (packet[0] >> 4) & 0x03;
  if (type === 3) {
    return { type: 'retry', version };
  }
  if (type !== 0) {
    return { type: 'other', version, longType: type };
  }

  let p = 5;
  const dcidLen = packet[p++];
  const dcid = packet.subarray(p, p + dcidLen);
  p += dcidLen;
  const scidLen = packet[p++];
  const scid = packet.subarray(p, p + scidLen);
  p += scidLen;
  const token = readQuicVarint(packet, p);
  p += token.length + token.value;
  const length = readQuicVarint(packet, p);
  p += length.length;
  const pnOffset = p;
  const end = p + length.value;

  if (packet.length < pnOffset + 4 + 16) {
    throw new Error('Initial packet too short for header protection sample');
  }
  const sample = packet.subarray(pnOffset + 4, pnOffset + 4 + 16);
  const mask = headerProtectionMask(keys.hp, sample);

  const firstByte = packet[0] ^ (mask[0] & 0x0f);
  const pnLength = (firstByte & 0x03) + 1;
  if (pnOffset + pnLength > packet.length) throw new Error('Initial packet truncated packet number');

  const header = Buffer.from(packet.subarray(0, pnOffset + pnLength));
  header[0] = firstByte;
  let packetNumber = 0;
  for (let i = 0; i < pnLength; i++) {
    header[pnOffset + i] = packet[pnOffset + i] ^ mask[1 + i];
    packetNumber = packetNumber * 256 + header[pnOffset + i];
  }

  const ciphertext = packet.subarray(pnOffset + pnLength, Math.min(end, packet.length));
  if (ciphertext.length < 16) throw new Error('Initial packet has no AEAD tag');

  const decipher = crypto.createDecipheriv('aes-128-gcm', keys.key, buildNonce(keys.iv, packetNumber));
  decipher.setAAD(header);
  decipher.setAuthTag(ciphertext.subarray(ciphertext.length - 16));
  const payload = Buffer.concat([
    decipher.update(ciphertext.subarray(0, ciphertext.length - 16)),
    decipher.final(),
  ]);

  return { type: 'initial', version, dcid, scid, packetNumber, payload, headerBytes: header.length };
}

/**
 * Walk a decrypted Initial payload, collecting CRYPTO frame bytes and any
 * CONNECTION_CLOSE. PADDING is a single zero byte by definition.
 * @param {Buffer} payload
 */
export function parseFrames(payload) {
  const cryptoFrames = [];
  let close = null;
  let p = 0;
  while (p < payload.length) {
    let type;
    try {
      const t = readQuicVarint(payload, p);
      type = t.value;
      p += t.length;
    } catch {
      break;
    }

    const read = () => {
      const r = readQuicVarint(payload, p);
      p += r.length;
      return r.value;
    };

    if (type === 0x00) continue; // PADDING
    if (type === 0x01 || type === 0x1e) continue; // PING / HANDSHAKE_DONE
    if (type === 0x02 || type === 0x03) {
      read(); // largest acknowledged
      read(); // ACK delay
      const ranges = read();
      read(); // first range
      for (let i = 0; i < ranges; i++) {
        read();
        read();
      }
      if (type === 0x03) {
        read();
        read();
        read();
      }
      continue;
    }
    if (type === 0x06) {
      const offset = read();
      const length = read();
      cryptoFrames.push({ offset, data: payload.subarray(p, p + length) });
      p += length;
      continue;
    }
    if (type === 0x1c) {
      const errorCode = read();
      read(); // frame type
      const reasonLen = read();
      close = { errorCode, reason: payload.subarray(p, p + reasonLen).toString('utf8') };
      p += reasonLen;
      continue;
    }
    if (type === 0x1d) {
      const errorCode = read();
      const reasonLen = read();
      close = { errorCode, reason: payload.subarray(p, p + reasonLen).toString('utf8') };
      p += reasonLen;
      continue;
    }
    break; // a frame type we cannot skip safely ends parsing
  }

  cryptoFrames.sort((a, b) => a.offset - b.offset);
  return { crypto: Buffer.concat(cryptoFrames.map((f) => f.data)), cryptoFrames, close };
}

/**
 * Parse TLS handshake messages carried in CRYPTO frames (no TLS record layer).
 * @param {Buffer} data
 */
export function parseCryptoHandshake(data) {
  const messages = [];
  let p = 0;
  while (p + 4 <= data.length) {
    const type = data[p];
    const length = (data[p + 1] << 16) | (data[p + 2] << 8) | data[p + 3];
    const body = data.subarray(p + 4, p + 4 + length);
    if (body.length < length) break;
    messages.push({ type, body });
    p += 4 + length;
  }
  return messages;
}

/**
 * Parse a server Initial datagram.
 * @param {Buffer} datagram
 * @param {Buffer} clientDcid the DCID the client sent
 */
export function parseServerInitial(datagram, clientDcid) {
  const keys = deriveInitialKeys(clientDcid).server;
  const unprotected = unprotectInitialPacket(datagram, keys);
  if (unprotected.type !== 'initial') return unprotected;

  const frames = parseFrames(unprotected.payload);
  const messages = parseCryptoHandshake(frames.crypto);
  const serverHelloMessage = messages.find((m) => m.type === 0x02);
  const serverHello = serverHelloMessage ? parseServerHello(serverHelloMessage.body) : null;

  return {
    ...unprotected,
    ...frames,
    messages,
    serverHello,
  };
}

/**
 * Probe a QUIC server with one padded Initial packet.
 *
 * @param {{host:string, port?:number, servername?:string, timeout?:number, yearsToCRQC?:number}} opts
 */
export function probeQuic({ host, port = 443, servername, timeout = 8000, yearsToCRQC = 7 }) {
  return new Promise((resolve, reject) => {
    const family = net.isIPv6(host) ? 'udp6' : 'udp4';
    const socket = dgram.createSocket(family);
    const dcid = crypto.randomBytes(8);
    const scid = crypto.randomBytes(8);
    const keys = deriveInitialKeys(dcid).client;

    const helloRecord = buildClientHello({ host: servername || host, alpn: ['h3'], quic: { scid } });
    const hello = helloRecord.subarray(5); // strip the TLS record header
    const cryptoFrame = Buffer.concat([u8(0x06), quicVarint(0), quicVarint(hello.length), hello]);

    // RFC 9000 requires a client Initial datagram of at least 1200 bytes.
    let payload = cryptoFrame;
    let datagram;
    for (let attempt = 0; attempt < 3; attempt++) {
      const headerGuess = 1 + 4 + 1 + dcid.length + 1 + scid.length + 1 + 2 + 4;
      const target = 1200 - headerGuess - 16;
      if (payload.length < target) payload = Buffer.concat([payload, Buffer.alloc(target - payload.length)]);
      datagram = protectInitialPacket({ payload, dcid, scid, keys, packetNumber: 0, pnLength: 4 }).packet;
    }

    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        socket.close();
      } catch {
        /* already closed */
      }
      fn(value);
    };

    const timer = setTimeout(
      () => finish(reject, new Error(`QUIC probe timed out after ${timeout}ms (no Initial response; server may filter UDP/${port})`)),
      timeout,
    );
    timer.unref?.();

    socket.on('error', (err) => finish(reject, err));
    socket.on('message', (message) => {
      try {
        const parsed = parseServerInitial(message, dcid);
        if (parsed.type === 'version-negotiation') {
          return finish(resolve, {
            reachable: true,
            versionNegotiation: true,
            versions: parsed.versions.map((v) => `0x${v.toString(16)}`),
            serverHello: null,
            group: null,
            cipherSuite: null,
            error: null,
            datagramBytes: message.length,
          });
        }
        if (parsed.type === 'retry') {
          return finish(resolve, {
            reachable: true,
            retry: true,
            serverHello: null,
            group: null,
            cipherSuite: null,
            error: 'server sent a Retry packet (address validation required)',
            datagramBytes: message.length,
          });
        }
        if (parsed.type !== 'initial') {
          return finish(resolve, {
            reachable: true,
            serverHello: null,
            group: null,
            cipherSuite: null,
            error: `unexpected QUIC packet type: ${parsed.type}`,
            datagramBytes: message.length,
          });
        }
        const sh = parsed.serverHello;
        finish(resolve, {
          reachable: true,
          versionNegotiation: false,
          retry: false,
          version: sh?.version || sh?.legacyVersion || null,
          versionName: versionName(sh?.version || sh?.legacyVersion || null),
          cipherSuite: sh?.cipherSuite ?? null,
          cipherName: CIPHER_SUITES[sh?.cipherSuite]?.name || null,
          group: sh?.group ?? null,
          groupLabel: GROUPS[sh?.group]?.label || null,
          serverHello: Boolean(sh),
          connectionClose: parsed.close || null,
          error: sh ? null : parsed.close ? `server closed the connection: ${parsed.close.reason || parsed.close.errorCode}` : 'no ServerHello in the Initial response',
          datagramBytes: message.length,
        });
      } catch (err) {
        finish(reject, err);
      }
    });

    socket.send(datagram, port, host, (err) => {
      if (err) finish(reject, err);
    });
  });
}

/**
 * Full QUIC inspection + unified findings.
 * @param {string} target `quic://host:443` or `host:443`
 * @param {{timeout?:number, yearsToCRQC?:number}} opts
 */
export async function inspectQuic(target, opts = {}) {
  const { timeout = 8000, yearsToCRQC = 7 } = opts;
  const raw = String(target).replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').split('/')[0];
  const bracket = /^\[([^\]]+)\](?::(\d+))?$/.exec(raw);
  let host = raw;
  let port = 443;
  if (bracket) {
    host = bracket[1];
    if (bracket[2]) port = Number(bracket[2]);
  } else {
    const parts = raw.split(':');
    if (parts.length === 2 && /^\d+$/.test(parts[1])) {
      host = parts[0];
      port = Number(parts[1]);
    }
  }
  const servername = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) ? undefined : host;

  const result = {
    target: String(target),
    host,
    port,
    servername: servername || null,
    reachable: false,
    error: null,
    version: null,
    versionName: null,
    cipherSuite: null,
    cipherName: null,
    group: null,
    groupLabel: null,
    hybrid: false,
    serverHello: false,
    versionNegotiation: false,
    retry: false,
    datagramBytes: null,
    findings: [],
  };

  try {
    Object.assign(result, await probeQuic({ host, port, servername, timeout }));
    result.reachable = true;
    const group = result.group != null ? GROUPS[result.group] : null;
    result.hybrid = Boolean(group && (group.type === 'hybrid' || group.type === 'KEM'));
  } catch (err) {
    result.error = err.message;
  }

  result.findings = deriveQuicFindings(result, { yearsToCRQC });
  return result;
}

/** Convert a QUIC result into unified findings. */
export function deriveQuicFindings(ep, { yearsToCRQC = 7 } = {}) {
  const findings = [];
  if (!ep.reachable) return findings;
  const where = { host: ep.host, port: ep.port, target: ep.target, protocol: 'quic' };

  if (ep.hybrid) {
    findings.push({
      id: 'quic-hybrid-kex',
      kind: 'endpoint',
      title: `QUIC negotiates ${ep.groupLabel}`,
      algorithm: 'x25519mlkem768',
      primitive: 'key-agreement',
      location: where,
      confidence: 'high',
      positive: true,
      note: 'HTTP/3 key exchange is already post-quantum hybrid.',
    });
  } else if (ep.group) {
    const name = GROUPS[ep.group]?.name || ep.group;
    findings.push({
      id: 'quic-classical-kex',
      kind: 'endpoint',
      title: `QUIC negotiates classical ${ep.groupLabel || ep.group}`,
      algorithm: name === 'x25519' ? 'x25519' : 'ecdh',
      primitive: 'key-agreement',
      location: where,
      confidence: 'high',
      note: 'HTTP/3 carries the same long-lived traffic as HTTPS. Enable X25519MLKEM768 on the QUIC listener.',
      evidence: { group: ep.group },
    });
  }
  return findings;
}
