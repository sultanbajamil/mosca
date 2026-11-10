/**
 * MOSCA — raw TLS ClientHello prober
 * ==================================
 *
 * Node's TLS stack negotiates whatever OpenSSL supports, so it cannot tell
 * you whether a *server* supports post-quantum key exchange. This module
 * builds a ClientHello by hand, offers the hybrid `X25519MLKEM768` group
 * first, and reads the group the server selects out of the ServerHello.
 *
 * That single capability is the difference between "your TLS is 1.3" and
 * "your TLS is 1.3 but a quantum computer recorded this session".
 *
 * The prober never completes a handshake. It sends a ClientHello, reads the
 * first flight, and closes the socket. No application data is exchanged.
 */

import net from 'node:net';
import crypto from 'node:crypto';

// ---------------------------------------------------------------------------
// Registries
// ---------------------------------------------------------------------------

/** TLS supported-group codepoints. */
export const GROUPS = {
  0x0017: { name: 'secp256r1', label: 'P-256', type: 'ECDHE', quantum: 'broken', bits: 256 },
  0x0018: { name: 'secp384r1', label: 'P-384', type: 'ECDHE', quantum: 'broken', bits: 384 },
  0x0019: { name: 'secp521r1', label: 'P-521', type: 'ECDHE', quantum: 'broken', bits: 521 },
  0x001d: { name: 'x25519', label: 'X25519', type: 'ECDHE', quantum: 'broken', bits: 253 },
  0x001e: { name: 'x448', label: 'X448', type: 'ECDHE', quantum: 'broken', bits: 448 },
  0x0100: { name: 'ffdhe2048', label: 'FFDHE-2048', type: 'DHE', quantum: 'broken', bits: 2048 },
  0x0101: { name: 'ffdhe3072', label: 'FFDHE-3072', type: 'DHE', quantum: 'broken', bits: 3072 },
  0x11eb: { name: 'X25519Kyber768Draft00', label: 'X25519+Kyber768 (draft)', type: 'hybrid', quantum: 'safe', bits: 256 },
  0x11ec: { name: 'X25519MLKEM768', label: 'X25519+ML-KEM-768', type: 'hybrid', quantum: 'safe', bits: 256 },
  0x6399: { name: 'X25519Kyber768Draft00', label: 'X25519+Kyber768 (legacy codepoint)', type: 'hybrid', quantum: 'safe', bits: 256 },
  0x0200: { name: 'mlkem512', label: 'ML-KEM-512', type: 'KEM', quantum: 'safe', bits: 256 },
  0x0201: { name: 'mlkem768', label: 'ML-KEM-768', type: 'KEM', quantum: 'safe', bits: 256 },
  0x0202: { name: 'mlkem1024', label: 'ML-KEM-1024', type: 'KEM', quantum: 'safe', bits: 256 },
};

/** Cipher suites we are likely to see, with their key-exchange family. */
export const CIPHER_SUITES = {
  0x1301: { name: 'TLS_AES_128_GCM_SHA256', kex: 'any', symmetric: 'aes-128-gcm', tls13: true },
  0x1302: { name: 'TLS_AES_256_GCM_SHA384', kex: 'any', symmetric: 'aes-256-gcm', tls13: true },
  0x1303: { name: 'TLS_CHACHA20_POLY1305_SHA256', kex: 'any', symmetric: 'chacha20-poly1305', tls13: true },
  0x1304: { name: 'TLS_AES_128_CCM_SHA256', kex: 'any', symmetric: 'aes-128-gcm', tls13: true },
  0x1305: { name: 'TLS_AES_128_CCM_8_SHA256', kex: 'any', symmetric: 'aes-128-gcm', tls13: true },
  0xc02b: { name: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', kex: 'ECDHE', symmetric: 'aes-128-gcm' },
  0xc02c: { name: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', kex: 'ECDHE', symmetric: 'aes-256-gcm' },
  0xc02f: { name: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', kex: 'ECDHE', symmetric: 'aes-128-gcm' },
  0xc030: { name: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', kex: 'ECDHE', symmetric: 'aes-256-gcm' },
  0xcca8: { name: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', kex: 'ECDHE', symmetric: 'chacha20-poly1305' },
  0xcca9: { name: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', kex: 'ECDHE', symmetric: 'chacha20-poly1305' },
  0xc013: { name: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', kex: 'ECDHE', symmetric: 'aes-128-cbc' },
  0xc014: { name: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', kex: 'ECDHE', symmetric: 'aes-256-cbc' },
  0xc009: { name: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', kex: 'ECDHE', symmetric: 'aes-128-cbc' },
  0xc00a: { name: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA', kex: 'ECDHE', symmetric: 'aes-256-cbc' },
  0x009c: { name: 'TLS_RSA_WITH_AES_128_GCM_SHA256', kex: 'RSA', symmetric: 'aes-128-gcm' },
  0x009d: { name: 'TLS_RSA_WITH_AES_256_GCM_SHA384', kex: 'RSA', symmetric: 'aes-256-gcm' },
  0x002f: { name: 'TLS_RSA_WITH_AES_128_CBC_SHA', kex: 'RSA', symmetric: 'aes-128-cbc' },
  0x0035: { name: 'TLS_RSA_WITH_AES_256_CBC_SHA', kex: 'RSA', symmetric: 'aes-256-cbc' },
  0x000a: { name: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', kex: 'RSA', symmetric: '3des' },
  0x0005: { name: 'TLS_RSA_WITH_RC4_128_SHA', kex: 'RSA', symmetric: 'rc4' },
  0x0004: { name: 'TLS_RSA_WITH_RC4_128_MD5', kex: 'RSA', symmetric: 'rc4' },
};

/** The HelloRetryRequest sentinel random from RFC 8446 §4.1.3. */
const HRR_RANDOM = Buffer.from('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c', 'hex');

/** Key-share payload sizes for each offered group. */
const SHARE_SIZES = {
  0x11ec: 1216, // X25519 (32) + ML-KEM-768 (1184)
  0x11eb: 1216,
  0x6399: 1216,
  0x001d: 32, // X25519
  0x0017: 65, // uncompressed P-256 point
  0x0018: 97, // uncompressed P-384 point
  0x0100: 256, // FFDHE-2048
};

/** ML-KEM modulus. */
const MLKEM_Q = 3329;

/**
 * Build a *canonical* ML-KEM encapsulation key.
 *
 * ML-KEM-768's public key is 384 NTT coefficients packed as 12-bit values,
 * followed by a 32-byte seed. Implementations reject a key whose coefficients
 * are >= q (3329), so uniformly random bytes fail to parse and the server
 * answers with a fatal `decode_error` alert. Reducing each coefficient modulo
 * q produces a key that passes the canonical-encoding check, which is all we
 * need: the probe reads the ServerHello and hangs up before encapsulation.
 *
 * @param {number} len total key length in bytes (1184 for ML-KEM-768)
 */
export function canonicalMlKemEk(len = 1184) {
  const out = crypto.randomBytes(len);
  const coeffBytes = len - 32;
  for (let i = 0; i + 2 < coeffBytes; i += 3) {
    const a = out[i] | ((out[i + 1] & 0x0f) << 8);
    const b = (out[i + 1] >> 4) | (out[i + 2] << 4);
    const ra = a % MLKEM_Q;
    const rb = b % MLKEM_Q;
    out[i] = ra & 0xff;
    out[i + 1] = ((ra >> 8) & 0x0f) | ((rb & 0x0f) << 4);
    out[i + 2] = (rb >> 4) & 0xff;
  }
  return out;
}

/** Build a syntactically valid key-share payload for a group. */
function keySharePayload(group) {
  const size = SHARE_SIZES[group];
  if (size >= 1000) {
    // draft-ietf-tls-ecdhe-mlkem: the ML-KEM encapsulation key comes first,
    // followed by the X25519 public key. Getting this order wrong makes
    // every hybrid-capable server answer with decode_error / illegal_parameter.
    return Buffer.concat([canonicalMlKemEk(size - 32), crypto.randomBytes(32)]);
  }
  return crypto.randomBytes(size);
}

/** Groups we offer, in order. Hybrid first so a capable server picks it. */
export const OFFERED_GROUPS = [0x11ec, 0x11eb, 0x6399, 0x001d, 0x0017, 0x0018, 0x0100];

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

const u8 = (n) => Buffer.from([n & 0xff]);
const u16 = (n) => {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n & 0xffff, 0);
  return b;
};
const u24 = (n) => Buffer.from([(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);

/** QUIC variable-length integer (RFC 9000 §16). */
export function quicVarint(value) {
  const n = Number(value);
  if (n < 0x40) return Buffer.from([n]);
  if (n < 0x4000) {
    const b = Buffer.alloc(2);
    b.writeUInt16BE(0x4000 | n, 0);
    return b;
  }
  if (n < 0x40000000) {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(0x80000000 | n, 0);
    return b;
  }
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(0xc000000000000000n | BigInt(n), 0);
  return b;
}

const extension = (type, data) => Buffer.concat([u16(type), u16(data.length), data]);

/** signature_algorithms we advertise, modern first. */
const SIGNATURE_ALGORITHMS = [
  // ML-DSA codepoints (draft-ietf-tls-mldsa)
  0x0904, // ML-DSA-44
  0x0905, // ML-DSA-65
  0x0906, // ML-DSA-87
  // modern classical
  0x0804, // rsa_pss_rsae_sha256
  0x0805, // rsa_pss_rsae_sha384
  0x0806, // rsa_pss_rsae_sha512
  0x0807, // ed25519
  0x0808, // ed448
  0x0809, // rsa_pss_pss_sha256
  0x080a, // rsa_pss_pss_sha384
  0x080b, // rsa_pss_pss_sha512
  0x0403, // ecdsa_secp256r1_sha256
  0x0503, // ecdsa_secp384r1_sha384
  0x0603, // ecdsa_secp521r1_sha512
  0x0401, // rsa_pkcs1_sha256
  0x0501, // rsa_pkcs1_sha384
  0x0601, // rsa_pkcs1_sha512
  // legacy, offered last so it never wins unless the server is ancient
  0x0303, // ecdsa_sha1
  0x0203, // rsa_pkcs1_sha1
  0x0201, // rsa_pkcs1_md5
];

const CIPHER_LIST = [
  0x1301, 0x1302, 0x1303,
  0xc02b, 0xc02f, 0xc02c, 0xc030,
  0xcca9, 0xcca8,
  0xc013, 0xc014, 0xc009, 0xc00a,
  0x009c, 0x009d, 0x002f, 0x0035, 0x000a, 0x0005, 0x0004,
];

/**
 * Build a TLS ClientHello record.
 * @param {{host:string, groups?:number[], alpn?:string[]}} opts
 * @returns {Buffer}
 */
export function buildClientHello({ host, groups = OFFERED_GROUPS, alpn = ['h2', 'http/1.1'], versions = [0x0304, 0x0303], sharePayload, quic }) {
  const exts = [];

  // server_name (0x0000)
  const hostBuf = Buffer.from(host, 'latin1');
  exts.push(
    extension(
      0x0000,
      Buffer.concat([u16(hostBuf.length + 3), u8(0), u16(hostBuf.length), hostBuf]),
    ),
  );

  // supported_groups (0x000a) — ordered by preference
  const groupList = Buffer.concat(groups.map(u16));
  exts.push(extension(0x000a, Buffer.concat([u16(groupList.length), groupList])));

  // signature_algorithms (0x000d)
  const sigList = Buffer.concat(SIGNATURE_ALGORITHMS.map(u16));
  exts.push(extension(0x000d, Buffer.concat([u16(sigList.length), sigList])));

  // supported_versions (0x002b)
  const versionList = Buffer.concat(versions.map(u16));
  exts.push(extension(0x002b, Buffer.concat([u8(versionList.length), versionList])));

  // key_share (0x0033): one share per offered group
  const shares = groups
    .filter((g) => SHARE_SIZES[g])
    .map((g) => {
      const payload = sharePayload ? sharePayload(g) : keySharePayload(g);
      return Buffer.concat([u16(g), u16(payload.length), payload]);
    });
  const shareBlock = Buffer.concat(shares);
  exts.push(extension(0x0033, Buffer.concat([u16(shareBlock.length), shareBlock])));

  // ALPN (0x0010)
  const alpnEntries = alpn.map((p) => Buffer.concat([u8(p.length), Buffer.from(p, 'latin1')]));
  const alpnBlock = Buffer.concat(alpnEntries);
  exts.push(extension(0x0010, Buffer.concat([u16(alpnBlock.length), alpnBlock])));

  // psk_key_exchange_modes (0x002d): psk_dhe_ke
  exts.push(extension(0x002d, Buffer.from([1, 1])));

  // QUIC transport parameters (0x0039). A QUIC server rejects a ClientHello
  // without an initial_source_connection_id, so the Initial probe needs one.
  if (quic) {
    const scid = Buffer.from(quic.scid || []);
    const params = Buffer.concat([quicVarint(0x0f), quicVarint(scid.length), scid]);
    exts.push(extension(0x0039, params));
  } else {
    // extended_master_secret (0x0017) — empty. TLS-over-TCP only.
    exts.push(extension(0x0017, Buffer.alloc(0)));
  }

  const extBlock = Buffer.concat(exts);

  const body = Buffer.concat([
    u16(0x0303), // legacy_version = TLS 1.2
    crypto.randomBytes(32), // random
    u8(32), // legacy_session_id length
    crypto.randomBytes(32), // session id (compat mode)
    u16(CIPHER_LIST.length * 2),
    Buffer.concat(CIPHER_LIST.map(u16)),
    u8(1), u8(0), // compression: null
    u16(extBlock.length),
    extBlock,
  ]);

  const handshake = Buffer.concat([u8(0x01), u24(body.length), body]);
  return Buffer.concat([u8(0x16), u16(0x0301), u16(handshake.length), handshake]);
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/**
 * Parse a ServerHello handshake body.
 * @param {Buffer} body
 */
export function parseServerHello(body) {
  let p = 0;
  const legacyVersion = body.readUInt16BE(p);
  p += 2;
  const random = body.subarray(p, p + 32);
  p += 32;
  const sidLen = body[p];
  p += 1 + sidLen;
  const cipherSuite = body.readUInt16BE(p);
  p += 2;
  p += 1; // compression method

  const result = {
    legacyVersion,
    cipherSuite,
    group: null,
    version: null,
    hrr: random.equals(HRR_RANDOM),
    alpn: null,
    raw: body,
  };

  if (p + 2 > body.length) return result;
  const extLen = body.readUInt16BE(p);
  p += 2;
  const end = Math.min(body.length, p + extLen);
  while (p + 4 <= end) {
    const type = body.readUInt16BE(p);
    const len = body.readUInt16BE(p + 2);
    p += 4;
    const data = body.subarray(p, p + len);
    p += len;
    if (type === 0x0033 && data.length >= 2) {
      result.group = data.readUInt16BE(0);
    } else if (type === 0x002b && data.length >= 2) {
      result.version = data.readUInt16BE(0);
    } else if (type === 0x0010 && data.length >= 3) {
      const alpnLen = data[2];
      result.alpn = data.subarray(3, 3 + alpnLen).toString('latin1');
    }
  }
  return result;
}

/**
 * Walk a TLS record stream and pull out every handshake message we care about.
 * @param {Buffer} buf
 */
export function parseServerFlight(buf) {
  const out = { serverHello: null, certDer: null, skeCurve: null, alert: null };
  let p = 0;
  while (p + 5 <= buf.length) {
    const type = buf[p];
    const recLen = buf.readUInt16BE(p + 3);
    if (p + 5 + recLen > buf.length) break;
    const rec = buf.subarray(p + 5, p + 5 + recLen);
    p += 5 + recLen;

    if (type === 0x15 && rec.length >= 2) {
      out.alert = { level: rec[0], description: rec[1] };
      continue;
    }
    if (type !== 0x16 || rec.length < 4) continue;

    let q = 0;
    while (q + 4 <= rec.length) {
      const hsType = rec[q];
      const hsLen = (rec[q + 1] << 16) | (rec[q + 2] << 8) | rec[q + 3];
      const hsBody = rec.subarray(q + 4, q + 4 + hsLen);
      q += 4 + hsLen;
      if (hsType === 0x02 && !out.serverHello) {
        out.serverHello = parseServerHello(hsBody);
      } else if (hsType === 0x0b && !out.certDer && hsBody.length > 6) {
        // TLS 1.2 Certificate: 3-byte list length, 3-byte cert length, DER
        const certLen = (hsBody[3] << 16) | (hsBody[4] << 8) | hsBody[5];
        out.certDer = hsBody.subarray(6, 6 + certLen);
      } else if (hsType === 0x0c && !out.skeCurve && hsBody.length > 3) {
        // ECDHE ServerKeyExchange starts with curve_type=3, then named_curve
        if (hsBody[0] === 0x03) out.skeCurve = hsBody.readUInt16BE(1);
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Network probe
// ---------------------------------------------------------------------------

/**
 * Send a ClientHello and read the server's first flight.
 * @param {{host:string, port?:number, servername?:string, timeout?:number}} opts
 * @returns {Promise<{version:number|null, cipherSuite:number, group:number|null,
 *                    hrr:boolean, alpn:string|null, certDer:Buffer|null, alert:any}>}
 */
export function probeServerHello({ host, port = 443, servername, timeout = 8000, versions }) {
  return new Promise((resolve, reject) => {
    const sni = servername || host;
    let settled = false;
    let buffer = Buffer.alloc(0);
    const socket = net.connect({ host, port });

    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      fn(value);
    };

    socket.setTimeout(timeout, () => {
      // A timeout after we already have a ServerHello is still useful.
      if (buffer.length > 0) {
        const parsed = parseServerFlight(buffer);
        if (parsed.serverHello) return finish(resolve, normalise(parsed));
      }
      finish(reject, new Error(`TLS probe timed out after ${timeout}ms`));
    });

    socket.on('connect', () => {
      socket.write(buildClientHello({ host: sni, versions }));
    });

    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      // Stop as soon as we have a ServerHello plus, if present, a certificate.
      if (buffer.length < 5) return;
      const recLen = buffer.readUInt16BE(3);
      if (buffer.length < 5 + recLen) return;
      const parsed = parseServerFlight(buffer);
      if (parsed.serverHello) {
        // Give the server a moment to send Certificate in the same flight;
        // for TLS 1.2 it arrives in the next record almost immediately.
        if (parsed.certDer || parsed.serverHello.version === 0x0304 || parsed.serverHello.hrr) {
          finish(resolve, normalise(parsed));
        } else {
          setTimeout(() => finish(resolve, normalise(parseServerFlight(buffer))), 120).unref?.();
        }
      }
    });

    socket.on('error', (err) => finish(reject, err));
    socket.on('close', () => {
      if (!settled) {
        if (buffer.length > 0) {
          const parsed = parseServerFlight(buffer);
          if (parsed.serverHello) return finish(resolve, normalise(parsed));
        }
        finish(reject, new Error('TLS probe closed before ServerHello'));
      }
    });
  });
}

function normalise(parsed) {
  const sh = parsed.serverHello;
  const version = sh?.version || sh?.legacyVersion || null;
  return {
    version,
    versionName: versionName(version),
    cipherSuite: sh?.cipherSuite ?? null,
    cipherName: CIPHER_SUITES[sh?.cipherSuite]?.name || null,
    group: sh?.group ?? parsed.skeCurve ?? null,
    groupName: GROUPS[sh?.group ?? parsed.skeCurve]?.name || null,
    hrr: Boolean(sh?.hrr),
    alpn: sh?.alpn || null,
    certDer: parsed.certDer || null,
    alert: parsed.alert || null,
  };
}

export function versionName(v) {
  switch (v) {
    case 0x0300: return 'SSL 3.0';
    case 0x0301: return 'TLS 1.0';
    case 0x0302: return 'TLS 1.1';
    case 0x0303: return 'TLS 1.2';
    case 0x0304: return 'TLS 1.3';
    default: return v ? `0x${v.toString(16)}` : 'unknown';
  }
}

/**
 * Describe the quantum posture of a negotiated group.
 * @param {number|null} group
 */
export function groupPosture(group) {
  if (group == null) return { status: 'unknown', label: 'unknown', hybrid: false };
  const g = GROUPS[group];
  if (!g) return { status: 'unknown', label: `0x${group.toString(16)}`, hybrid: false };
  return {
    status: g.quantum,
    label: g.label,
    name: g.name,
    hybrid: g.type === 'hybrid' || g.type === 'KEM',
    type: g.type,
    bits: g.bits,
  };
}
