/**
 * MOSCA — IKEv2 / IPsec probe
 * ===========================
 *
 * VPN gateways are the longest-lived cryptographic estate in most
 * organisations: a tunnel built in 2018 can still be carrying traffic in
 * 2035. Yet no web scanner sees them.
 *
 * RFC 9370 adds "Additional Key Exchange" (ADDKE) transforms to IKEv2, which
 * is how hybrid post-quantum key exchange reaches IPsec. This module sends a
 * standards-shaped IKE_SA_INIT and reads the responder's SA payload. If the
 * gateway negotiates an ADDKE transform, the tunnel can be hybrid; if it
 * answers NO_PROPOSAL_CHOSEN, it cannot.
 *
 * The probe never authenticates: IKE_SA_INIT is the first unauthenticated
 * exchange by design, and the socket is closed after the first response.
 */

import dgram from 'node:dgram';
import net from 'node:net';
import crypto from 'node:crypto';
import { canonicalMlKemEk } from './clienthello.js';

export const IKE_EXCHANGE = { IKE_SA_INIT: 34, IKE_AUTH: 35, INFORMATIONAL: 36 };
export const IKE_PAYLOAD = {
  SA: 33,
  KE: 34,
  NONCE: 40,
  NOTIFY: 41,
  VENDOR_ID: 43,
};

/** IKEv2 transform types. */
export const TRANSFORM = { ENCR: 1, PRF: 2, INTEG: 3, DH: 4, ESN: 5, ADDKE: 6 };

/** Provisional ML-KEM ADDKE transform identifiers. */
export const MLKEM_ADDKE_IDS = [35, 36, 37, 41, 42, 43];

const NOTIFY_NAMES = {
  1: 'UNSUPPORTED_CRITICAL_PAYLOAD',
  7: 'INVALID_SYNTAX',
  9: 'INVALID_MESSAGE_ID',
  11: 'NO_PROPOSAL_CHOSEN',
  14: 'NO_PROPOSAL_CHOSEN',
  17: 'INVALID_KE_PAYLOAD',
  24: 'INVALID_SYNTAX',
  34: 'SINGLE_PAIR_REQUIRED',
  35: 'NO_ADDITIONAL_SAS',
  36: 'INTERNAL_ADDRESS_FAILURE',
  37: 'FAILED_CP_REQUIRED',
  38: 'TS_UNACCEPTABLE',
  39: 'INVALID_SELECTORS',
  40: 'UNACCEPTABLE_ADDRESSES',
  41: 'UNEXPECTED_NAT_DETECTED',
  43: 'TEMPORARY_FAILURE',
  44: 'CHILD_SA_NOT_FOUND',
};

const u8 = (n) => Buffer.from([n & 0xff]);
const u16 = (n) => {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n & 0xffff);
  return b;
};

/** Generic IKEv2 payload header. */
function ikePayload(next, body) {
  return Buffer.concat([u8(next), u8(0), u16(body.length + 4), body]);
}

/**
 * One transform. `attributes` entries are [type, value] TV pairs.
 * @param {number} type
 * @param {number} id
 * @param {[number, number][]} [attributes]
 * @param {boolean} [last]
 */
export function buildTransform(type, id, attributes = [], last = false) {
  const attrs = attributes.map(([attrType, value]) => Buffer.concat([u16(0x8000 | attrType), u16(value)]));
  const body = Buffer.concat([u8(type), u8(0), u16(id), ...attrs]);
  return Buffer.concat([u8(last ? 1 : 0), u8(0), u16(body.length + 4), body]);
}

/**
 * One SA proposal. `addkeId` adds a type-6 transform for RFC 9370.
 * @param {{addkeId?:number|null, dhId?:number}} opts
 */
export function buildProposal({ addkeId = null, dhId = 31 } = {}) {
  const transforms = [
    // ENCR_AES_GCM_16 (20), 256-bit key
    buildTransform(TRANSFORM.ENCR, 20, [[14, 256]]),
    // PRF_HMAC_SHA2_256 (5)
    buildTransform(TRANSFORM.PRF, 5),
    // AUTH_HMAC_SHA2_256_128 (12)
    buildTransform(TRANSFORM.INTEG, 12),
    // DH group (31 = Curve25519)
    buildTransform(TRANSFORM.DH, dhId),
  ];
  if (addkeId != null) transforms.push(buildTransform(TRANSFORM.ADDKE, addkeId, [], true));
  else transforms[transforms.length - 1] = buildTransform(TRANSFORM.DH, dhId, [], true);

  const body = Buffer.concat([
    u8(1), // last proposal (single proposal)
    u8(0),
    u16(0), // length, patched
    u8(1), // proposal number
    u8(1), // protocol id: IKE
    u8(0), // SPI size
    u16(transforms.length),
    ...transforms,
  ]);
  body.writeUInt16BE(body.length, 2);
  return body;
}

/** The SA payload body: one proposal. */
export function buildSaBody(opts = {}) {
  return buildProposal(opts);
}

/** KE payload body for a Diffie-Hellman group. */
export function buildKeBody({ dhId = 31, key = crypto.randomBytes(32), additional = [] } = {}) {
  const main = Buffer.concat([u16(dhId), u16(0), u16(key.length), key]);
  const extras = additional.map(({ dhId: id, key: extraKey }) =>
    Buffer.concat([u16(id), u16(0), u16(extraKey.length), extraKey]),
  );
  return Buffer.concat([main, ...extras]);
}

/**
 * Build an IKE_SA_INIT request.
 * @param {{initiatorSpi?:Buffer, addkeId?:number|null, dhId?:number, includeAddkeKe?:boolean}} opts
 */
export function buildIkeSaInit({ initiatorSpi = crypto.randomBytes(8), addkeId = null, dhId = 31, includeAddkeKe = false } = {}) {
  const nonce = crypto.randomBytes(32);
  const additional = includeAddkeKe && addkeId != null ? [{ dhId: addkeId, key: canonicalMlKemEk(1184) }] : [];

  const saBody = buildSaBody({ addkeId, dhId });
  const keBody = buildKeBody({ dhId, additional });

  const sa = ikePayload(IKE_PAYLOAD.KE, saBody);
  const ke = ikePayload(IKE_PAYLOAD.NONCE, keBody);
  const noncePayload = ikePayload(0, nonce);

  const body = Buffer.concat([sa, ke, noncePayload]);
  const header = Buffer.alloc(28);
  initiatorSpi.copy(header, 0);
  // responder SPI stays zero
  header[16] = IKE_PAYLOAD.SA;
  header[17] = 0x20; // IKEv2
  header[18] = IKE_EXCHANGE.IKE_SA_INIT;
  header[19] = 0x08; // initiator flag
  header.writeUInt32BE(0, 20); // message id
  header.writeUInt32BE(28 + body.length, 24);
  return { packet: Buffer.concat([header, body]), initiatorSpi, nonce };
}

/**
 * Parse an IKEv2 message into its generic header and payload list.
 * @param {Buffer} buf
 */
export function parseIkeMessage(buf) {
  if (buf.length < 28) throw new Error('IKEv2 message shorter than its header');
  const header = {
    initiatorSpi: buf.subarray(0, 8),
    responderSpi: buf.subarray(8, 16),
    nextPayload: buf[16],
    majorVersion: buf[17] >> 4,
    minorVersion: buf[17] & 0x0f,
    exchangeType: buf[18],
    flags: buf[19],
    messageId: buf.readUInt32BE(20),
    length: buf.readUInt32BE(24),
  };

  const payloads = [];
  let next = header.nextPayload;
  let p = 28;
  while (next !== 0 && p + 4 <= Math.min(buf.length, header.length)) {
    const length = buf.readUInt16BE(p + 2);
    if (length < 4 || p + length > buf.length) break;
    payloads.push({ type: next, body: buf.subarray(p + 4, p + length) });
    next = buf[p];
    p += length;
  }
  return { header, payloads };
}

/** Parse the SA payload body into proposals and transforms. */
export function parseSaPayload(body) {
  const proposals = [];
  let p = 0;
  while (p + 9 <= body.length) {
    const last = body[p];
    const length = body.readUInt16BE(p + 2);
    if (length < 9 || p + length > body.length) break;
    const protocolId = body[p + 5];
    const spiSize = body[p + 6];
    const transformCount = body.readUInt16BE(p + 7);
    let q = p + 9 + spiSize;
    const transforms = [];
    for (let i = 0; i < transformCount && q + 8 <= p + length; i++) {
      const tLast = body[q];
      const tLength = body.readUInt16BE(q + 2);
      if (tLength < 8 || q + tLength > p + length) break;
      transforms.push({
        type: body[q + 4],
        id: body.readUInt16BE(q + 6),
        length: tLength,
      });
      q += tLength;
      if (tLast) break;
    }
    proposals.push({ number: body[p + 4], protocolId, spiSize, transforms });
    p += length;
    if (last) break;
  }
  return proposals;
}

/** Parse a Notify payload. */
export function parseNotify(body) {
  if (body.length < 4) return null;
  const protocolId = body[0];
  const spiSize = body[1];
  const type = body.readUInt16BE(2);
  return {
    protocolId,
    type,
    name: NOTIFY_NAMES[type] || `NOTIFY_${type}`,
    data: body.subarray(4 + spiSize),
  };
}

/**
 * Interpret a responder packet.
 * @param {Buffer} buf
 */
export function interpretIkeResponse(buf) {
  const { header, payloads } = parseIkeMessage(buf);
  const proposals = [];
  const notifies = [];
  for (const payload of payloads) {
    if (payload.type === IKE_PAYLOAD.SA) proposals.push(...parseSaPayload(payload.body));
    if (payload.type === IKE_PAYLOAD.NOTIFY) {
      const notify = parseNotify(payload.body);
      if (notify) notifies.push(notify);
    }
  }
  const transforms = proposals.flatMap((p) => p.transforms);
  const addke = transforms.filter((t) => t.type === TRANSFORM.ADDKE);
  const dh = transforms.filter((t) => t.type === TRANSFORM.DH);
  const noProposal = notifies.some((n) => n.type === 11 || n.type === 14);
  const invalidKe = notifies.some((n) => n.type === 17);

  return {
    header,
    payloads,
    proposals,
    notifies,
    transforms,
    accepted: proposals.length > 0,
    noProposal,
    invalidKe,
    addke,
    dh,
    addkeSupported: addke.length > 0,
  };
}

/** Send one datagram and resolve with the first reply. */
function exchange(socket, host, port, packet, timeout) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.off('message', onMessage);
      socket.off('error', onError);
      fn(value);
    };
    const onMessage = (message) => done(resolve, message);
    const onError = (err) => done(reject, err);
    const timer = setTimeout(() => done(reject, new Error(`IKEv2 probe timed out after ${timeout}ms`)), timeout);

    socket.on('message', onMessage);
    socket.on('error', onError);
    socket.send(packet, port, host, (err) => {
      if (err) done(reject, err);
    });
  });
}

/**
 * Probe an IKEv2 gateway.
 *
 * First the classic proposal, then one hybrid probe per provisional ADDKE
 * transform id. A response that is not NO_PROPOSAL_CHOSEN to a hybrid offer
 * is evidence that the gateway understands ADDKE.
 *
 * @param {{host:string, port?:number, timeout?:number, addkeIds?:number[]}} opts
 */
export async function probeIkev2({ host, port = 500, timeout = 2000, addkeIds = MLKEM_ADDKE_IDS }) {
  const family = net.isIPv6(host) ? 'udp6' : 'udp4';
  const socket = dgram.createSocket(family);
  try {
    const classic = buildIkeSaInit({ dhId: 31 });
    const classicReply = await exchange(socket, host, port, classic.packet, timeout);
    const classicResult = interpretIkeResponse(classicReply);

    const result = {
      reachable: true,
      classic: {
        accepted: classicResult.accepted,
        noProposal: classicResult.noProposal,
        invalidKe: classicResult.invalidKe,
        notifies: classicResult.notifies.map((n) => n.name),
        dh: classicResult.dh.map((t) => t.id),
      },
      addke: {
        supported: false,
        transformId: null,
        notifies: [],
        attempts: 0,
      },
      responderSpi: classicResult.header.responderSpi.toString('hex'),
    };

    if (!classicResult.noProposal) {
      for (const addkeId of addkeIds) {
        result.addke.attempts += 1;
        try {
          const hybrid = buildIkeSaInit({ dhId: 31, addkeId, includeAddkeKe: true });
          const reply = await exchange(socket, host, port, hybrid.packet, timeout);
          const interpreted = interpretIkeResponse(reply);
          if (!interpreted.noProposal) {
            result.addke.supported = true;
            result.addke.transformId = interpreted.addke[0]?.id ?? addkeId;
            result.addke.notifies = interpreted.notifies.map((n) => n.name);
            result.addke.accepted = interpreted.accepted;
            break;
          }
          result.addke.notifies = interpreted.notifies.map((n) => n.name);
        } catch {
          // A gateway may silently drop oversized or unknown hybrid offers.
        }
      }
    }

    return result;
  } finally {
    try {
      socket.close();
    } catch {
      /* already closed */
    }
  }
}

/**
 * Inspect an IKEv2 gateway and derive unified findings.
 * @param {string} target `ikev2://host:500` or `host:500`
 * @param {{timeout?:number}} opts
 */
export async function inspectIkev2(target, opts = {}) {
  const { timeout = 2000 } = opts;
  const raw = String(target).replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').split('/')[0];
  const bracket = /^\[([^\]]+)\](?::(\d+))?$/.exec(raw);
  let host = raw;
  let port = 500;
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

  const result = {
    target: String(target),
    host,
    port,
    reachable: false,
    error: null,
    classic: null,
    addke: null,
    findings: [],
  };

  try {
    Object.assign(result, await probeIkev2({ host, port, timeout, addkeIds: opts.addkeIds }));
    result.reachable = true;
  } catch (err) {
    result.error = err.message;
  }

  result.findings = deriveIkeFindings(result);
  return result;
}

/** Turn an IKEv2 result into unified findings. */
export function deriveIkeFindings(ep) {
  const findings = [];
  if (!ep.reachable) return findings;
  const where = { host: ep.host, port: ep.port, target: ep.target, protocol: 'ikev2' };

  if (ep.addke?.supported) {
    findings.push({
      id: 'ikev2-addke-supported',
      kind: 'endpoint',
      title: `IKEv2 gateway accepts ADDKE hybrid key exchange (transform ${ep.addke.transformId})`,
      algorithm: 'x25519mlkem768',
      primitive: 'key-agreement',
      location: where,
      confidence: 'medium',
      positive: true,
      note: 'RFC 9370 additional key exchange is understood by the gateway. Confirm that the hybrid proposal is actually preferred in production policy.',
      evidence: { transformId: ep.addke.transformId, notifies: ep.addke.notifies },
    });
  } else {
    findings.push({
      id: 'ikev2-classical-kex',
      kind: 'endpoint',
      title: 'IKEv2 gateway negotiates classical Diffie-Hellman only',
      algorithm: ep.classic?.dh?.[0] === 31 ? 'x25519' : 'dh',
      primitive: 'key-agreement',
      location: where,
      confidence: 'medium',
      note: 'IPsec tunnels are long-lived and carry site-to-site traffic that cannot be re-keyed retroactively. Add an RFC 9370 hybrid proposal once the gateway firmware supports ML-KEM.',
      evidence: {
        classicDh: ep.classic?.dh || [],
        addkeAttempts: ep.addke?.attempts ?? 0,
        notifies: ep.addke?.notifies || ep.classic?.notifies || [],
      },
    });
  }
  return findings;
}
