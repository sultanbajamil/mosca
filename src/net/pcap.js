/**
 * MOSCA — passive PCAP / PCAPNG harvester
 * =======================================
 *
 * Harvest-now-decrypt-later starts with a recording. This module reads one:
 * a packet capture already sitting on disk, with no packets sent and no
 * authentication performed. It unwraps Ethernet, 802.1Q, Linux SLL, IPv4 and
 * IPv6, reassembles enough of each TCP direction to read the clear-text
 * handshake, and asks the same question the live probes ask:
 *
 *   what did this session actually negotiate, and when does the recording
 *   become readable?
 *
 * TLS ClientHello / ServerHello and SSH identification / SSH_MSG_KEXINIT are
 * parsed directly from the capture. The exposure calculation is anchored to
 * the capture timestamp, not to the day the report was generated: a session
 * recorded in 2014 has had longer to fall inside the Mosca window than one
 * recorded this morning.
 *
 * Only node:fs and Buffer are used. No native packet library, no external
 * service, and no traffic emitted from the scanning host.
 */

import fs from 'node:fs';
import path from 'node:path';
import {
  GROUPS,
  CIPHER_SUITES,
  parseServerHello,
  groupPosture,
  versionName,
} from './clienthello.js';
import {
  parseBanner,
  parseKexInit,
  parsePacket,
  classifySshKex,
  HYBRID_KEX,
  WEAK_KEX,
  LEGACY_HOST_KEYS,
  WEAK_CIPHERS,
  WEAK_MACS,
} from './ssh.js';
import { lookup } from '../rules/algorithms.js';
import { resolveCrqcYear } from '../config.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Classic libpcap magic numbers, read as big-endian. */
export const PCAP_MAGIC = {
  0xa1b2c3d4: { endian: 'be', resolution: 'micro' },
  0xd4c3b2a1: { endian: 'le', resolution: 'micro' },
  0xa1b23c4d: { endian: 'be', resolution: 'nano' },
  0x4d3cb2a1: { endian: 'le', resolution: 'nano' },
};

/** PCAPNG block types. */
export const PCAPNG = {
  SHB: 0x0a0d0d0a,
  IDB: 0x00000001,
  SPB: 0x00000003,
  EPB: 0x00000006,
  BYTE_ORDER_MAGIC: 0x1a2b3c4d,
};

/** Link-layer types we understand. */
export const LINKTYPE = {
  0: 'null',
  1: 'ethernet',
  12: 'raw',
  101: 'raw',
  108: 'loopback',
  113: 'linux-sll',
  276: 'linux-sll2',
};

const VLAN_TYPES = new Set([0x8100, 0x88a8, 0x9100, 0x9200]);

// ---------------------------------------------------------------------------
// Small binary helpers
// ---------------------------------------------------------------------------

function read16(buf, offset, endian = 'be') {
  return endian === 'le' ? buf.readUInt16LE(offset) : buf.readUInt16BE(offset);
}

function read32(buf, offset, endian = 'be') {
  return endian === 'le' ? buf.readUInt32LE(offset) : buf.readUInt32BE(offset);
}

function formatIPv6(buf) {
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push(buf.readUInt16BE(i).toString(16));
  // Compress the longest run of zero groups, as RFC 5952 recommends.
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < groups.length; ) {
    if (groups[i] !== '0') {
      i++;
      continue;
    }
    let j = i;
    while (j < groups.length && groups[j] === '0') j++;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  if (bestLen > 1) {
    const head = groups.slice(0, bestStart).join(':');
    const tail = groups.slice(bestStart + bestLen).join(':');
    return `${head}::${tail}`;
  }
  return groups.join(':');
}

// ---------------------------------------------------------------------------
// PCAP reader
// ---------------------------------------------------------------------------

/**
 * Parse a classic libpcap file.
 * @param {Buffer} buffer
 * @param {{file?:string}} [opts]
 */
export function parsePcap(buffer, opts = {}) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 24) {
    throw new Error('PCAP file is truncated: a global header needs 24 bytes');
  }
  const magic = buffer.readUInt32BE(0);
  const format = PCAP_MAGIC[magic];
  if (!format) {
    throw new Error(`Unrecognised PCAP magic 0x${magic.toString(16).padStart(8, '0')}`);
  }
  const { endian, resolution } = format;
  const linkType = read32(buffer, 20, endian);
  const snapLength = read32(buffer, 16, endian);
  const versionMajor = read16(buffer, 4, endian);
  const versionMinor = read16(buffer, 6, endian);
  const packets = [];

  let offset = 24;
  let index = 0;
  while (offset + 16 <= buffer.length) {
    const tsSec = read32(buffer, offset, endian);
    const tsFrac = read32(buffer, offset + 4, endian);
    const inclLen = read32(buffer, offset + 8, endian);
    const origLen = read32(buffer, offset + 12, endian);
    offset += 16;
    if (inclLen > buffer.length - offset) break; // truncated final record
    const data = buffer.subarray(offset, offset + inclLen);
    offset += inclLen;

    const ts = tsSec + tsFrac / (resolution === 'nano' ? 1e9 : 1e6);
    const decoded = decodeFrame(linkType, data);
    if (decoded) {
      packets.push({
        index,
        ts,
        tsSec,
        tsFrac,
        origLen,
        ...decoded,
      });
    }
    index += 1;
  }

  return {
    format: 'pcap',
    file: opts.file || null,
    endian,
    resolution,
    linkType,
    linkTypeName: LINKTYPE[linkType] || `linktype-${linkType}`,
    version: `${versionMajor}.${versionMinor}`,
    snapLength,
    packetCount: packets.length,
    packets,
  };
}

// ---------------------------------------------------------------------------
// PCAPNG reader
// ---------------------------------------------------------------------------

/**
 * Parse a PCAPNG file: Section Header, Interface Description, Enhanced Packet
 * and Simple Packet blocks are the ones a capture tool emits in practice.
 * @param {Buffer} buffer
 * @param {{file?:string}} [opts]
 */
export function parsePcapng(buffer, opts = {}) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) {
    throw new Error('PCAPNG file is truncated: a Section Header Block needs 12 bytes');
  }
  let offset = 0;
  let endian = 'le';
  let sawSection = false;
  const interfaces = [];
  const packets = [];

  while (offset + 12 <= buffer.length) {
    const bareType = buffer.readUInt32BE(offset);
    if (bareType === PCAPNG.SHB) {
      const magic = buffer.readUInt32BE(offset + 8);
      if (magic === PCAPNG.BYTE_ORDER_MAGIC) endian = 'be';
      else if (magic === 0x4d3c2b1a) endian = 'le';
      else throw new Error('PCAPNG Section Header Block has an invalid byte-order magic');
      sawSection = true;
    }
    if (!sawSection) throw new Error('PCAPNG file does not start with a Section Header Block');

    const blockType = read32(buffer, offset, endian);
    const blockLength = read32(buffer, offset + 4, endian);
    if (blockLength < 12 || offset + blockLength > buffer.length) break;
    const body = buffer.subarray(offset + 8, offset + blockLength - 4);
    const next = offset + blockLength;

    if (blockType === PCAPNG.IDB) {
      const linkType = read16(body, 0, endian);
      const snaplen = read32(body, 4, endian);
      let unitsPerSecond = 1e6;
      let p = 8;
      while (p + 4 <= body.length) {
        const code = read16(body, p, endian);
        const len = read16(body, p + 2, endian);
        p += 4;
        if (code === 0) break;
        if (p + len > body.length) break;
        if (code === 9 && len >= 1) {
          const value = body[p];
          unitsPerSecond = value & 0x80
            ? Math.pow(2, -(value & 0x7f))
            : Math.pow(10, value);
        }
        p += Math.ceil(len / 4) * 4;
      }
      interfaces.push({ linkType, snaplen, unitsPerSecond });
    } else if (blockType === PCAPNG.EPB && body.length >= 20) {
      const interfaceId = read32(body, 0, endian);
      const tsHigh = read32(body, 4, endian);
      const tsLow = read32(body, 8, endian);
      const inclLen = read32(body, 12, endian);
      const origLen = read32(body, 16, endian);
      if (20 + inclLen <= body.length) {
        const iface = interfaces[interfaceId] || interfaces[0] || { linkType: 1, unitsPerSecond: 1e6 };
        const rawTs = tsHigh * 0x100000000 + tsLow;
        const ts = rawTs / iface.unitsPerSecond;
        const data = body.subarray(20, 20 + inclLen);
        const decoded = decodeFrame(iface.linkType, data);
        if (decoded) {
          packets.push({
            index: packets.length,
            ts,
            tsSec: Math.floor(ts),
            tsFrac: Math.round((ts % 1) * 1e6),
            origLen,
            interfaceId,
            ...decoded,
          });
        }
      }
    } else if (blockType === PCAPNG.SPB && body.length >= 4) {
      const iface = interfaces[0] || { linkType: 1, unitsPerSecond: 1e6 };
      const origLen = read32(body, 0, endian);
      const data = body.subarray(4);
      const decoded = decodeFrame(iface.linkType, data);
      if (decoded) {
        packets.push({
          index: packets.length,
          ts: null,
          tsSec: null,
          tsFrac: null,
          origLen,
          interfaceId: 0,
          ...decoded,
        });
      }
    }

    offset = next;
  }

  return {
    format: 'pcapng',
    file: opts.file || null,
    endian,
    resolution: 'interface',
    linkType: interfaces[0]?.linkType ?? null,
    linkTypeName: LINKTYPE[interfaces[0]?.linkType] || (interfaces.length ? `linktype-${interfaces[0].linkType}` : 'unknown'),
    interfaces,
    packetCount: packets.length,
    packets,
  };
}

/**
 * Auto-detect and parse either capture format.
 * @param {Buffer} buffer
 * @param {{file?:string}} [opts]
 */
export function parsePcapBuffer(buffer, opts = {}) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 4) throw new Error('Capture file is empty');
  const magic = buffer.readUInt32BE(0);
  if (magic === PCAPNG.SHB) return parsePcapng(buffer, opts);
  if (PCAP_MAGIC[magic]) return parsePcap(buffer, opts);
  throw new Error(`Unrecognised capture format (first four bytes: 0x${magic.toString(16).padStart(8, '0')})`);
}

// ---------------------------------------------------------------------------
// Link and network layers
// ---------------------------------------------------------------------------

/** Decode a link-layer frame into src/dst IP, TCP ports and payload. */
export function decodeFrame(linkType, frame) {
  if (!Buffer.isBuffer(frame) || frame.length === 0) return null;
  switch (linkType) {
    case 1:
      return decodeEthernet(frame);
    case 113:
      return decodeSll(frame);
    case 276:
      return decodeSll2(frame);
    case 0:
    case 108:
      return decodeNull(frame);
    case 12:
    case 101:
      return decodeIp(frame);
    default:
      // Unknown link type: try Ethernet last, it is the most common capture.
      return decodeEthernet(frame) || decodeIp(frame);
  }
}

function decodeEthernet(frame) {
  if (frame.length < 14) return null;
  let type = frame.readUInt16BE(12);
  let l3 = 14;
  let guard = 0;
  while (VLAN_TYPES.has(type) && guard++ < 4) {
    if (frame.length < l3 + 4) return null;
    l3 += 4;
    type = frame.readUInt16BE(l3 - 2);
  }
  if (type === 0x0800 || type === 0x86dd) return decodeIp(frame.subarray(l3));
  if (type === 0x0806) return null; // ARP carries no transport session
  return null;
}

function decodeSll(frame) {
  if (frame.length < 16) return null;
  const protocol = frame.readUInt16BE(14);
  if (protocol !== 0x0800 && protocol !== 0x86dd) return null;
  return decodeIp(frame.subarray(16));
}

function decodeSll2(frame) {
  if (frame.length < 20) return null;
  const protocol = frame.readUInt16BE(0);
  if (protocol !== 0x0800 && protocol !== 0x86dd) return null;
  return decodeIp(frame.subarray(20));
}

function decodeNull(frame) {
  if (frame.length < 5) return null;
  const le = frame.readUInt32LE(0);
  const be = frame.readUInt32BE(0);
  const family = le === 2 || le === 30 ? le : be === 2 || be === 30 ? be : null;
  if (family === 2 || family === 30) return decodeIp(frame.subarray(4));
  return decodeIp(frame.subarray(4));
}

function decodeIp(packet) {
  if (!packet || packet.length < 1) return null;
  const version = packet[0] >> 4;
  if (version === 4) return decodeIPv4(packet);
  if (version === 6) return decodeIPv6(packet);
  return null;
}

function decodeIPv4(packet) {
  if (packet.length < 20) return null;
  const ihl = (packet[0] & 0x0f) * 4;
  if (ihl < 20 || packet.length < ihl) return null;
  const totalLength = packet.readUInt16BE(2);
  const protocol = packet[9];
  const srcIP = `${packet[12]}.${packet[13]}.${packet[14]}.${packet[15]}`;
  const dstIP = `${packet[16]}.${packet[17]}.${packet[18]}.${packet[19]}`;
  // A non-first fragment has no TCP header; skip it rather than misparse.
  const fragment = packet.readUInt16BE(6);
  if ((fragment & 0x1fff) !== 0) return null;
  const end = totalLength >= ihl && totalLength <= packet.length ? totalLength : packet.length;
  const l4 = packet.subarray(ihl, end);
  if (protocol !== 6) return null;
  const tcp = decodeTcp(l4);
  return tcp ? { srcIP, dstIP, ...tcp } : null;
}

function decodeIPv6(packet) {
  if (packet.length < 40) return null;
  const payloadLength = packet.readUInt16BE(4);
  let nextHeader = packet[6];
  const srcIP = formatIPv6(packet.subarray(8, 24));
  const dstIP = formatIPv6(packet.subarray(24, 40));
  let offset = 40;
  let guard = 0;
  while ([0, 43, 44, 51, 60].includes(nextHeader) && guard++ < 8) {
    if (offset + 2 > packet.length) return null;
    const following = packet[offset];
    let headerLength;
    if (nextHeader === 44) {
      // Fragment header: only the first fragment carries the TCP header.
      if (offset + 8 > packet.length) return null;
      const fragmentField = packet.readUInt16BE(offset + 2);
      if ((fragmentField & 0xfff8) !== 0) return null;
      headerLength = 8;
    } else if (nextHeader === 51) {
      headerLength = (packet[offset + 1] + 2) * 4;
    } else {
      headerLength = (packet[offset + 1] + 1) * 8;
    }
    nextHeader = following;
    offset += headerLength;
    if (offset > packet.length) return null;
  }
  if (nextHeader !== 6) return null;
  const end = payloadLength > 0 ? Math.min(packet.length, 40 + payloadLength) : packet.length;
  const tcp = decodeTcp(packet.subarray(offset, end));
  return tcp ? { srcIP, dstIP, ...tcp } : null;
}

function decodeTcp(segment) {
  if (!segment || segment.length < 20) return null;
  const srcPort = segment.readUInt16BE(0);
  const dstPort = segment.readUInt16BE(2);
  const seq = segment.readUInt32BE(4);
  const dataOffset = (segment[12] >> 4) * 4;
  const flags = segment[13];
  if (dataOffset < 20 || dataOffset > segment.length) return null;
  const payload = segment.subarray(dataOffset);
  return { srcPort, dstPort, seq, flags, payload };
}

// ---------------------------------------------------------------------------
// TCP flow assembly
// ---------------------------------------------------------------------------

function flowKey(packet) {
  const a = `${packet.srcIP}:${packet.srcPort}`;
  const b = `${packet.dstIP}:${packet.dstPort}`;
  return a <= b ? `${a}|${b}` : `${b}|${a}`;
}

function endpoint(packet, side) {
  return side === 'a'
    ? { ip: packet.srcIP, port: packet.srcPort }
    : { ip: packet.dstIP, port: packet.dstPort };
}

function direction(flow, packet) {
  if (packet.srcIP === flow.a.ip && packet.srcPort === flow.a.port) return 'a';
  if (packet.srcIP === flow.b.ip && packet.srcPort === flow.b.port) return 'b';
  return 'a';
}

function newFlow(packet) {
  return {
    a: { ip: packet.srcIP, port: packet.srcPort },
    b: { ip: packet.dstIP, port: packet.dstPort },
    initiator: 'a',
    firstTs: packet.ts,
    lastTs: packet.ts,
    tls: {
      a: { buffer: Buffer.alloc(0), handshake: Buffer.alloc(0), clientHello: null, serverHello: null, records: 0 },
      b: { buffer: Buffer.alloc(0), handshake: Buffer.alloc(0), clientHello: null, serverHello: null, records: 0 },
    },
    ssh: {
      a: { buffer: Buffer.alloc(0), banner: null, kex: null, bannerTs: null, kexTs: null, packets: 0 },
      b: { buffer: Buffer.alloc(0), banner: null, kex: null, bannerTs: null, kexTs: null, packets: 0 },
    },
  };
}

function looksLikeTls(buffer) {
  return buffer.length >= 5 && buffer[0] >= 0x14 && buffer[0] <= 0x18 && buffer[1] === 0x03;
}

function drainTls(state, payload, timestamp) {
  if (payload.length === 0) return;
  // A flow that has already produced TLS records keeps its state. A new flow
  // whose first payload is not a TLS record is ignored rather than parsed as
  // garbage.
  if (state.buffer.length === 0 && state.records === 0 && !looksLikeTls(payload)) return;
  state.buffer = Buffer.concat([state.buffer, payload]);

  let guard = 0;
  while (state.buffer.length >= 5 && guard++ < 512) {
    const type = state.buffer[0];
    const major = state.buffer[1];
    const length = state.buffer.readUInt16BE(3);
    if (type < 0x14 || type > 0x18 || major !== 0x03 || length > 18432) {
      state.buffer = Buffer.alloc(0);
      return;
    }
    if (state.buffer.length < 5 + length) break;
    const record = state.buffer.subarray(5, 5 + length);
    state.buffer = state.buffer.subarray(5 + length);
    state.records += 1;
    if (type !== 0x16) continue; // application data, alert, CCS
    state.handshake = Buffer.concat([state.handshake, record]);
    drainHandshake(state);
  }
  if (!state.firstTs) state.firstTs = timestamp;
}

function drainHandshake(state) {
  let guard = 0;
  while (state.handshake.length >= 4 && guard++ < 64) {
    const type = state.handshake[0];
    const length = (state.handshake[1] << 16) | (state.handshake[2] << 8) | state.handshake[3];
    if (length > 1024 * 1024) {
      state.handshake = Buffer.alloc(0);
      return;
    }
    if (state.handshake.length < 4 + length) break;
    const body = state.handshake.subarray(4, 4 + length);
    state.handshake = state.handshake.subarray(4 + length);
    if (type === 0x01 && !state.clientHello) {
      state.clientHello = parseClientHelloBody(body);
    } else if (type === 0x02 && !state.serverHello) {
      state.serverHello = parseServerHello(body);
    }
  }
}

function drainSsh(state, payload, timestamp) {
  if (payload.length === 0) return;
  state.buffer = Buffer.concat([state.buffer, payload]);

  // Identification strings are line-oriented and may be preceded by comments.
  let guard = 0;
  while (!state.banner && guard++ < 16) {
    const newline = state.buffer.indexOf(0x0a);
    if (newline === -1) break;
    const line = state.buffer.subarray(0, newline).toString('latin1').replace(/\r$/, '');
    state.buffer = state.buffer.subarray(newline + 1);
    if (/^SSH-(1\.99|2\.0)-/.test(line)) {
      state.banner = parseBanner(line);
      state.bannerTs = timestamp;
    }
  }
  if (!state.banner) return;

  let packets = 0;
  while (packets < 16) {
    let packet;
    try {
      packet = parsePacket(state.buffer);
    } catch {
      state.buffer = Buffer.alloc(0);
      return;
    }
    if (!packet) break;
    state.buffer = state.buffer.subarray(packet.consumed);
    state.packets += 1;
    packets += 1;
    if (packet.payload[0] === 20 && !state.kex) {
      try {
        state.kex = parseKexInit(packet.payload);
        state.kexTs = timestamp;
      } catch {
        // An unparseable KEXINIT is not fatal for the rest of the flow.
      }
    }
  }
}

/**
 * Parse a TLS ClientHello handshake body.
 * @param {Buffer} body
 */
export function parseClientHelloBody(body) {
  if (!Buffer.isBuffer(body) || body.length < 34) {
    throw new Error('truncated TLS ClientHello');
  }
  let p = 0;
  const legacyVersion = body.readUInt16BE(p);
  p += 2;
  const random = body.subarray(p, p + 32);
  p += 32;
  const sessionIdLength = body[p];
  p += 1 + sessionIdLength;
  if (p + 2 > body.length) throw new Error('truncated TLS ClientHello cipher list');
  const cipherLength = body.readUInt16BE(p);
  p += 2;
  const cipherSuites = [];
  for (let i = 0; i + 1 < cipherLength && p + i + 1 < body.length; i += 2) {
    cipherSuites.push(body.readUInt16BE(p + i));
  }
  p += cipherLength;
  if (p + 1 > body.length) throw new Error('truncated TLS ClientHello compression list');
  const compressionLength = body[p];
  p += 1 + compressionLength;
  if (p + 2 > body.length) {
    return { legacyVersion, random, cipherSuites, supportedGroups: [], keyShares: [], sni: null, alpn: [], supportedVersions: [] };
  }
  const extensionLength = body.readUInt16BE(p);
  p += 2;
  const end = Math.min(body.length, p + extensionLength);
  const result = {
    legacyVersion,
    random,
    cipherSuites,
    supportedGroups: [],
    keyShares: [],
    sni: null,
    alpn: [],
    supportedVersions: [],
  };

  while (p + 4 <= end) {
    const type = body.readUInt16BE(p);
    const length = body.readUInt16BE(p + 2);
    p += 4;
    if (p + length > end) break;
    const data = body.subarray(p, p + length);
    p += length;

    if (type === 0x0000 && data.length >= 5) {
      // server_name: list length, name type, name length, name
      const nameType = data[2];
      const nameLength = data.readUInt16BE(3);
      if (nameType === 0 && 5 + nameLength <= data.length) {
        result.sni = data.subarray(5, 5 + nameLength).toString('latin1');
      }
    } else if (type === 0x000a && data.length >= 2) {
      const listLength = data.readUInt16BE(0);
      for (let i = 2; i + 1 < Math.min(data.length, 2 + listLength); i += 2) {
        result.supportedGroups.push(data.readUInt16BE(i));
      }
    } else if (type === 0x0033 && data.length >= 2) {
      const listLength = data.readUInt16BE(0);
      let q = 2;
      while (q + 4 <= Math.min(data.length, 2 + listLength)) {
        const group = data.readUInt16BE(q);
        const shareLength = data.readUInt16BE(q + 2);
        q += 4 + shareLength;
        result.keyShares.push(group);
      }
    } else if (type === 0x002b && data.length >= 1) {
      const listLength = data[0];
      for (let i = 1; i + 1 < Math.min(data.length, 1 + listLength); i += 2) {
        result.supportedVersions.push(data.readUInt16BE(i));
      }
    } else if (type === 0x0010 && data.length >= 2) {
      const listLength = data.readUInt16BE(0);
      let q = 2;
      while (q + 1 <= Math.min(data.length, 2 + listLength)) {
        const len = data[q];
        q += 1;
        if (q + len > data.length) break;
        result.alpn.push(data.subarray(q, q + len).toString('latin1'));
        q += len;
      }
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Session extraction
// ---------------------------------------------------------------------------

function buildTlsSession(flow, parsed, opts) {
  const a = flow.tls.a;
  const b = flow.tls.b;
  let clientDir = a.clientHello ? 'a' : b.clientHello ? 'b' : null;
  let serverDir = a.serverHello ? 'a' : b.serverHello ? 'b' : null;
  if (!clientDir && serverDir) clientDir = serverDir === 'a' ? 'b' : 'a';
  if (!serverDir && clientDir) serverDir = clientDir === 'a' ? 'b' : 'a';
  if (!clientDir && !serverDir) return null;

  const client = (clientDir ? flow.tls[clientDir] : null) || {};
  const server = (serverDir ? flow.tls[serverDir] : null) || {};
  const clientEp = clientDir ? endpointFor(flow, clientDir) : null;
  const serverEp = serverDir ? endpointFor(flow, serverDir) : null;
  const hello = client.clientHello || {};
  const shello = server.serverHello || {};
  const versionCode = shello.version || shello.legacyVersion || hello.supportedVersions?.[0] || hello.legacyVersion || null;
  const group = shello.group ?? null;
  const posture = groupPosture(group);
  const cipherSuite = shello.cipherSuite ?? hello.cipherSuites?.[0] ?? null;
  const cipher = CIPHER_SUITES[cipherSuite] || null;
  const captureTs = flow.firstTs;
  const serverName = hello.sni || serverEp?.ip || clientEp?.ip || 'unknown';

  const tls = {
    clientHello: Boolean(client.clientHello),
    serverHello: Boolean(server.serverHello),
    versionCode,
    protocol: versionName(versionCode),
    cipherSuite,
    cipherName: cipher?.name || null,
    group,
    groupName: posture.name || null,
    groupLabel: posture.label || null,
    groupType: posture.type || null,
    hybrid: Boolean(posture.hybrid),
    sni: hello.sni || null,
    clientOfferedGroups: (hello.supportedGroups || []).map((id) => ({
      id,
      name: GROUPS[id]?.name || `0x${id.toString(16)}`,
      label: GROUPS[id]?.label || `0x${id.toString(16)}`,
      hybrid: Boolean(GROUPS[id]?.type === 'hybrid' || GROUPS[id]?.quantum === 'safe'),
    })),
    clientKeyShares: (hello.keyShares || []).map((id) => GROUPS[id]?.name || `0x${id.toString(16)}`),
    alpn: shello.alpn || (hello.alpn?.[0] || null),
  };

  return finaliseSession({
    protocol: 'tls',
    flow,
    client: clientEp,
    server: { ...serverEp, name: serverName },
    captureTs,
    tls,
    ssh: null,
  }, opts);
}

function buildSshSession(flow, opts) {
  const a = flow.ssh.a;
  const b = flow.ssh.b;
  if (!a.banner && !b.banner && !a.kex && !b.kex) return null;

  const initiator = flow.initiator;
  const responder = initiator === 'a' ? 'b' : 'a';
  const client = flow.ssh[initiator];
  const server = flow.ssh[responder];
  const clientKex = client.kex?.kexAlgorithms || [];
  const serverKex = server.kex?.kexAlgorithms || [];
  const agreed = firstCommon(clientKex, serverKex) || firstCommon(serverKex, clientKex);
  const hybridAlgorithm = agreed && HYBRID_KEX.includes(agreed)
    ? agreed
    : (agreed ? null : [...clientKex, ...serverKex].find((name) => HYBRID_KEX.includes(name)) || null);
  const hybrid = Boolean(hybridAlgorithm);
  const clientEp = endpointFor(flow, initiator);
  const serverEp = endpointFor(flow, responder);
  const serverBanner = server.banner || client.banner || null;
  const clientBanner = client.banner || null;
  const captureTs = flow.firstTs;

  const ssh = {
    clientBanner: clientBanner?.raw || null,
    serverBanner: serverBanner?.raw || null,
    banner: serverBanner?.raw || null,
    software: serverBanner?.software || null,
    comments: serverBanner?.comments || null,
    clientKex,
    serverKex,
    agreedKex: agreed,
    hybrid,
    hybridAlgorithm,
    hostKeyAlgorithms: server.kex?.serverHostKeyAlgorithms || [],
    encryption: server.kex ? [...new Set([...server.kex.encryptionC2S, ...server.kex.encryptionS2C])] : [],
    macs: server.kex ? [...new Set([...server.kex.macC2S, ...server.kex.macS2C])] : [],
    clientKexTs: client.kexTs,
    serverKexTs: server.kexTs,
  };

  return finaliseSession({
    protocol: 'ssh',
    flow,
    client: clientEp,
    server: { ...serverEp, name: serverEp?.ip || 'unknown' },
    captureTs,
    tls: null,
    ssh,
  }, opts);
}

function endpointFor(flow, side) {
  const ep = side === 'a' ? flow.a : flow.b;
  return { ip: ep.ip, port: ep.port };
}

/** Map a selected TLS group onto a registry algorithm id. */
function tlsAlgorithmFor(group, groupName) {
  if (group === 0x001d) return 'x25519';
  if (group === 0x001e) return 'x448';
  if (group === 0x0017 || group === 0x0018 || group === 0x0019) return 'ecdh';
  if (group === 0x0100 || group === 0x0101) return 'dh';
  if (groupName && lookup(groupName).id !== 'unknown') return lookup(groupName).id;
  return 'ecdh';
}

function firstCommon(preferred, other) {
  const set = new Set(other);
  return preferred.find((name) => set.has(name)) || null;
}

function finaliseSession(base, opts = {}) {
  const config = opts.config || {};
  const crqcYear = resolveCrqcYear(config);
  const shelfLife = Number(config.defaultShelfLife) || 7;
  const captureTs = Number.isFinite(base.captureTs) ? base.captureTs : null;
  const captureDate = captureTs != null ? new Date(captureTs * 1000) : null;
  const captureYear = captureDate ? captureDate.getUTCFullYear() : new Date().getUTCFullYear();
  const yearsToCRQC = Math.max(0, crqcYear - captureYear);
  const hybrid = base.protocol === 'tls' ? Boolean(base.tls?.hybrid) : Boolean(base.ssh?.hybrid);
  const exposed = !hybrid && shelfLife > yearsToCRQC;
  const captureTime = captureDate ? captureDate.toISOString() : null;
  const id = `${base.protocol}-${base.server?.ip || 'unknown'}-${base.server?.port || 0}-${captureTs ?? 'na'}`;

  return {
    id,
    protocol: base.protocol,
    client: base.client,
    server: base.server,
    captureTs,
    captureTime,
    captureYear,
    firstTs: base.flow.firstTs,
    lastTs: base.flow.lastTs,
    bytes: base.flow.bytes || 0,
    tls: base.tls,
    ssh: base.ssh,
    hybrid,
    hndl: {
      applicable: true,
      exposed,
      shelfLife,
      crqcYear,
      captureYear,
      yearsToCRQC,
      inequality: `${captureYear} + ${shelfLife} ${exposed ? '>' : '≤'} ${crqcYear}`,
    },
  };
}

/**
 * Turn decoded packets into TCP flows and then into captured sessions.
 * @param {object[]} packets
 * @param {{file?:string, config?:object}} [opts]
 */
export function extractSessions(packets, opts = {}) {
  const flows = new Map();
  for (const packet of packets) {
    const key = flowKey(packet);
    let flow = flows.get(key);
    if (!flow) {
      flow = newFlow(packet);
      // A SYN or SYN-ACK is the only unambiguous statement of who initiated
      // the connection. Captures without a handshake fall back to the first
      // observed payload, which is correct for most TLS and SSH sessions.
      if (typeof packet.flags === 'number') {
        const syn = (packet.flags & 0x02) !== 0;
        const ack = (packet.flags & 0x10) !== 0;
        if (syn && ack) flow.initiator = 'b';
        else if (syn) flow.initiator = 'a';
      }
      flows.set(key, flow);
    }
    flow.lastTs = packet.ts;
    if (!packet.payload || packet.payload.length === 0) continue;
    flow.bytes = (flow.bytes || 0) + packet.payload.length;
    const side = direction(flow, packet);
    drainTls(flow.tls[side], packet.payload, packet.ts);
    drainSsh(flow.ssh[side], packet.payload, packet.ts);
  }

  const sessions = [];
  for (const flow of flows.values()) {
    const tlsSession = buildTlsSession(flow, flow.tls, opts);
    if (tlsSession) sessions.push(tlsSession);
    const sshSession = buildSshSession(flow, opts);
    if (sshSession) sessions.push(sshSession);
  }
  sessions.sort((a, b) => (a.captureTs ?? 0) - (b.captureTs ?? 0) || a.id.localeCompare(b.id));
  return sessions;
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/**
 * Turn captured sessions into findings in the same unified schema as a live
 * endpoint. `captureYear` is carried onto the finding so the risk engine
 * anchors the Mosca inequality to the recording date.
 * @param {object[]} sessions
 * @param {{file?:string, config?:object}} [opts]
 */
export function deriveCaptureFindings(sessions, opts = {}) {
  const findings = [];
  const file = opts.file || null;
  for (const session of sessions) {
    const where = {
      file,
      host: session.server?.name || session.server?.ip || 'unknown',
      port: session.server?.port ?? null,
      captureTime: session.captureTime,
      line: 1,
    };
    const common = {
      kind: 'captured-session',
      location: where,
      confidence: 'high',
      captureYear: session.captureYear,
      captureTime: session.captureTime,
      capturedProtocol: session.protocol,
      evidence: {
        captureTime: session.captureTime,
        client: session.client,
        server: session.server,
      },
    };
    const inequality = session.hndl.inequality;

    if (session.protocol === 'tls') {
      const tls = session.tls;
      if (tls.hybrid) {
        findings.push({
          ...common,
          id: 'captured-session-tls-hybrid',
          title: `Captured TLS session used hybrid key exchange (${tls.groupLabel || tls.groupName || 'ML-KEM'})`,
          algorithm: 'x25519mlkem768',
          primitive: 'key-agreement',
          positive: true,
          note: `Recorded ${session.captureTime}. The captured handshake used a post-quantum hybrid KEM, so the recording is not exposed to a future quantum computer.`,
          evidence: { ...common.evidence, group: tls.group, cipher: tls.cipherName },
        });
      } else {
        const algorithm = tls.algorithm || tlsAlgorithmFor(tls.group, tls.groupName);
        const label = tls.groupLabel || tls.groupName || 'an unknown group';
        findings.push({
          ...common,
          id: 'captured-session-tls-classical',
          title: `Captured TLS session used classical key exchange (${label})`,
          algorithm,
          primitive: 'key-agreement',
          note: `Recorded ${session.captureTime}. The capture contains a classical handshake to ${where.host}:${where.port}. It becomes readable once a CRQC exists; the recording is already a disclosure in progress (${inequality}).`,
          evidence: { ...common.evidence, group: tls.group, cipher: tls.cipherName, offered: tls.clientOfferedGroups },
        });
      }
      if (tls.protocol === 'TLS 1.0' || tls.protocol === 'TLS 1.1') {
        findings.push({
          ...common,
          id: 'captured-session-legacy-tls',
          title: `Captured session negotiated ${tls.protocol}`,
          algorithm: tls.protocol === 'TLS 1.1' ? 'tls-1.1' : 'tls-1.0',
          primitive: 'protocol',
          note: `Recorded ${session.captureTime}. ${tls.protocol} is deprecated by RFC 8996 and also carries the classical key-exchange exposure.`,
        });
      }
    }

    if (session.protocol === 'ssh') {
      const ssh = session.ssh;
      const kex = ssh.agreedKex || ssh.clientKex[0] || ssh.serverKex[0] || null;
      if (ssh.hybrid) {
        findings.push({
          ...common,
          id: 'captured-session-ssh-hybrid',
          title: `Captured SSH session agreed hybrid key exchange (${ssh.hybridAlgorithm})`,
          algorithm: 'mlkem768x25519-sha256',
          primitive: 'key-agreement',
          positive: true,
          note: `Recorded ${session.captureTime}. The recorded KEXINIT exchange shows a hybrid KEM, so the session is protected against harvest-now-decrypt-later.`,
          evidence: { ...common.evidence, clientKex: ssh.clientKex, serverKex: ssh.serverKex, agreed: ssh.agreedKex },
        });
      } else if (kex) {
        findings.push({
          ...common,
          id: 'captured-session-ssh-classical',
          title: `Captured SSH session agreed classical key exchange (${kex})`,
          algorithm: classifySshKex(kex),
          primitive: 'key-agreement',
          note: `Recorded ${session.captureTime}. The recorded SSH handshake is classical-only; the capture is exposed to harvest-now-decrypt-later (${inequality}).`,
          evidence: { ...common.evidence, clientKex: ssh.clientKex, serverKex: ssh.serverKex, agreed: ssh.agreedKex },
        });
      }
      const legacyHostKey = (ssh.hostKeyAlgorithms || []).find((name) => LEGACY_HOST_KEYS.has(name));
      if (legacyHostKey) {
        findings.push({
          ...common,
          id: 'captured-session-legacy-hostkey',
          title: `Captured SSH session advertised a legacy host key (${legacyHostKey})`,
          algorithm: legacyHostKey,
          primitive: 'signature',
          note: `Recorded ${session.captureTime}. The server advertised ${legacyHostKey}, which is withdrawn and classically weak.`,
        });
      }
      const weakKex = (ssh.serverKex || []).filter((name) => WEAK_KEX.has(name));
      if (weakKex.length) {
        findings.push({
          ...common,
          id: 'captured-session-weak-kex',
          title: `Captured SSH session offered weak key exchange (${weakKex.join(', ')})`,
          algorithm: 'dh',
          primitive: 'key-agreement',
          classical: 'weak',
          note: `Recorded ${session.captureTime}. SHA-1 group key exchange is deprecated.`,
        });
      }
      const weakCipher = (ssh.encryption || []).find((name) => WEAK_CIPHERS.has(name));
      if (weakCipher) {
        findings.push({
          ...common,
          id: 'captured-session-weak-cipher',
          title: `Captured SSH session offered weak cipher (${weakCipher})`,
          algorithm: lookup(weakCipher).id === 'unknown' ? 'aes-128-cbc' : lookup(weakCipher).id,
          primitive: 'symmetric',
          classical: 'weak',
          note: `Recorded ${session.captureTime}. CBC-mode and 64-bit-block ciphers are obsolete.`,
        });
      }
      const weakMac = (ssh.macs || []).find((name) => WEAK_MACS.has(name));
      if (weakMac) {
        findings.push({
          ...common,
          id: 'captured-session-weak-mac',
          title: `Captured SSH session offered weak MAC (${weakMac})`,
          algorithm: lookup(weakMac).id === 'unknown' ? 'hmac-sha1' : lookup(weakMac).id,
          primitive: 'mac',
          classical: 'weak',
          note: `Recorded ${session.captureTime}. MD5 and SHA-1 MACs are withdrawn.`,
        });
      }
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Public analysis API
// ---------------------------------------------------------------------------

/**
 * Summarise captured sessions, including the HNDL Captured Ratio.
 * @param {object[]} sessions
 */
export function summariseSessions(sessions) {
  const tlsSessions = sessions.filter((s) => s.protocol === 'tls');
  const sshSessions = sessions.filter((s) => s.protocol === 'ssh');
  const hybridSessions = sessions.filter((s) => s.hybrid);
  const classicalSessions = sessions.filter((s) => !s.hybrid);
  const servers = [];
  const seen = new Set();
  for (const session of sessions) {
    const key = `${session.server?.name || session.server?.ip}:${session.server?.port}`;
    if (seen.has(key)) continue;
    seen.add(key);
    servers.push({
      name: session.server?.name || session.server?.ip || 'unknown',
      ip: session.server?.ip || null,
      port: session.server?.port ?? null,
      protocol: session.protocol,
      hybrid: session.hybrid,
      captureTime: session.captureTime,
    });
  }
  return {
    sessionCount: sessions.length,
    tlsSessions: tlsSessions.length,
    sshSessions: sshSessions.length,
    hybridSessions: hybridSessions.length,
    classicalSessions: classicalSessions.length,
    hndlCapturedRatio: sessions.length === 0 ? 0 : Math.round((classicalSessions.length / sessions.length) * 1000) / 10,
    servers,
    firstCapture: sessions[0]?.captureTime || null,
    lastCapture: sessions[sessions.length - 1]?.captureTime || null,
  };
}

/**
 * Analyse a capture buffer.
 * @param {Buffer} buffer
 * @param {{file?:string, config?:object}} [opts]
 */
export function analysePcapBuffer(buffer, opts = {}) {
  const parsed = parsePcapBuffer(buffer, { file: opts.file });
  const sessions = extractSessions(parsed.packets, opts);
  const findings = deriveCaptureFindings(sessions, opts);
  const summary = summariseSessions(sessions);
  return {
    file: opts.file || null,
    format: parsed.format,
    endian: parsed.endian,
    resolution: parsed.resolution,
    linkType: parsed.linkType,
    linkTypeName: parsed.linkTypeName,
    packetCount: parsed.packetCount,
    sessions,
    findings,
    summary,
  };
}

/**
 * Read and analyse a capture file. The file is opened read-only; no network
 * traffic is generated.
 * @param {string} file
 * @param {{config?:object}} [opts]
 */
export function analysePcapFile(file, opts = {}) {
  const absolute = path.resolve(file);
  const buffer = fs.readFileSync(absolute);
  return analysePcapBuffer(buffer, { ...opts, file: absolute });
}

/**
 * Aggregate several capture files for the scan pipeline.
 * @param {object[]} results
 */
export function summariseCaptures(results = []) {
  const sessions = results.flatMap((result) => result.sessions || []);
  const summary = summariseSessions(sessions);
  return {
    ...summary,
    files: results.map((result) => ({
      file: result.file,
      format: result.format,
      linkType: result.linkTypeName,
      packetCount: result.packetCount,
      sessionCount: result.sessions.length,
    })),
    packetCount: results.reduce((sum, result) => sum + (result.packetCount || 0), 0),
  };
}

export { GROUPS, CIPHER_SUITES, versionName };
