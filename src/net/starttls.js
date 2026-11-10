/**
 * MOSCA — STARTTLS / protocol-upgrade prober
 * ==========================================
 *
 * SMTP, IMAP, POP3, PostgreSQL and LDAP all begin in cleartext and upgrade
 * to TLS after a short, protocol-specific preamble. A scanner that only
 * speaks TLS sees none of them, which is why mail and directory servers are
 * routinely absent from PQC inventories.
 *
 * This module performs the smallest preamble each protocol requires, then
 * sends the same hand-built ClientHello used for HTTPS (see ./clienthello.js)
 * and reads the ServerHello. It never authenticates, never sends mail, never
 * runs a query, and closes the socket as soon as the fingerprint is read.
 *
 * PostgreSQL and LDAP never carry a cleartext banner, so their preambles are
 * binary. Both are encoded by hand below.
 */

import net from 'node:net';
import {
  buildClientHello,
  parseServerFlight,
  versionName,
  CIPHER_SUITES,
  GROUPS,
} from './clienthello.js';
import { analyseChain, deriveChainFindings } from './x509-chain.js';

/** Supported upgrade protocols and their default ports. */
export const STARTTLS_PROTOCOLS = {
  smtp: { defaultPort: 587, label: 'SMTP', command: 'EHLO mosca.local', expect: 250 },
  imap: { defaultPort: 143, label: 'IMAP', command: 'a001 STARTTLS', expect: 'a001 OK' },
  pop3: { defaultPort: 110, label: 'POP3', command: 'STLS', expect: '+OK' },
  postgres: { defaultPort: 5432, label: 'PostgreSQL' },
  ldap: { defaultPort: 389, label: 'LDAP' },
};

/** PostgreSQL SSLRequest: Int32 length 8, Int32 code 80877103. */
const POSTGRES_SSL_REQUEST = Buffer.from('0000000804d2162f', 'hex');

/**
 * LDAP StartTLS ExtendedRequest, message id 1.
 *
 *   SEQUENCE { INTEGER 1,
 *              [APPLICATION 23] { [0] LDAPOID "1.3.6.1.4.1.1466.20037" } }
 */
const LDAP_STARTTLS = Buffer.from('3011020101770c800a2b060104018b3a811c45', 'hex');

/**
 * Parse `smtp://host:587`, `imap://host`, or `host:port` with an explicit
 * `protocol` option.
 * @param {string} target
 * @param {string} [fallbackProtocol]
 */
export function parseStarttlsTarget(target, fallbackProtocol = 'smtp') {
  let raw = String(target).trim();
  let protocol = fallbackProtocol;
  const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(raw);
  if (scheme) {
    protocol = scheme[1].toLowerCase();
    raw = raw.slice(scheme[0].length);
  }
  raw = raw.split('/')[0].split('?')[0];

  let host = raw;
  let port = STARTTLS_PROTOCOLS[protocol]?.defaultPort || 443;
  const bracket = /^\[([^\]]+)\](?::(\d+))?$/.exec(raw);
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
  if (!STARTTLS_PROTOCOLS[protocol]) {
    throw new Error(`unsupported STARTTLS protocol: ${protocol}`);
  }
  return { protocol, host, port, servername: /^\d{1,3}(\.\d{1,3}){3}$/.test(host) ? undefined : host };
}

/** Reject a promise after `ms`. */
function withTimeout(promise, ms, message) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(message)), ms);
      timer.unref?.();
    }),
  ]).finally(() => clearTimeout(timer));
}

/**
 * A tiny buffered reader over a socket, with protocol-specific matchers.
 * The reader owns a single buffer so no byte is lost between preambles.
 * @param {net.Socket} socket
 */
function createReader(socket) {
  let buffer = Buffer.alloc(0);
  let ended = false;
  let failure = null;
  const waiters = new Set();

  const notify = () => {
    for (const waiter of [...waiters]) {
      const result = waiter.check(buffer);
      if (result) {
        waiters.delete(waiter);
        buffer = buffer.subarray(result.consumed);
        waiter.resolve(result.value);
      }
    }
  };

  socket.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    notify();
  });
  const fail = (err) => {
    ended = true;
    failure = err;
    for (const waiter of waiters) waiter.reject(err);
    waiters.clear();
  };
  socket.on('error', fail);
  socket.on('close', () => {
    if (!ended) fail(new Error('connection closed before the upgrade completed'));
  });

  return {
    get buffer() {
      return buffer;
    },
    /** Wait until `check(buffer)` returns `{consumed, value}`. */
    readUntil(check, label = 'data') {
      if (ended) return Promise.reject(failure || new Error('socket closed'));
      const immediate = check(buffer);
      if (immediate) {
        buffer = buffer.subarray(immediate.consumed);
        return Promise.resolve(immediate.value);
      }
      return new Promise((resolve, reject) => {
        waiters.add({ check, resolve, reject, label });
      });
    },
    /** Read a line-oriented protocol reply, returning all lines it consumed. */
    readReply(code) {
      return this.readUntil((buf) => {
        const text = buf.toString('latin1');
        const lines = text.split('\r\n');
        // The last element is either '' (complete) or a partial line.
        for (let i = 0; i < lines.length - 1; i++) {
          const line = lines[i];
          const prefix = String(code);
          if (line.startsWith(`${prefix} `) || line.startsWith(`${prefix}-`) || line.startsWith(prefix)) {
            // Multiline replies continue with `code-`; a `code ` line ends them.
            if (line.startsWith(`${prefix}-`)) continue;
            const consumed = lines.slice(0, i + 1).join('\r\n').length + 2;
            return { consumed, value: lines.slice(0, i + 1).join('\n') };
          }
        }
        return null;
      }, `reply ${code}`);
    },
  };
}

/**
 * Probe one STARTTLS service.
 *
 * @param {string} target `smtp://host:587` or `host:587`
 * @param {{protocol?:string, timeout?:number, yearsToCRQC?:number}} opts
 */
export async function inspectStarttls(target, opts = {}) {
  const { timeout = 10000, yearsToCRQC = 7 } = opts;
  const { protocol, host, port, servername } = parseStarttlsTarget(target, opts.protocol);
  const spec = STARTTLS_PROTOCOLS[protocol];

  const result = {
    target: String(target),
    protocol,
    protocolLabel: spec.label,
    host,
    port,
    servername: servername || null,
    reachable: false,
    upgraded: false,
    banner: null,
    error: null,
    version: null,
    versionName: null,
    cipherSuite: null,
    cipherName: null,
    group: null,
    groupLabel: null,
    hybrid: false,
    certDer: null,
    chainAnalysis: null,
    findings: [],
  };

  const socket = net.connect({ host, port });
  socket.setNoDelay(true);
  const reader = createReader(socket);

  try {
    await withTimeout(
      new Promise((resolve, reject) => {
        socket.once('connect', resolve);
        socket.once('error', reject);
      }),
      timeout,
      `STARTTLS connect timed out after ${timeout}ms`,
    );
    result.reachable = true;

    // ------------------------------------------------------------ preamble
    if (protocol === 'postgres') {
      socket.write(POSTGRES_SSL_REQUEST);
      const answer = await withTimeout(
        reader.readUntil((buf) => (buf.length >= 1 ? { consumed: 1, value: buf.subarray(0, 1).toString('latin1') } : null), 'SSLRequest answer'),
        timeout,
        'PostgreSQL did not answer SSLRequest',
      );
      result.banner = answer;
      result.upgraded = answer === 'S';
      if (!result.upgraded) throw new Error(`PostgreSQL refused TLS (answer: ${answer})`);
    } else if (protocol === 'ldap') {
      socket.write(LDAP_STARTTLS);
      const reply = await withTimeout(
        reader.readUntil((buf) => {
          if (buf.length < 2 || buf[0] !== 0x30) return null;
          let len = buf[1];
          let header = 2;
          if (len & 0x80) {
            const n = len & 0x7f;
            if (buf.length < 2 + n) return null;
            len = 0;
            for (let i = 0; i < n; i++) len = len * 256 + buf[2 + i];
            header = 2 + n;
          }
          if (buf.length < header + len) return null;
          return { consumed: header + len, value: buf.subarray(0, header + len) };
        }, 'LDAP StartTLS response'),
        timeout,
        'LDAP did not answer StartTLS',
      );
      // ExtendedResponse [APPLICATION 24] carries an ENUMERATED resultCode;
      // 0 = success. Anything else means the server declined.
      const success = reply.includes(0x78) && reply.includes(Buffer.from([0x0a, 0x01, 0x00]));
      result.banner = `LDAP ExtendedResponse (${reply.length} bytes)`;
      result.upgraded = success;
      if (!success) throw new Error('LDAP refused StartTLS');
    } else {
      // SMTP / IMAP / POP3 all start with a server greeting.
      const greetingCode = protocol === 'smtp' ? 220 : protocol === 'imap' ? '* OK' : '+OK';
      result.banner = await withTimeout(reader.readReply(greetingCode), timeout, `${spec.label} greeting timed out`);

      const command =
        protocol === 'smtp'
          ? `${spec.command}\r\nSTARTTLS\r\n`
          : protocol === 'imap'
            ? 'a001 STARTTLS\r\n'
            : 'STLS\r\n';
      socket.write(command);

      if (protocol === 'smtp') {
        await withTimeout(reader.readReply(250), timeout, 'SMTP EHLO was rejected');
        const upgrade = await withTimeout(reader.readReply(220), timeout, 'SMTP STARTTLS was rejected');
        result.upgraded = true;
        result.banner = `${result.banner}\n${upgrade}`;
      } else if (protocol === 'imap') {
        const upgrade = await withTimeout(reader.readReply('a001 OK'), timeout, 'IMAP STARTTLS was rejected');
        result.upgraded = true;
        result.banner = `${result.banner}\n${upgrade}`;
      } else {
        const upgrade = await withTimeout(reader.readReply('+OK'), timeout, 'POP3 STLS was rejected');
        result.upgraded = true;
        result.banner = `${result.banner}\n${upgrade}`;
      }
    }

    // --------------------------------------------------------- ClientHello
    socket.write(buildClientHello({ host: servername || host }));

    const flight = await withTimeout(
      reader.readUntil((buf) => {
        if (buf.length < 5) return null;
        const parsed = parseServerFlight(buf);
        if (!parsed.serverHello) return null;
        // A TLS 1.3 ServerHello is enough; for TLS 1.2 wait for the
        // Certificate message when the record is already complete.
        if (parsed.serverHello.version === 0x0304 || parsed.serverHello.hrr) {
          return { consumed: buf.length, value: parsed };
        }
        const firstRecord = 5 + buf.readUInt16BE(3);
        if (buf.length >= firstRecord && parsed.certDer) {
          return { consumed: buf.length, value: parsed };
        }
        return null;
      }, 'ServerHello'),
      timeout,
      `${spec.label} TLS probe timed out after ${timeout}ms`,
    );

    const sh = flight.serverHello;
    const version = sh.version || sh.legacyVersion || null;
    result.version = version;
    result.versionName = versionName(version);
    result.cipherSuite = sh.cipherSuite ?? null;
    result.cipherName = CIPHER_SUITES[sh.cipherSuite]?.name || null;
    result.group = sh.group ?? flight.skeCurve ?? null;
    result.groupLabel = GROUPS[result.group]?.label || null;
    result.hybrid = Boolean(GROUPS[result.group] && (GROUPS[result.group].type === 'hybrid' || GROUPS[result.group].type === 'KEM'));
    result.certDer = flight.certDer || null;

    if (result.certDer) {
      result.chainAnalysis = analyseChain([result.certDer], { yearsToCRQC });
    }
  } catch (err) {
    result.error = err.message;
  } finally {
    socket.destroy();
  }

  result.findings = deriveStarttlsFindings(result, { yearsToCRQC });
  return result;
}

/**
 * Convert a STARTTLS result into unified findings.
 * @param {object} ep
 * @param {{yearsToCRQC?:number}} [opts]
 */
export function deriveStarttlsFindings(ep, { yearsToCRQC = 7 } = {}) {
  const findings = [];
  if (!ep.reachable || !ep.upgraded) return findings;
  const where = { host: ep.host, port: ep.port, target: ep.target, protocol: ep.protocol };

  if (ep.hybrid) {
    findings.push({
      id: 'starttls-hybrid-kex',
      kind: 'endpoint',
      title: `${ep.protocolLabel} STARTTLS negotiates ${ep.groupLabel}`,
      algorithm: 'x25519mlkem768',
      primitive: 'key-agreement',
      location: where,
      confidence: 'high',
      positive: true,
      note: 'The upgraded channel negotiates a hybrid KEM and is protected against harvest-now-decrypt-later.',
    });
  } else if (ep.group) {
    const name = GROUPS[ep.group]?.name || ep.group;
    findings.push({
      id: 'starttls-classical-kex',
      kind: 'endpoint',
      title: `${ep.protocolLabel} STARTTLS negotiates classical ${ep.groupLabel || ep.group}`,
      algorithm: name === 'x25519' ? 'x25519' : 'ecdh',
      primitive: 'key-agreement',
      location: where,
      confidence: 'high',
      note: 'Mail and directory traffic is long-lived and routinely archived. A recorded upgrade can be decrypted once a CRQC exists.',
      evidence: { group: ep.group },
    });
  }

  if (ep.chainAnalysis) {
    findings.push(...deriveChainFindings(ep.chainAnalysis, where, { yearsToCRQC }));
  }
  return findings;
}
