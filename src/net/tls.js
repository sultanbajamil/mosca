/**
 * MOSCA — endpoint inspection
 * ===========================
 *
 * Combines two independent views of a TLS service:
 *
 *   1. A real handshake through Node's TLS stack, to retrieve the
 *      certificate chain and the parameters this runtime actually negotiates.
 *   2. A raw ClientHello probe (see ./clienthello.js), to discover whether
 *      the *server* supports post-quantum hybrid key exchange — something
 *      the local runtime may not be able to negotiate itself.
 *
 * The gap between those two views is itself a finding: if the server offers
 * X25519MLKEM768 but our OpenSSL does not, every other client that does
 * support it is already protected, and the report says so.
 */

import tls from 'node:tls';
import { probeServerHello, groupPosture, versionName, GROUPS, CIPHER_SUITES } from './clienthello.js';
import { parseCertificate } from './x509.js';
import { lookup, QUANTUM } from '../rules/algorithms.js';

/**
 * Parse a target like `example.com`, `example.com:8443`, `https://example.com:8443/path`.
 * @param {string} target
 */
export function parseTarget(target) {
  let raw = String(target).trim();
  let port = 443;
  let servername;

  raw = raw.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  raw = raw.split('/')[0];
  raw = raw.split('?')[0];

  const bracket = /^\[([^\]]+)\](?::(\d+))?$/.exec(raw);
  if (bracket) {
    return { host: bracket[1], port: bracket[2] ? Number(bracket[2]) : 443, servername: undefined };
  }
  const parts = raw.split(':');
  if (parts.length === 2 && /^\d+$/.test(parts[1])) {
    port = Number(parts[1]);
    raw = parts[0];
  }
  // A bare IP address cannot be used as SNI.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(raw)) servername = undefined;
  else servername = raw;

  return { host: raw, port, servername };
}

/**
 * Perform a real TLS handshake to retrieve the peer certificate chain.
 */
function nodeHandshake({ host, port, servername, timeout }) {
  return new Promise((resolve, reject) => {
    let socket;
    try {
      socket = tls.connect({
        host,
        port,
        servername,
        rejectUnauthorized: false,
        ALPNProtocols: ['h2', 'http/1.1'],
        // This client deliberately offers TLS 1.0/1.1 so the probe can detect
        // servers that still accept them. It is the detector, not the policy.
        minVersion: 'TLSv1', // mosca-ignore-line -- legacy detection probe
        maxVersion: 'TLSv1.3',
      });
    } catch (err) {
      reject(err);
      return;
    }

    const done = (fn, value) => {
      socket.destroy();
      fn(value);
    };

    socket.setTimeout(timeout, () => done(reject, new Error(`handshake timed out after ${timeout}ms`)));

    socket.once('secureConnect', () => {
      try {
        const leaf = socket.getPeerCertificate(true);
        const chain = [];
        const seen = new Set();
        let current = leaf;
        while (current && current.raw && !seen.has(current.fingerprint256)) {
          seen.add(current.fingerprint256);
          chain.push(current);
          current = current.issuerCertificate;
        }
        done(resolve, {
          protocol: socket.getProtocol(),
          cipher: socket.getCipher(),
          alpn: socket.alpnProtocol || null,
          ephemeral: socket.getEphemeralKeyInfo(),
          authorized: socket.authorized,
          authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
          leaf,
          chain,
        });
      } catch (err) {
        done(reject, err);
      }
    });

    socket.once('error', (err) => done(reject, err));
  });
}

/**
 * Node reports protocol names as `TLSv1.3` / `TLSv1.2`; normalise them to the
 * spelling used in reports and in the algorithm registry.
 * @param {string|null} protocol
 */
export function normaliseProtocol(protocol) {
  if (!protocol) return protocol;
  return String(protocol).replace(/^TLSv?/i, 'TLS ').replace(/^SSLv?/i, 'SSL ');
}

/**
 * Classify a parsed certificate into a finding-friendly summary.
 */
export function summariseCertificate(parsed) {
  const now = Date.now();
  const notAfter = parsed.notAfter ? parsed.notAfter.getTime() : null;
  const daysRemaining = notAfter == null ? null : Math.floor((notAfter - now) / 86400000);
  const sig = lookup(parsed.sigAlgo);
  const key = lookup(parsed.publicKey?.algorithm || 'unknown');

  return {
    subject: parsed.subject?.CN || Object.values(parsed.subject || {})[0] || '(no CN)',
    issuer: parsed.issuer?.O || parsed.issuer?.CN || 'unknown',
    sanCount: parsed.san.length,
    san: parsed.san.slice(0, 20),
    notBefore: parsed.notBefore,
    notAfter: parsed.notAfter,
    daysRemaining,
    expired: daysRemaining != null && daysRemaining < 0,
    signature: {
      name: parsed.sigAlgName,
      oid: parsed.sigAlgOid,
      algorithm: sig.id,
      label: sig.label,
      quantum: sig.quantum,
      classical: sig.classical,
      replacement: sig.replacement,
      standard: sig.standard,
    },
    publicKey: {
      algorithm: key.id,
      label: key.label,
      bits: parsed.publicKey?.bits ?? null,
      curve: parsed.publicKey?.curve ?? null,
      quantum: key.quantum,
      classical: key.classical,
      replacement: key.replacement,
      standard: key.standard,
    },
    isCA: parsed.isCA,
    derLength: parsed.derLength,
  };
}

/**
 * Inspect one TLS endpoint.
 * @param {string} target
 * @param {{timeout?:number, legacy?:boolean, dataClass?:string, shelfLife?:number}} opts
 */
export async function inspectEndpoint(target, opts = {}) {
  const { timeout = 10000, legacy = true } = opts;
  const { host, port, servername } = parseTarget(target);
  const base = {
    target: String(target),
    host,
    port,
    servername: servername || null,
    reachable: false,
    error: null,
    protocol: null,
    cipher: null,
    alpn: null,
    group: null,
    groupLabel: null,
    hybrid: false,
    certificate: null,
    chain: [],
    legacyTls: [],
    serverPrefersHybrid: false,
    findings: [],
  };

  const [handshake, probe] = await Promise.allSettled([
    nodeHandshake({ host, port, servername, timeout }),
    probeServerHello({ host, port, servername, timeout }),
  ]);

  if (handshake.status === 'fulfilled') {
    const h = handshake.value;
    base.reachable = true;
    // Node reports "TLSv1.3"; the rest of the tool speaks "TLS 1.3".
    base.protocol = normaliseProtocol(h.protocol);
    base.cipher = h.cipher?.name || null;
    base.alpn = h.alpn;
    base.authorized = h.authorized;
    base.authorizationError = h.authorizationError;
    base.localEphemeral = h.ephemeral ? `${h.ephemeral.name || h.ephemeral.type}` : null;

    if (h.leaf?.raw) {
      try {
        const parsed = parseCertificate(h.leaf.raw);
        base.certificate = summariseCertificate(parsed);
        base.chain = h.chain.map((c) => ({
          subject: c.subject?.CN || null,
          issuer: c.issuer?.CN || null,
          validTo: c.valid_to || null,
        }));
      } catch (err) {
        base.certificateError = `could not parse certificate: ${err.message}`;
      }
    }
  } else {
    base.error = handshake.reason?.message || String(handshake.reason);
  }

  if (probe.status === 'fulfilled') {
    const p = probe.value;
    base.reachable = base.reachable || Boolean(p.cipherSuite);
    if (!base.protocol && p.versionName) base.protocol = p.versionName;
    if (!base.cipher && p.cipherName) base.cipher = p.cipherName;
    if (p.group != null) {
      const posture = groupPosture(p.group);
      base.group = posture.name || null;
      base.groupLabel = posture.label;
      base.hybrid = posture.hybrid;
      base.groupType = posture.type;
      base.serverPrefersHybrid = posture.hybrid;
    }
    base.probeVersion = p.versionName;
    base.probeCipher = p.cipherName;
    base.helloRetry = p.hrr;
    base.probeAlert = p.alert;
  } else if (!base.reachable) {
    base.error = base.error || probe.reason?.message || String(probe.reason);
  }

  if (legacy && base.reachable) {
    // Ask specifically for TLS 1.0/1.1 to see whether the server still accepts it.
    const legacyVersions = [0x0301, 0x0302];
    const legacyProbe = await Promise.allSettled([
      probeServerHello({ host, port, servername, timeout, versions: legacyVersions }),
    ]);
    const r = legacyProbe[0];
    if (r.status === 'fulfilled' && r.value.version && r.value.version <= 0x0302) {
      base.legacyTls.push(versionName(r.value.version));
    }
  }

  base.findings = deriveEndpointFindings(base);
  return base;
}

/**
 * Turn one endpoint record into zero or more findings.
 */
export function deriveEndpointFindings(ep) {
  const findings = [];
  const where = { host: ep.host, port: ep.port, target: ep.target };

  if (!ep.reachable) {
    return findings;
  }

  // ------------------------------------------------------------- key exchange
  if (ep.hybrid) {
    findings.push({
      id: 'endpoint-hybrid-kex',
      kind: 'endpoint',
      title: `Post-quantum hybrid key exchange enabled (${ep.groupLabel})`,
      algorithm: 'x25519mlkem768',
      primitive: 'key-agreement',
      location: where,
      confidence: 'high',
      note: 'The server negotiated a hybrid KEM. Sessions are protected against harvest-now-decrypt-later.',
      positive: true,
    });
  } else if (ep.group) {
    const g = Object.values(GROUPS).find((x) => x.name === ep.group);
    findings.push({
      id: 'endpoint-classical-kex',
      kind: 'endpoint',
      title: `Classical-only key exchange (${ep.groupLabel || ep.group})`,
      algorithm: ep.group === 'x25519' ? 'x25519' : 'ecdh',
      primitive: 'key-agreement',
      location: where,
      confidence: 'high',
      note: `Server selected ${ep.groupLabel || ep.group}. A recorded session can be decrypted once a CRQC exists. Enable X25519MLKEM768 (group 0x11EC).`,
      evidence: { group: ep.group, bits: g?.bits ?? null },
    });
  }

  // -------------------------------------------------------------- certificate
  if (ep.certificate) {
    const cert = ep.certificate;
    const sig = cert.signature;
    if (sig.quantum === QUANTUM.BROKEN || sig.quantum === QUANTUM.WEAKENED) {
      findings.push({
        id: 'endpoint-cert-signature',
        kind: 'endpoint',
        title: `Certificate signed with ${sig.name}`,
        algorithm: sig.algorithm,
        primitive: 'signature',
        location: where,
        confidence: 'high',
        note: `The certificate signature is quantum-vulnerable. Migrate to ML-DSA-65 (FIPS 204) or a hybrid certificate.`,
        evidence: { oid: sig.oid, bits: cert.publicKey.bits },
      });
    }
    const key = cert.publicKey;
    if (key.quantum === QUANTUM.BROKEN) {
      findings.push({
        id: 'endpoint-cert-key',
        kind: 'endpoint',
        title: `Certificate public key is ${key.label}${key.bits ? ` (${key.bits} bits)` : ''}`,
        algorithm: key.algorithm,
        // A certificate's public key authenticates the handshake; it signs,
        // it does not encrypt. Recommending a KEM here would be wrong.
        primitive: 'signature',
        location: where,
        confidence: 'high',
        note: `Public-key cryptography on this certificate falls to Shor's algorithm.`,
        evidence: { bits: key.bits, curve: key.curve },
      });
    }
    if (cert.expired) {
      findings.push({
        id: 'endpoint-cert-expired',
        kind: 'endpoint',
        title: `Certificate expired ${Math.abs(cert.daysRemaining)} days ago`,
        algorithm: 'unknown',
        primitive: 'certificate',
        location: where,
        confidence: 'high',
        classicalOnly: true,
      });
    } else if (cert.daysRemaining != null && cert.daysRemaining < 30) {
      findings.push({
        id: 'endpoint-cert-expiring',
        kind: 'endpoint',
        title: `Certificate expires in ${cert.daysRemaining} days`,
        algorithm: 'unknown',
        primitive: 'certificate',
        location: where,
        confidence: 'high',
        classicalOnly: true,
      });
    }
  }

  // ---------------------------------------------------------------- protocol
  if (ep.protocol) {
    const versionAlgo = ep.protocol === 'TLS 1.3' ? 'tls-1.3' : ep.protocol === 'TLS 1.2' ? 'tls-1.2' : ep.protocol === 'TLS 1.1' ? 'tls-1.1' : 'tls-1.0';
    if (ep.protocol !== 'TLS 1.3' && ep.protocol !== 'TLS 1.2') {
      findings.push({
        id: 'endpoint-legacy-protocol',
        kind: 'endpoint',
        title: `Legacy protocol negotiated: ${ep.protocol}`,
        algorithm: versionAlgo,
        primitive: 'protocol',
        location: where,
        confidence: 'high',
      });
    }
  }
  for (const v of ep.legacyTls) {
    findings.push({
      id: 'endpoint-accepts-legacy-tls',
      kind: 'endpoint',
      title: `Server still accepts ${v}`,
      algorithm: v === 'TLS 1.1' ? 'tls-1.1' : 'tls-1.0',
      primitive: 'protocol',
      location: where,
      confidence: 'high',
      note: 'RFC 8996 deprecates TLS 1.0 and 1.1. Disable them at the terminator.',
    });
  }

  // ----------------------------------------------------------------- cipher
  if (ep.cipher) {
    const suite = Object.values(CIPHER_SUITES).find((s) => s.name === ep.cipher);
    const symmetric = suite?.symmetric;
    if (symmetric === 'rc4' || symmetric === '3des') {
      findings.push({
        id: 'endpoint-weak-cipher',
        kind: 'endpoint',
        title: `Weak cipher suite: ${ep.cipher}`,
        algorithm: symmetric,
        primitive: 'symmetric',
        location: where,
        confidence: 'high',
      });
    } else if (symmetric === 'aes-128-gcm' || symmetric === 'aes-128-cbc') {
      findings.push({
        id: 'endpoint-aes128',
        kind: 'endpoint',
        title: `AES-128 session cipher (${ep.cipher})`,
        algorithm: 'aes-128',
        primitive: 'symmetric',
        location: where,
        confidence: 'high',
        note: "Grover's algorithm reduces AES-128 to ~64-bit security. Prefer AES-256-GCM or ChaCha20-Poly1305.",
      });
    }
  }

  // ---------------------------------------------- local runtime capability
  if (ep.hybrid && ep.localEphemeral && !/MLKEM|KYBER/i.test(ep.localEphemeral)) {
    findings.push({
      id: 'endpoint-local-runtime-behind',
      kind: 'endpoint',
      title: 'Server supports PQC but the scanning runtime does not',
      algorithm: 'x25519mlkem768',
      primitive: 'key-agreement',
      location: where,
      confidence: 'high',
      positive: true,
      note: `The server offered ${ep.groupLabel} but this Node/OpenSSL build negotiated ${ep.localEphemeral}. Upgrade the client runtime to benefit.`,
    });
  }

  return findings;
}
