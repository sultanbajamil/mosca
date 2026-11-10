/**
 * MOSCA — X.509 chain analysis
 * ============================
 *
 * A TLS audit that stops at the leaf certificate misses the most common
 * structural failure in real PKI: a modern leaf signed by a legacy
 * intermediate, or a root that must stay trusted, unchanged, for the next
 * twenty years while still using RSA and SHA-1.
 *
 * This module consumes the DER of every certificate in the peer chain and
 * answers four questions:
 *
 *   1. Which certificate is the weakest link, and where is it?
 *   2. Does a long-lived classical root cross the CRQC window?
 *   3. What will the same chain cost, in bytes, once it carries
 *      ML-DSA-65 or SLH-DSA signatures?
 *   4. Will that flight exceed the 14 KB initial congestion window and
 *      fragment every handshake?
 *
 * Everything here is pure computation over already-parsed DER. No network,
 * no dependencies.
 */

import { parseCertificate } from './x509.js';
import {
  lookup,
  rsaVariant,
  QUANTUM_RANK,
  CLASSICAL_RANK,
} from '../rules/algorithms.js';

/** Standard initial congestion window (`initcwnd`) in bytes. */
export const INITIAL_CWND = 14 * 1024;

/**
 * Public-key and signature sizes, in bytes, for the post-quantum schemes a
 * certificate chain is likely to adopt. Values come from FIPS 204 / FIPS 205
 * and the NIST submission packages.
 */
export const PQC_SIZES = {
  'ml-dsa-44': { label: 'ML-DSA-44', publicKey: 1312, signature: 2420, standard: 'FIPS 204' },
  'ml-dsa-65': { label: 'ML-DSA-65', publicKey: 1952, signature: 3309, standard: 'FIPS 204' },
  'ml-dsa-87': { label: 'ML-DSA-87', publicKey: 2592, signature: 4627, standard: 'FIPS 204' },
  'slh-dsa-128s': { label: 'SLH-DSA-SHA2-128s', publicKey: 32, signature: 7856, standard: 'FIPS 205' },
  'slh-dsa-128f': { label: 'SLH-DSA-SHA2-128f', publicKey: 32, signature: 17088, standard: 'FIPS 205' },
  'slh-dsa-192s': { label: 'SLH-DSA-SHA2-192s', publicKey: 48, signature: 16224, standard: 'FIPS 205' },
  'slh-dsa-256s': { label: 'SLH-DSA-SHA2-256s', publicKey: 64, signature: 29792, standard: 'FIPS 205' },
};

/** Hybrid X.509 certificate: classical key plus an ML-DSA key and signature. */
const HYBRID_OVERHEAD = { publicKey: 1952, signature: 3309 };

/**
 * Turn a parsed certificate's public-key record into the most specific
 * registry id available.
 * @param {object|null} pk
 */
export function keyAlgorithmId(pk) {
  if (!pk) return 'unknown';
  if (pk.algorithm === 'rsa') return rsaVariant(pk.bits).id;
  if (pk.algorithm === 'ecdsa') return 'ecdsa';
  return pk.algorithm;
}

/** Chain role from position and self-signed status. */
function roleFor(index, parsed) {
  if (index === 0) return 'leaf';
  if (parsed.isCA && parsed.subject?.CN && parsed.subject.CN === parsed.issuer?.CN) return 'root';
  return 'intermediate';
}

/**
 * Classify one parsed certificate.
 *
 * `classical` is deliberately downgraded when the certificate carries a
 * SHA-1 or MD5 signature: that is a property of the signature, not of the
 * public key, and it is broken today.
 *
 * @param {object} parsed output of parseCertificate
 * @param {number} index
 * @param {Date} now
 */
export function classifyCertificate(parsed, index = 0, now = new Date()) {
  const keyId = keyAlgorithmId(parsed.publicKey);
  const key = lookup(keyId);
  const sigHash = parsed.sigHash || null;
  const legacyHash = sigHash === 'sha1' || sigHash === 'md5' || parsed.sigAlgo === 'md5';

  const quantum = key.quantum;
  const classical = legacyHash ? 'broken' : key.classical;

  const notAfter = parsed.notAfter ? parsed.notAfter.getTime() : null;
  const notBefore = parsed.notBefore ? parsed.notBefore.getTime() : null;
  const daysRemaining = notAfter == null ? null : Math.floor((notAfter - now.getTime()) / 86400000);
  const validityYears =
    notAfter != null && notBefore != null
      ? Math.round(((notAfter - notBefore) / (365.25 * 86400000)) * 10) / 10
      : null;

  const entry = {
    index,
    role: roleFor(index, parsed),
    subject: parsed.subject?.CN || Object.values(parsed.subject || {})[0] || '(no CN)',
    issuer: parsed.issuer?.CN || parsed.issuer?.O || 'unknown',
    isCA: Boolean(parsed.isCA),
    keyAlgorithm: keyId,
    keyLabel: key.label,
    keyBits: parsed.publicKey?.bits ?? null,
    curve: parsed.publicKey?.curve ?? null,
    signatureAlgorithm: parsed.sigAlgName,
    signatureHash: sigHash,
    signatureOid: parsed.sigAlgOid,
    legacySignature: legacyHash,
    quantum,
    classical,
    notBefore: parsed.notBefore || null,
    notAfter: parsed.notAfter || null,
    daysRemaining,
    validityYears,
    expired: daysRemaining != null && daysRemaining < 0,
    derBytes: parsed.derLength,
    publicKeyBytes: parsed.publicKey?.keyBytes ?? null,
    signatureBytes: parsed.signatureBytes ?? null,
  };
  entry.rank = (QUANTUM_RANK[quantum] ?? 2) * 4 + (CLASSICAL_RANK[classical] ?? 1);
  return entry;
}

/**
 * Identify the weakest certificate in the chain.
 *
 * The leaf is the reference point. A chain weakness is reported only when a
 * certificate *above* the leaf is at least as weak, which is the case that
 * surprises teams: "our certificate is ECDSA, why is the report complaining?"
 *
 * @param {object[]} entries
 */
export function weakestLink(entries) {
  if (!entries.length) return null;
  let worst = entries[0];
  for (const entry of entries) {
    if (entry.rank > worst.rank) worst = entry;
  }
  const leaf = entries[0];
  return {
    ...worst,
    leafRank: leaf.rank,
    isChainWeakness: worst.index > 0 && worst.rank >= leaf.rank,
    delta: worst.rank - leaf.rank,
  };
}

/**
 * A root that must remain trusted past the CRQC window, on a classical
 * algorithm, is a structural exposure: it cannot be rotated quickly.
 *
 * @param {object[]} entries
 * @param {{now?:Date, yearsToCRQC?:number, minValidityYears?:number}} opts
 */
export function longLivedClassical(entries, { now = new Date(), yearsToCRQC = 7, minValidityYears = 10 } = {}) {
  const root =
    [...entries].reverse().find((e) => e.role === 'root') ||
    [...entries].reverse().find((e) => e.isCA) ||
    null;
  if (!root) return null;

  const remainingYears =
    root.notAfter != null
      ? Math.round(((root.notAfter.getTime() - now.getTime()) / (365.25 * 86400000)) * 10) / 10
      : null;
  const validity = root.validityYears ?? 0;
  const longLived = validity >= minValidityYears || (remainingYears != null && remainingYears >= minValidityYears);
  const classical = root.quantum === 'broken' || root.quantum === 'weakened';

  return {
    ...root,
    remainingYears,
    longLived,
    classical,
    crossesCrqc: classical && remainingYears != null && remainingYears > yearsToCRQC,
    exposed: longLived && classical && (remainingYears == null || remainingYears > yearsToCRQC),
  };
}

/**
 * Estimate the certificate flight after a chain moves to a post-quantum
 * signature scheme.
 *
 * The estimate keeps every non-key, non-signature byte of each current
 * certificate (names, extensions, validity) and swaps in the new public key
 * and signature sizes. That is accurate enough to answer the only question
 * that matters operationally: does the handshake fit in the first flight?
 *
 * @param {object[]} entries classified certificates
 * @param {{algorithms?:string[], hybrid?:boolean}} opts
 */
export function estimatePqcHandshake(entries, { algorithms = ['ml-dsa-65', 'slh-dsa-128s'], hybrid = false } = {}) {
  const projections = {};

  for (const algorithm of algorithms) {
    const sizes = PQC_SIZES[algorithm];
    if (!sizes) continue;

    const perCertificate = entries.map((entry) => {
      const pk = entry.publicKeyBytes || 0;
      const sig = entry.signatureBytes || 0;
      const overhead = Math.max(0, entry.derBytes - pk - sig);
      const newPk = sizes.publicKey + (hybrid ? HYBRID_OVERHEAD.publicKey : 0);
      const newSig = sizes.signature + (hybrid ? HYBRID_OVERHEAD.signature : 0);
      const projected = overhead + newPk + newSig;
      return {
        index: entry.index,
        role: entry.role,
        subject: entry.subject,
        currentBytes: entry.derBytes,
        projectedBytes: projected,
        deltaBytes: projected - entry.derBytes,
      };
    });

    // TLS 1.3 Certificate: 1 context byte + 3 list bytes + per-cert 3-byte
    // length prefix. CertificateVerify carries one signature.
    const certificateMessageBytes =
      4 + perCertificate.reduce((sum, c) => sum + 3 + c.projectedBytes, 0);
    const certificateVerifyBytes = sizes.signature + (hybrid ? HYBRID_OVERHEAD.signature : 0);
    const totalBytes = certificateMessageBytes + certificateVerifyBytes;

    projections[algorithm] = {
      algorithm,
      label: sizes.label,
      standard: sizes.standard,
      hybrid,
      perCertificate,
      certificateMessageBytes,
      certificateVerifyBytes,
      totalBytes,
      threshold: INITIAL_CWND,
      exceeds: totalBytes > INITIAL_CWND,
      headroomBytes: INITIAL_CWND - totalBytes,
      currentChainBytes: entries.reduce((sum, e) => sum + e.derBytes, 0),
    };
  }

  return {
    threshold: INITIAL_CWND,
    projections,
    worst: Object.values(projections).sort((a, b) => b.totalBytes - a.totalBytes)[0] || null,
    exceeds: Object.values(projections).some((p) => p.exceeds),
  };
}

/**
 * Analyse a full DER chain.
 *
 * @param {Buffer[]|object[]} certificates raw DER buffers or parsed certs
 * @param {{now?:Date, yearsToCRQC?:number}} opts
 */
export function analyseChain(certificates, { now = new Date(), yearsToCRQC = 7 } = {}) {
  const parsed = [];
  const errors = [];
  certificates.forEach((cert, index) => {
    try {
      const item = Buffer.isBuffer(cert) ? parseCertificate(cert) : cert;
      parsed.push(classifyCertificate(item, index, now));
    } catch (err) {
      errors.push({ index, error: err.message });
    }
  });

  if (!parsed.length) {
    return {
      length: 0,
      entries: [],
      errors,
      weakest: null,
      root: null,
      longLivedRoot: null,
      pqc: estimatePqcHandshake([], { algorithms: ['ml-dsa-65', 'slh-dsa-128s'] }),
      quantumSafe: false,
    };
  }

  const weakest = weakestLink(parsed);
  const root = [...parsed].reverse().find((e) => e.role === 'root') || null;
  const longLivedRoot = longLivedClassical(parsed, { now, yearsToCRQC });
  const pqc = estimatePqcHandshake(parsed);

  return {
    length: parsed.length,
    entries: parsed,
    errors,
    roles: parsed.map((e) => e.role),
    weakest,
    root,
    longLivedRoot,
    pqc,
    quantumSafe: parsed.every((e) => e.quantum === 'safe'),
    legacySignatures: parsed.filter((e) => e.legacySignature).map((e) => ({
      index: e.index,
      role: e.role,
      subject: e.subject,
      hash: e.signatureHash,
    })),
    earliestExpiry: parsed.reduce(
      (min, e) => (e.notAfter && (min == null || e.notAfter < min) ? e.notAfter : min),
      null,
    ),
  };
}

/**
 * Convert a chain analysis into unified findings.
 *
 * @param {object} chain output of analyseChain
 * @param {{host:string, port:number, target?:string}} where endpoint location
 * @param {{yearsToCRQC?:number}} [opts]
 */
export function deriveChainFindings(chain, where, { yearsToCRQC = 7 } = {}) {
  const findings = [];
  if (!chain || !chain.entries?.length) return findings;

  // ------------------------------------------------------------- weakest link
  const weak = chain.weakest;
  if (weak && weak.isChainWeakness) {
    findings.push({
      id: 'chain-weakest-link',
      kind: 'chain',
      title: `Weakest link is the ${weak.role} certificate "${weak.subject}"`,
      algorithm: weak.keyAlgorithm,
      primitive: 'signature',
      location: where,
      confidence: 'high',
      quantum: weak.quantum,
      classical: weak.classical,
      note: `The leaf is stronger than the ${weak.role} at depth ${weak.index}. Rotating the leaf will not remove the exposure; the issuing hierarchy must migrate too.`,
      evidence: {
        depth: weak.index,
        role: weak.role,
        subject: weak.subject,
        issuer: weak.issuer,
        keyAlgorithm: weak.keyAlgorithm,
        keyBits: weak.keyBits,
        signature: weak.signatureAlgorithm,
        signatureHash: weak.signatureHash,
        leafRank: weak.leafRank,
        weakestRank: weak.rank,
      },
    });
  }

  // ----------------------------------------------------- legacy signature
  for (const legacy of chain.legacySignatures || []) {
    findings.push({
      id: 'chain-legacy-signature',
      kind: 'chain',
      title: `${legacy.role} certificate "${legacy.subject}" uses ${String(legacy.hash).toUpperCase()}`,
      algorithm: legacy.hash === 'md5' ? 'md5' : 'sha1',
      primitive: 'signature',
      location: where,
      confidence: 'high',
      note: 'A SHA-1 or MD5 signature is broken classically today, independently of quantum computing. Re-issue the certificate from a modern hierarchy.',
      evidence: { depth: legacy.index, role: legacy.role, hash: legacy.hash, subject: legacy.subject },
    });
  }

  // ------------------------------------------------- long-lived classical root
  const root = chain.longLivedRoot;
  if (root && root.exposed) {
    findings.push({
      id: 'chain-long-lived-root',
      kind: 'chain',
      title: `Long-lived classical root "${root.subject}" (${root.remainingYears ?? '?'}y remaining)`,
      algorithm: root.keyAlgorithm,
      primitive: 'certificate',
      location: where,
      confidence: 'high',
      quantum: root.quantum,
      classical: root.classical,
      note: `The root is valid for ${root.validityYears ?? '?'} years and crosses the ${yearsToCRQC}-year CRQC window. Root rotation is the slowest migration in PKI; start the cross-signing programme now.`,
      evidence: {
        depth: root.index,
        subject: root.subject,
        notAfter: root.notAfter?.toISOString?.() || null,
        validityYears: root.validityYears,
        remainingYears: root.remainingYears,
        keyAlgorithm: root.keyAlgorithm,
        keyBits: root.keyBits,
      },
    });
  }

  // -------------------------------------------------- PQC handshake bloat
  const pqc = chain.pqc;
  if (pqc?.worst) {
    const worst = pqc.worst;
    if (worst.exceeds) {
      findings.push({
        id: 'chain-pqc-bloat',
        kind: 'chain',
        title: `PQC chain would exceed the 14 KB initial congestion window (${worst.label}: ${worst.totalBytes} bytes)`,
        algorithm: 'pqc-transition',
        primitive: 'certificate',
        location: where,
        confidence: 'medium',
        quantum: 'unknown',
        classical: 'acceptable',
        note: 'The projected certificate flight no longer fits in one TCP initial window. Expect an extra round trip, fragmentation, or middlebox failures. Consider a shorter chain, ML-DSA-65 over SLH-DSA, or certificate compression (RFC 8879).',
        evidence: {
          algorithm: worst.algorithm,
          totalBytes: worst.totalBytes,
          threshold: worst.threshold,
          overshootBytes: worst.totalBytes - worst.threshold,
          certificateMessageBytes: worst.certificateMessageBytes,
          certificateVerifyBytes: worst.certificateVerifyBytes,
          chainLength: chain.length,
          perCertificate: worst.perCertificate,
        },
      });
    } else {
      findings.push({
        id: 'chain-pqc-fits',
        kind: 'chain',
        title: `PQC chain would fit the initial congestion window (${worst.label}: ${worst.totalBytes} bytes)`,
        algorithm: worst.algorithm,
        primitive: 'certificate',
        location: where,
        confidence: 'medium',
        quantum: 'safe',
        classical: 'strong',
        positive: true,
        note: `Projected ${worst.totalBytes} bytes against a ${worst.threshold}-byte threshold, leaving ${worst.headroomBytes} bytes of headroom.`,
        evidence: { totalBytes: worst.totalBytes, threshold: worst.threshold, chainLength: chain.length },
      });
    }
  }

  return findings;
}
