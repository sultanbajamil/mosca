/**
 * MOSCA — compliance gates
 * ========================
 *
 * A QRI is useful for prioritisation but useless in an audit. Auditors ask a
 * different question: "does this estate meet the standard we are certified
 * against, and if not, which line fails?".
 *
 * This module maps enriched findings onto four concrete regimes:
 *
 *   cnsa2       NSA/CISA CNSA 2.0 (ML-KEM/ML-DSA, AES-256, SHA-384)
 *   nist-2030   NIST IR 8547 transition (RSA/ECC deprecated by 2030)
 *   pci-dss     PCI DSS v4.0 cryptography requirements (TLS 1.2+, no RC4/3DES)
 *   hipaa       HIPAA Security Rule encryption safeguards for ePHI
 *
 * Every control is a predicate over the unified finding stream. That keeps
 * the gate explainable: each failure names the finding, algorithm and
 * location that caused it, and each control names its remediation.
 */

/** A control fails when its predicate returns true for any non-positive item. */
function isAsymmetric(item) {
  return ['signature', 'key-agreement', 'pke', 'certificate'].includes(item.primitive);
}

function asymmetricQuantumBroken(item) {
  return !item.positive && isAsymmetric(item) && item.quantum === 'broken';
}

const SYMMETRIC_WEAK = new Set(['des', '3des', 'rc4', 'none', 'export']);
const HASH_BROKEN = new Set(['md5', 'sha1']);
const TLS_LEGACY = new Set(['tls-1.0', 'tls-1.1', 'ssl-3.0', 'ssl-2.0', 'sslv3', 'sslv2']);

function isWeakSymmetric(item) {
  if (item.positive) return false;
  if (SYMMETRIC_WEAK.has(item.algorithm)) return true;
  return item.algorithm === 'aes-128' || item.algorithm === 'aes-192';
}

function isBrokenHash(item) {
  return !item.positive && HASH_BROKEN.has(item.algorithm);
}

function isLegacyTls(item) {
  return !item.positive && (TLS_LEGACY.has(item.algorithm) || /^ssl/.test(item.algorithm));
}

function isSmallRsa(item) {
  if (item.positive) return false;
  const match = /^rsa-(\d+)$/.exec(item.algorithm || '');
  return Boolean(match && Number(match[1]) < 2048);
}

function isConfidentialityExposure(item) {
  const confidentiality = ['key-agreement', 'pke', 'symmetric'].includes(item.primitive);
  return !item.positive && confidentiality && item.mosca?.exposed && item.quantum !== 'safe';
}

function isPqcControlPresent(item) {
  return (
    item.positive &&
    (item.quantum === 'safe' && isAsymmetric(item) ||
      item.finding?.id === 'dependency-pqc-ready' ||
      item.id === 'dependency-pqc-ready' ||
      item.id === 'chain-pqc-fits')
  );
}

/**
 * Standard definitions. Controls are evaluated in order, so the report reads
 * like the auditor's checklist.
 */
export const COMPLIANCE_STANDARDS = {
  cnsa2: {
    id: 'cnsa2',
    label: 'CNSA 2.0',
    authority: 'NSA / CISA',
    deadline: '2030 for software and firmware signing; 2033 for networking equipment',
    description:
      'Commercial National Security Algorithm Suite 2.0. Requires ML-KEM for key establishment, ML-DSA for signatures, AES-256 for symmetric encryption and SHA-384 or stronger for hashing.',
    controls: [
      {
        id: 'cnsa2-key-establishment',
        label: 'Key establishment uses ML-KEM',
        requirement: 'TLS, SSH, QUIC, IPsec and application KEMs must negotiate ML-KEM-768/1024, hybrid constructions included.',
        remediation: 'Enable X25519MLKEM768 on the listener or upgrade the protocol library to one that implements FIPS 203.',
        severity: 'required',
        match: (item) => item.kind === 'endpoint' && item.primitive === 'key-agreement' && item.quantum === 'broken',
      },
      {
        id: 'cnsa2-signatures',
        label: 'Signatures use ML-DSA',
        requirement: 'Every digital signature that must remain valid past 2030 must use ML-DSA-65/87 (or SLH-DSA where size is not constrained).',
        remediation: 'Add a dual-signing period: keep the classical signature for compatibility and attach ML-DSA-65.',
        severity: 'required',
        match: (item) => isAsymmetric(item) && item.primitive === 'signature' && item.quantum === 'broken',
      },
      {
        id: 'cnsa2-symmetric',
        label: 'Symmetric encryption uses AES-256',
        requirement: 'AES-256 is required; AES-128, 3DES, DES and RC4 are not approved.',
        remediation: 'Rotate data keys to AES-256-GCM or AES-256-CBC with an authenticated MAC.',
        severity: 'required',
        match: isWeakSymmetric,
      },
      {
        id: 'cnsa2-hash',
        label: 'Hashing uses SHA-384 or stronger',
        requirement: 'MD5 and SHA-1 are prohibited. CNSA 2.0 selects SHA-384 for integrity.',
        remediation: 'Replace MD5/SHA-1 with SHA-384 (or SHA-512) and re-issue dependent signatures.',
        severity: 'required',
        match: isBrokenHash,
      },
    ],
  },

  'nist-2030': {
    id: 'nist-2030',
    label: 'NIST 2030 transition',
    authority: 'NIST IR 8547',
    deadline: '2030: deprecate RSA/ECC in new systems; 2035: disallow entirely',
    description:
      'NIST expects RSA, ECDSA, ECDH, DSA and EdDSA to be deprecated by 2030 and removed by 2035. This gate treats every classical asymmetric primitive as a planned migration item.',
    controls: [
      {
        id: 'nist-asymmetric-2030',
        label: 'Classical asymmetric algorithms have a migration plan',
        requirement: 'RSA, ECDSA, ECDH, DSA and EdDSA must be replaced by FIPS 203/204/205 before 2030.',
        remediation: 'Inventory each key and certificate, then schedule an ML-KEM/ML-DSA replacement with a dual-running period.',
        severity: 'required',
        match: asymmetricQuantumBroken,
      },
      {
        id: 'nist-symmetric-128',
        label: 'Symmetric strength is at least 128 bits',
        requirement: '3DES, DES and RC4 are below the 112-bit floor and must not be used.',
        remediation: 'Use AES-128-GCM or AES-256-GCM; migrate legacy hardware first.',
        severity: 'required',
        match: (item) => !item.positive && SYMMETRIC_WEAK.has(item.algorithm),
      },
      {
        id: 'nist-hash-256',
        label: 'Hash strength is at least 256 bits',
        requirement: 'MD5 and SHA-1 no longer provide the collision resistance NIST requires for new systems.',
        remediation: 'Replace with SHA-256 or SHA-384 and re-sign affected artifacts.',
        severity: 'required',
        match: isBrokenHash,
      },
      {
        id: 'nist-pqc-agility',
        label: 'At least one FIPS 203/204/205 capability is deployed',
        requirement: 'A transition plan needs evidence that at least one post-quantum primitive is already available in the estate.',
        remediation: 'Land @noble/post-quantum, liboqs, ML-KEM TLS groups or ML-DSA JOSE profiles in a non-production path.',
        severity: 'recommended',
        // Pass when a PQC control exists, or when there is no asymmetric debt.
        match: () => false,
        evaluate: (items) => {
          const hasClassicalDebt = items.some(asymmetricQuantumBroken);
          if (!hasClassicalDebt) return [];
          const hasPqc = items.some(isPqcControlPresent);
          return hasPqc ? [] : [{ synthetic: 'nist-pqc-agility', title: 'No FIPS 203/204/205 capability found in the scanned estate' }];
        },
      },
    ],
  },

  'pci-dss': {
    id: 'pci-dss',
    label: 'PCI DSS v4.0',
    authority: 'PCI SSC',
    deadline: 'Continuous; v4.0 future-dated requirements effective 31 March 2025',
    description:
      'PCI DSS requires strong cryptography for cardholder data in transit and at rest, prohibits SSL/early TLS, RC4 and 3DES, and sets minimum key lengths.',
    controls: [
      {
        id: 'pci-tls-version',
        label: 'TLS 1.2 or higher',
        requirement: 'SSL, TLS 1.0 and TLS 1.1 are prohibited for cardholder data environments.',
        remediation: 'Raise the minimum protocol version to TLS 1.2 and prefer TLS 1.3 for hybrid key exchange.',
        severity: 'required',
        match: isLegacyTls,
      },
      {
        id: 'pci-weak-ciphers',
        label: 'No RC4, 3DES, DES or NULL ciphers',
        requirement: 'Only strong cipher suites may protect cardholder data.',
        remediation: 'Remove the cipher from the policy and rotate any key that protected cardholder data with it.',
        severity: 'required',
        match: (item) => !item.positive && SYMMETRIC_WEAK.has(item.algorithm),
      },
      {
        id: 'pci-key-length',
        label: 'RSA keys are at least 2048 bits',
        requirement: 'RSA-1024 and smaller are not acceptable for new or renewed keys.',
        remediation: 'Re-issue RSA-2048+ certificates and keys; plan the ML-KEM/ML-DSA replacement at the same time.',
        severity: 'required',
        match: isSmallRsa,
      },
      {
        id: 'pci-hash',
        label: 'No MD5 or SHA-1',
        requirement: 'MD5 and SHA-1 are unacceptable for cryptographic protection of cardholder data.',
        remediation: 'Move to SHA-256 or SHA-384 for integrity and signatures.',
        severity: 'required',
        match: isBrokenHash,
      },
      {
        id: 'pci-hndl',
        label: 'Cardholder traffic resists harvest-now-decrypt-later',
        requirement: 'Long-lived cardholder data must not be protected by a quantum-vulnerable key exchange.',
        remediation: 'Enable hybrid ML-KEM key exchange on every internet-facing payment endpoint.',
        severity: 'recommended',
        match: (item) => isConfidentialityExposure(item) && item.kind === 'endpoint',
      },
    ],
  },

  hipaa: {
    id: 'hipaa',
    label: 'HIPAA Security Rule',
    authority: 'HHS / OCR',
    deadline: 'Continuous',
    description:
      'The Security Rule requires encryption of electronic protected health information in transit and at rest, plus integrity controls. ePHI is typically retained for decades, which makes harvest-now-decrypt-later a direct disclosure risk.',
    controls: [
      {
        id: 'hipaa-transit',
        label: 'ePHI in transit uses TLS 1.2+ with forward secrecy',
        requirement: 'Legacy TLS and static-RSA key exchange are not adequate safeguards for ePHI.',
        remediation: 'Require TLS 1.3 or TLS 1.2 with ECDHE, and enable X25519MLKEM768 where supported.',
        severity: 'required',
        match: (item) =>
          isLegacyTls(item) ||
          (!item.positive && item.kind === 'endpoint' && item.primitive === 'key-agreement' && item.algorithm === 'rsa'),
      },
      {
        id: 'hipaa-at-rest',
        label: 'ePHI at rest uses AES-256',
        requirement: 'AES-128, 3DES and DES do not meet the current expectation for ePHI at rest.',
        remediation: 'Re-encrypt data sets and backups with AES-256-GCM under a managed key service.',
        severity: 'required',
        match: isWeakSymmetric,
      },
      {
        id: 'hipaa-integrity',
        label: 'ePHI integrity does not rely on MD5 or SHA-1',
        requirement: 'Integrity controls must use a collision-resistant hash.',
        remediation: 'Replace MD5/SHA-1 with SHA-256 or SHA-384 and re-baseline stored digests.',
        severity: 'required',
        match: isBrokenHash,
      },
      {
        id: 'hipaa-hndl',
        label: 'Long-lived ePHI is not exposed to HNDL',
        requirement: 'Retention periods for ePHI routinely exceed the time to a CRQC.',
        remediation: 'Treat every quantum-vulnerable confidentiality primitive as an active disclosure and prioritise hybrid KEM.',
        severity: 'required',
        match: isConfidentialityExposure,
      },
    ],
  },
};

/** All standard ids in display order. */
export const COMPLIANCE_IDS = Object.keys(COMPLIANCE_STANDARDS);

/** Normalise a standard selector; returns null for an unknown id. */
export function resolveStandard(id) {
  if (!id) return null;
  const key = String(id).toLowerCase();
  if (key === 'all') return 'all';
  return COMPLIANCE_STANDARDS[key] ? key : null;
}

function compact(item) {
  return {
    fingerprint: item.fingerprint || null,
    id: item.id || null,
    title: item.title || null,
    algorithm: item.algorithm || null,
    kind: item.kind || null,
    severity: item.severity || null,
    positive: Boolean(item.positive),
    location: item.location || null,
  };
}

/**
 * Evaluate one standard.
 * @param {object|object[]} analysis analysis object or an items array
 * @param {string} standardId
 */
export function evaluateCompliance(analysis, standardId) {
  const standard = COMPLIANCE_STANDARDS[standardId];
  if (!standard) throw new Error(`unknown compliance standard: ${standardId}`);
  const items = Array.isArray(analysis) ? analysis : analysis.items || [];
  const evaluatedItems = items.filter((item) => !item.positive);

  const controls = standard.controls.map((control) => {
    let violations;
    if (control.evaluate) {
      violations = control.evaluate(items);
    } else {
      violations = evaluatedItems.filter((item) => control.match(item)).map(compact);
    }
    return {
      id: control.id,
      label: control.label,
      requirement: control.requirement,
      remediation: control.remediation,
      severity: control.severity,
      status: violations.length === 0 ? 'pass' : 'fail',
      violations,
      violationCount: violations.length,
    };
  });

  const failed = controls.filter((c) => c.status === 'fail');
  const requiredFailed = failed.filter((c) => c.severity === 'required');
  const status = failed.length === 0 ? 'pass' : requiredFailed.length > 0 ? 'fail' : 'partial';
  const score = Math.round(((controls.length - failed.length) / controls.length) * 1000) / 10;

  return {
    id: standard.id,
    label: standard.label,
    authority: standard.authority,
    deadline: standard.deadline,
    description: standard.description,
    status,
    score,
    controls,
    violationCount: failed.reduce((sum, c) => sum + c.violationCount, 0),
    // The first non-passing control is what the report should lead with.
    topControl: failed[0] || null,
  };
}

/**
 * Evaluate every standard, or just the selected one.
 * @param {object|object[]} analysis
 * @param {string} [selection] standard id, `all`, or undefined (all)
 */
export function evaluateAllCompliance(analysis, selection) {
  const resolved = resolveStandard(selection);
  if (resolved === null && selection) throw new Error(`unknown compliance standard: ${selection}`);
  const ids = !selection || resolved === 'all' ? COMPLIANCE_IDS : [resolved];
  return ids.map((id) => evaluateCompliance(analysis, id));
}

/**
 * A one-line verdict suitable for tables and CI annotations.
 * @param {object} result
 */
export function complianceVerdict(result) {
  if (!result) return 'not evaluated';
  if (result.status === 'pass') return 'PASS';
  return `${result.status.toUpperCase()} (${result.violationCount} violation${result.violationCount === 1 ? '' : 's'}, score ${result.score})`;
}
