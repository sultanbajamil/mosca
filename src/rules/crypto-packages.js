/**
 * MOSCA — cryptographic package intelligence
 * ==========================================
 *
 * A dependency is a cryptographic decision made by someone else, often
 * years ago. `node-rsa` pins you to RSA. `elliptic` pins you to ECDSA.
 * `@noble/post-quantum` is the opposite: a deliberate move to FIPS 203/204.
 *
 * The table below is intentionally small and opinionated. It covers the
 * packages that actually appear in audits, not every library that happens to
 * contain a hash function. Each entry maps to the same algorithm registry the
 * rest of MOSCA uses, so supply-chain findings participate in QRI, HNDL,
 * CBOM and SARIF without a second scoring model.
 */

/** @typedef {'quantum-safe'|'quantum-vulnerable'|'classically-broken'|'deprecated'|'mixed'} PackageStatus */

/**
 * @type {Record<string, {
 *   ecosystem: string, status: PackageStatus, algorithm: string,
 *   primitive: string, replacement?: string, note: string,
 *   maxVersion?: string, matchName?: (name:string)=>boolean
 * }>}
 */
export const CRYPTO_PACKAGES = {
  // ------------------------------------------------------------------- npm
  'crypto-js': {
    ecosystem: 'npm',
    status: 'deprecated',
    algorithm: 'aes-128',
    primitive: 'symmetric',
    replacement: 'aes-256-gcm',
    note: 'crypto-js is unmaintained, defaults to AES-128-CBC, and lacks modern AEAD and post-quantum primitives. Replace with @noble/ciphers or the WebCrypto API.',
  },
  'node-rsa': {
    ecosystem: 'npm',
    status: 'quantum-vulnerable',
    algorithm: 'rsa',
    primitive: 'pke',
    replacement: 'ml-kem-768',
    note: 'Pure-JavaScript RSA. Every key it creates falls to Shor; migrate confidentiality to ML-KEM-768 and signatures to ML-DSA-65.',
  },
  jsencrypt: {
    ecosystem: 'npm',
    status: 'quantum-vulnerable',
    algorithm: 'rsa',
    primitive: 'pke',
    replacement: 'ml-kem-768',
    note: 'Browser RSA helper. No post-quantum path.',
  },
  'node-forge': {
    ecosystem: 'npm',
    status: 'quantum-vulnerable',
    algorithm: 'rsa',
    primitive: 'pke',
    replacement: 'ml-kem-768',
    note: 'node-forge ships RSA, ECDSA and legacy TLS primitives. Audit which parts are used; the asymmetric surface is quantum-vulnerable.',
  },
  elliptic: {
    ecosystem: 'npm',
    status: 'quantum-vulnerable',
    algorithm: 'ecdsa',
    primitive: 'signature',
    replacement: 'ml-dsa-65',
    note: 'Elliptic-curve arithmetic in JavaScript. ECDSA and ECDH are broken by Shor; the package explicitly does not implement post-quantum curves.',
  },
  tweetnacl: {
    ecosystem: 'npm',
    status: 'quantum-vulnerable',
    algorithm: 'ed25519',
    primitive: 'signature',
    replacement: 'ml-dsa-65',
    note: 'TweetNaCl provides X25519 and Ed25519. Excellent classical code, but both primitives fall to Shor.',
  },
  'libsodium-wrappers': {
    ecosystem: 'npm',
    status: 'quantum-vulnerable',
    algorithm: 'ed25519',
    primitive: 'signature',
    replacement: 'ml-dsa-65',
    note: 'libsodium exposes X25519/Ed25519, not ML-KEM or ML-DSA. Hybrid TLS still protects transport, but application-level signing needs a PQ scheme.',
  },
  '@noble/curves': {
    ecosystem: 'npm',
    status: 'quantum-vulnerable',
    algorithm: 'ecdsa',
    primitive: 'signature',
    replacement: 'ml-dsa-65',
    note: 'Audited classical curves only. Pair it with @noble/post-quantum if signatures must survive a CRQC.',
  },
  '@noble/post-quantum': {
    ecosystem: 'npm',
    status: 'quantum-safe',
    algorithm: 'ml-kem-768',
    primitive: 'key-agreement',
    note: 'FIPS 203/204/205 primitives in audited JavaScript. Record it as a positive control and keep the version current.',
  },
  'mlkem': {
    ecosystem: 'npm',
    status: 'quantum-safe',
    algorithm: 'ml-kem-768',
    primitive: 'key-agreement',
    note: 'ML-KEM implementation for Node.js.',
  },
  liboqs: {
    ecosystem: 'native',
    status: 'quantum-safe',
    algorithm: 'ml-kem-768',
    primitive: 'key-agreement',
    note: 'Open Quantum Safe reference library. Provides ML-KEM, ML-DSA and SLH-DSA.',
  },
  'oqs-js': {
    ecosystem: 'npm',
    status: 'quantum-safe',
    algorithm: 'ml-kem-768',
    primitive: 'key-agreement',
    note: 'JavaScript bindings to liboqs.',
  },

  // ---------------------------------------------------------------- python
  pycrypto: {
    ecosystem: 'pypi',
    status: 'classically-broken',
    algorithm: 'des',
    primitive: 'symmetric',
    replacement: 'aes-256-gcm',
    note: 'PyCrypto is abandoned and ships DES/RC4-era primitives. It is classically unsafe, not merely quantum-vulnerable. Migrate to pyca/cryptography.',
  },
  pycryptodome: {
    ecosystem: 'pypi',
    status: 'quantum-vulnerable',
    algorithm: 'rsa',
    primitive: 'pke',
    replacement: 'ml-kem-768',
    note: 'PyCryptodome is maintained, but its RSA/ECC/DSA surface is quantum-vulnerable. AES-256 and SHA-2 are fine.',
  },
  'python-rsa': {
    ecosystem: 'pypi',
    status: 'quantum-vulnerable',
    algorithm: 'rsa',
    primitive: 'pke',
    replacement: 'ml-kem-768',
    note: 'Pure-Python RSA. No post-quantum path.',
  },
  'ecdsa': {
    ecosystem: 'pypi',
    status: 'quantum-vulnerable',
    algorithm: 'ecdsa',
    primitive: 'signature',
    replacement: 'ml-dsa-65',
    note: 'Pure-Python ECDSA. Broken by Shor; replace signatures with ML-DSA-65.',
  },
  pqcrypto: {
    ecosystem: 'pypi/cargo',
    status: 'quantum-safe',
    algorithm: 'ml-kem-768',
    primitive: 'key-agreement',
    note: 'Bindings for PQClean implementations of ML-KEM, ML-DSA and SLH-DSA (Python and Rust ecosystems).',
  },
  'py-mlkem': {
    ecosystem: 'pypi',
    status: 'quantum-safe',
    algorithm: 'ml-kem-768',
    primitive: 'key-agreement',
    note: 'ML-KEM implementation for Python.',
  },

  // -------------------------------------------------------------------- go
  'golang.org/x/crypto': {
    ecosystem: 'go',
    status: 'quantum-vulnerable',
    algorithm: 'ssh-rsa',
    primitive: 'signature',
    replacement: 'ml-dsa-65',
    maxVersion: '0.33.0',
    matchName: (name) => name === 'golang.org/x/crypto' || name.startsWith('golang.org/x/crypto/'),
    note: 'Older golang.org/x/crypto/ssh releases predate ML-KEM and the modern SSH hybrid KEX. Upgrade before enabling post-quantum SSH.',
  },
  'github.com/cloudflare/circl': {
    ecosystem: 'go',
    status: 'quantum-safe',
    algorithm: 'ml-kem-768',
    primitive: 'key-agreement',
    matchName: (name) => name === 'github.com/cloudflare/circl' || name.startsWith('github.com/cloudflare/circl/'),
    note: 'Cloudflare CIRCL implements ML-KEM, ML-DSA, SLH-DSA and hybrid KEMs.',
  },

  // ----------------------------------------------------------------- cargo
  'rsa': {
    ecosystem: 'cargo',
    status: 'quantum-vulnerable',
    algorithm: 'rsa',
    primitive: 'pke',
    replacement: 'ml-kem-768',
    note: 'Rust RSA crate. Quantum-vulnerable at every key size.',
  },
  'ed25519-dalek': {
    ecosystem: 'cargo',
    status: 'quantum-vulnerable',
    algorithm: 'ed25519',
    primitive: 'signature',
    replacement: 'ml-dsa-65',
    note: 'Ed25519 signatures fall to Shor. Use ml-dsa or slh-dsa for long-lived integrity.',
  },
  'x25519-dalek': {
    ecosystem: 'cargo',
    status: 'quantum-vulnerable',
    algorithm: 'x25519',
    primitive: 'key-agreement',
    replacement: 'x25519mlkem768',
    note: 'X25519 key agreement is quantum-vulnerable. Prefer a hybrid ML-KEM construction.',
  },
  'ml-kem': {
    ecosystem: 'cargo',
    status: 'quantum-safe',
    algorithm: 'ml-kem-768',
    primitive: 'key-agreement',
    note: 'RustCrypto ML-KEM implementation (FIPS 203).',
  },
  'ml-dsa': {
    ecosystem: 'cargo',
    status: 'quantum-safe',
    algorithm: 'ml-dsa-65',
    primitive: 'signature',
    note: 'RustCrypto ML-DSA implementation (FIPS 204).',
  },

  // ------------------------------------------------------------------ maven
  'org.bouncycastle:bcprov-jdk15on': {
    ecosystem: 'maven',
    status: 'quantum-vulnerable',
    algorithm: 'rsa',
    primitive: 'pke',
    replacement: 'ml-kem-768',
    note: 'Legacy Bouncy Castle line. Newer releases add ML-KEM/ML-DSA, but this artifact pins the classical API generation.',
  },
  'org.bouncycastle:bcprov-jdk18on': {
    ecosystem: 'maven',
    status: 'mixed',
    algorithm: 'rsa',
    primitive: 'pke',
    replacement: 'ml-kem-768',
    note: 'Bouncy Castle has post-quantum primitives, but the default APIs remain classical. Check which provider is actually used.',
  },
  'com.nimbusds:nimbus-jose-jwt': {
    ecosystem: 'maven',
    status: 'quantum-vulnerable',
    algorithm: 'rsa',
    primitive: 'signature',
    replacement: 'ml-dsa-65',
    note: 'JOSE library defaulting to RS256/ES256. Plan ML-DSA JOSE profiles for long-lived tokens.',
  },
};

/** Parse a loose version into numeric components. */
export function versionParts(value) {
  return String(value || '')
    .replace(/^[~^<>=v\s]+/, '')
    .split(/[.+-]/)
    .slice(0, 3)
    .map((part) => Number.parseInt(part, 10) || 0);
}

/** True when `a` is strictly older than `b`. */
export function versionLessThan(a, b) {
  const left = versionParts(a);
  const right = versionParts(b);
  for (let i = 0; i < 3; i++) {
    if ((left[i] || 0) < (right[i] || 0)) return true;
    if ((left[i] || 0) > (right[i] || 0)) return false;
  }
  return false;
}

/**
 * Find the rule for a package name. Exact matches win; predicate rules second.
 * @param {string} name
 */
export function packageRule(name) {
  const normalised = String(name || '').replace(/^node_modules\//, '');
  if (CRYPTO_PACKAGES[normalised]) return CRYPTO_PACKAGES[normalised];
  if (CRYPTO_PACKAGES[normalised.toLowerCase()]) return CRYPTO_PACKAGES[normalised.toLowerCase()];
  for (const rule of Object.values(CRYPTO_PACKAGES)) {
    if (rule.matchName && rule.matchName(normalised)) return rule;
  }
  return null;
}
