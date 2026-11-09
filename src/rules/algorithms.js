/**
 * MOSCA — algorithm registry
 * ==========================
 *
 * A single, auditable source of truth for "is this primitive safe after
 * quantum computers arrive?".
 *
 * Every entry is classified on two independent axes:
 *
 *   quantum   — resistance to a cryptographically relevant quantum computer
 *               (CRQC) running Shor's algorithm (asymmetric) or Grover's
 *               algorithm (symmetric / hash).
 *
 *   classical — resistance to today's best classical attacks.
 *
 * Values for `quantum`:
 *   broken    Shor breaks it outright. RSA, (EC)DH, ECDSA, DSA, Ed25519...
 *   weakened  Grover gives a quadratic speed-up; the effective security
 *             level is roughly halved. AES-128 -> ~64-bit.
 *   safe      No known quantum speed-up that matters at the recommended
 *             parameter set (ML-KEM, ML-DSA, AES-256, SHA-384...).
 *   unknown   We do not have a confident classification.
 *
 * Values for `classical`:
 *   broken | weak | acceptable | strong
 *
 * `replacement` points at the id of the algorithm that should be adopted.
 * `standard` cites the normative document. `hybrid` is the recommended
 * transition construct where a drop-in hybrid exists.
 *
 * References are collected in docs/METHODOLOGY.md.
 */

/** @typedef {'broken'|'weakened'|'safe'|'unknown'} QuantumStatus */
/** @typedef {'broken'|'weak'|'acceptable'|'strong'} ClassicalStatus */

const Q = {
  BROKEN: 'broken',
  WEAKENED: 'weakened',
  SAFE: 'safe',
  UNKNOWN: 'unknown',
};

const C = {
  BROKEN: 'broken',
  WEAK: 'weak',
  ACCEPTABLE: 'acceptable',
  STRONG: 'strong',
};

/** Ordered so that comparisons like `atLeast(a, b)` are meaningful. */
export const QUANTUM_RANK = { safe: 0, weakened: 1, unknown: 2, broken: 3 };
export const CLASSICAL_RANK = { strong: 0, acceptable: 1, weak: 2, broken: 3 };

/**
 * @type {Record<string, {
 *   id: string, label: string, primitives: string[], quantum: QuantumStatus,
 *   classical: ClassicalStatus, replacement?: string, standard?: string,
 *   hybrid?: string, deprecated?: boolean, note?: string
 * }>}
 */
export const ALGORITHMS = {
  // ---------------------------------------------------------------- RSA ---
  rsa: {
    id: 'rsa',
    label: 'RSA',
    primitives: ['pke', 'signature'],
    quantum: Q.BROKEN,
    classical: C.ACCEPTABLE,
    replacement: 'ml-kem-768',
    standard: 'FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA)',
    hybrid: 'X25519MLKEM768',
    note: 'Shor factors the modulus in polynomial time. Key size is irrelevant: RSA-16384 falls as fast as RSA-2048.',
  },
  'rsa-512': {
    id: 'rsa-512',
    label: 'RSA-512',
    primitives: ['pke', 'signature'],
    quantum: Q.BROKEN,
    classical: C.BROKEN,
    replacement: 'ml-kem-768',
    standard: 'FIPS 203',
    note: 'Classically factorable with modest resources.',
  },
  'rsa-1024': {
    id: 'rsa-1024',
    label: 'RSA-1024',
    primitives: ['pke', 'signature'],
    quantum: Q.BROKEN,
    classical: C.WEAK,
    replacement: 'ml-kem-768',
    standard: 'FIPS 203',
    note: 'Below the 2048-bit floor required by NIST SP 800-57 and CA/Browser Forum.',
  },
  'rsa-2048': {
    id: 'rsa-2048',
    label: 'RSA-2048',
    primitives: ['pke', 'signature'],
    quantum: Q.BROKEN,
    classical: C.ACCEPTABLE,
    replacement: 'ml-kem-768',
    standard: 'FIPS 203',
    hybrid: 'X25519MLKEM768',
    note: 'Classically fine today, but NIST deprecates it for new use after 2030 and disallows it after 2035.',
  },
  'rsa-3072': {
    id: 'rsa-3072',
    label: 'RSA-3072',
    primitives: ['pke', 'signature'],
    quantum: Q.BROKEN,
    classical: C.STRONG,
    replacement: 'ml-kem-768',
    standard: 'FIPS 203',
  },
  'rsa-4096': {
    id: 'rsa-4096',
    label: 'RSA-4096',
    primitives: ['pke', 'signature'],
    quantum: Q.BROKEN,
    classical: C.STRONG,
    replacement: 'ml-kem-768',
    standard: 'FIPS 203',
  },

  // ------------------------------------------------------- Diffie-Hellman ---
  dh: {
    id: 'dh',
    label: 'Diffie-Hellman (finite field)',
    primitives: ['key-agreement'],
    quantum: Q.BROKEN,
    classical: C.ACCEPTABLE,
    replacement: 'ml-kem-768',
    standard: 'FIPS 203',
    hybrid: 'X25519MLKEM768',
    note: 'Shor solves the discrete logarithm problem over finite fields.',
  },
  dsa: {
    id: 'dsa',
    label: 'DSA',
    primitives: ['signature'],
    quantum: Q.BROKEN,
    classical: C.WEAK,
    replacement: 'ml-dsa-65',
    standard: 'FIPS 204',
    deprecated: true,
    note: 'FIPS 186-5 withdraws DSA for digital signature generation.',
  },
  elgamal: {
    id: 'elgamal',
    label: 'ElGamal',
    primitives: ['pke'],
    quantum: Q.BROKEN,
    classical: C.ACCEPTABLE,
    replacement: 'ml-kem-768',
    standard: 'FIPS 203',
  },

  // ----------------------------------------------------------- Elliptic ---
  ecdh: {
    id: 'ecdh',
    label: 'ECDH',
    primitives: ['key-agreement'],
    quantum: Q.BROKEN,
    classical: C.STRONG,
    replacement: 'x25519mlkem768',
    standard: 'FIPS 203 + draft-ietf-tls-ecdhe-mlkem',
    hybrid: 'X25519MLKEM768',
    note: 'Shor solves ECDLP. Curve size does not help; P-521 is as dead as P-256.',
  },
  ecdsa: {
    id: 'ecdsa',
    label: 'ECDSA',
    primitives: ['signature'],
    quantum: Q.BROKEN,
    classical: C.STRONG,
    replacement: 'ml-dsa-65',
    standard: 'FIPS 204',
  },
  x25519: {
    id: 'x25519',
    label: 'X25519',
    primitives: ['key-agreement'],
    quantum: Q.BROKEN,
    classical: C.STRONG,
    replacement: 'x25519mlkem768',
    standard: 'FIPS 203 + draft-ietf-tls-ecdhe-mlkem',
    hybrid: 'X25519MLKEM768',
  },
  x448: {
    id: 'x448',
    label: 'X448',
    primitives: ['key-agreement'],
    quantum: Q.BROKEN,
    classical: C.STRONG,
    replacement: 'x25519mlkem768',
    standard: 'FIPS 203',
  },
  ed25519: {
    id: 'ed25519',
    label: 'Ed25519',
    primitives: ['signature'],
    quantum: Q.BROKEN,
    classical: C.STRONG,
    replacement: 'ml-dsa-65',
    standard: 'FIPS 204',
  },
  ed448: {
    id: 'ed448',
    label: 'Ed448',
    primitives: ['signature'],
    quantum: Q.BROKEN,
    classical: C.STRONG,
    replacement: 'ml-dsa-87',
    standard: 'FIPS 204',
  },
  secp256k1: {
    id: 'secp256k1',
    label: 'secp256k1',
    primitives: ['signature', 'key-agreement'],
    quantum: Q.BROKEN,
    classical: C.STRONG,
    replacement: 'ml-dsa-65',
    standard: 'FIPS 204',
  },
  ecies: {
    id: 'ecies',
    label: 'ECIES',
    primitives: ['pke'],
    quantum: Q.BROKEN,
    classical: C.STRONG,
    replacement: 'ml-kem-768',
    standard: 'FIPS 203',
  },

  // ------------------------------------------------- post-quantum (safe) ---
  'ml-kem-512': {
    id: 'ml-kem-512',
    label: 'ML-KEM-512',
    primitives: ['key-agreement', 'pke'],
    quantum: Q.SAFE,
    classical: C.STRONG,
    standard: 'FIPS 203',
    note: 'NIST security category 1. Prefer ML-KEM-768 for general use.',
  },
  'ml-kem-768': {
    id: 'ml-kem-768',
    label: 'ML-KEM-768',
    primitives: ['key-agreement', 'pke'],
    quantum: Q.SAFE,
    classical: C.STRONG,
    standard: 'FIPS 203',
    note: 'NIST security category 3. The recommended general-purpose KEM.',
  },
  'ml-kem-1024': {
    id: 'ml-kem-1024',
    label: 'ML-KEM-1024',
    primitives: ['key-agreement', 'pke'],
    quantum: Q.SAFE,
    classical: C.STRONG,
    standard: 'FIPS 203',
    note: 'NIST security category 5.',
  },
  'ml-dsa-44': {
    id: 'ml-dsa-44',
    label: 'ML-DSA-44',
    primitives: ['signature'],
    quantum: Q.SAFE,
    classical: C.STRONG,
    standard: 'FIPS 204',
  },
  'ml-dsa-65': {
    id: 'ml-dsa-65',
    label: 'ML-DSA-65',
    primitives: ['signature'],
    quantum: Q.SAFE,
    classical: C.STRONG,
    standard: 'FIPS 204',
    note: 'NIST security category 3. The recommended general-purpose signature.',
  },
  'ml-dsa-87': {
    id: 'ml-dsa-87',
    label: 'ML-DSA-87',
    primitives: ['signature'],
    quantum: Q.SAFE,
    classical: C.STRONG,
    standard: 'FIPS 204',
  },
  'slh-dsa-128s': {
    id: 'slh-dsa-128s',
    label: 'SLH-DSA-SHA2-128s',
    primitives: ['signature'],
    quantum: Q.SAFE,
    classical: C.STRONG,
    standard: 'FIPS 205',
    note: 'Stateless hash-based signature. Large signatures, very conservative assumptions.',
  },
  'slh-dsa-128f': {
    id: 'slh-dsa-128f',
    label: 'SLH-DSA-SHA2-128f',
    primitives: ['signature'],
    quantum: Q.SAFE,
    classical: C.STRONG,
    standard: 'FIPS 205',
  },
  'slh-dsa-192s': {
    id: 'slh-dsa-192s',
    label: 'SLH-DSA-SHA2-192s',
    primitives: ['signature'],
    quantum: Q.SAFE,
    classical: C.STRONG,
    standard: 'FIPS 205',
  },
  'slh-dsa-256s': {
    id: 'slh-dsa-256s',
    label: 'SLH-DSA-SHA2-256s',
    primitives: ['signature'],
    quantum: Q.SAFE,
    classical: C.STRONG,
    standard: 'FIPS 205',
  },
  'x25519mlkem768': {
    id: 'x25519mlkem768',
    label: 'X25519MLKEM768 (hybrid)',
    primitives: ['key-agreement'],
    quantum: Q.SAFE,
    classical: C.STRONG,
    standard: 'draft-ietf-tls-ecdhe-mlkem',
    note: 'Hybrid: survives a break of either X25519 or ML-KEM. Deployed by Chrome, Firefox, Cloudflare, Google, AWS.',
  },
  'x25519kyber768draft00': {
    id: 'x25519kyber768draft00',
    label: 'X25519Kyber768Draft00 (hybrid, draft)',
    primitives: ['key-agreement'],
    quantum: Q.SAFE,
    classical: C.STRONG,
    standard: 'draft-kwiatkowski-tls-ecdhe-kyber',
    note: 'Pre-standard Kyber. Migrate to X25519MLKEM768 (codepoint 0x11EC).',
  },
  'sntrup761x25519': {
    id: 'sntrup761x25519',
    label: 'sntrup761x25519 (hybrid)',
    primitives: ['key-agreement'],
    quantum: Q.SAFE,
    classical: C.STRONG,
    note: 'NIST alternate candidate. Default hybrid in OpenSSH and OpenSSL 3.x.',
  },
  'mlkem768x25519': {
    id: 'mlkem768x25519',
    label: 'mlkem768x25519-sha256 (hybrid)',
    primitives: ['key-agreement'],
    quantum: Q.SAFE,
    classical: C.STRONG,
    standard: 'OpenSSH 9.9+',
  },
  sntrup761: {
    id: 'sntrup761',
    label: 'sntrup761',
    primitives: ['key-agreement'],
    quantum: Q.SAFE,
    classical: C.STRONG,
  },
  frodokem: {
    id: 'frodokem',
    label: 'FrodoKEM',
    primitives: ['key-agreement'],
    quantum: Q.SAFE,
    classical: C.STRONG,
    note: 'Conservative, large keys. ISO/IEC 18033-2 candidate, not NIST-standardised.',
  },
  hqc: {
    id: 'hqc',
    label: 'HQC',
    primitives: ['key-agreement'],
    quantum: Q.SAFE,
    classical: C.STRONG,
    note: 'Selected by NIST in March 2025 as a code-based backup KEM.',
  },

  // --------------------------------------------------------- symmetric ---
  'aes-128': {
    id: 'aes-128',
    label: 'AES-128',
    primitives: ['symmetric'],
    quantum: Q.WEAKENED,
    classical: C.STRONG,
    replacement: 'aes-256',
    note: "Grover's algorithm gives ~2^64 quantum work against AES-128. Move to AES-256 for data that must outlive the machine.",
  },
  'aes-192': {
    id: 'aes-192',
    label: 'AES-192',
    primitives: ['symmetric'],
    quantum: Q.SAFE,
    classical: C.STRONG,
    note: '~96-bit post-quantum security.',
  },
  'aes-256': {
    id: 'aes-256',
    label: 'AES-256',
    primitives: ['symmetric'],
    quantum: Q.SAFE,
    classical: C.STRONG,
    note: '~128-bit post-quantum security. The recommended choice.',
  },
  'aes-128-gcm': {
    id: 'aes-128-gcm',
    label: 'AES-128-GCM',
    primitives: ['symmetric'],
    quantum: Q.WEAKENED,
    classical: C.STRONG,
    replacement: 'aes-256-gcm',
  },
  'aes-256-gcm': {
    id: 'aes-256-gcm',
    label: 'AES-256-GCM',
    primitives: ['symmetric'],
    quantum: Q.SAFE,
    classical: C.STRONG,
  },
  'aes-128-cbc': {
    id: 'aes-128-cbc',
    label: 'AES-128-CBC',
    primitives: ['symmetric'],
    quantum: Q.WEAKENED,
    classical: C.ACCEPTABLE,
    replacement: 'aes-256-gcm',
    note: 'CBC without an AEAD is vulnerable to padding oracles when not authenticated.',
  },
  'aes-256-cbc': {
    id: 'aes-256-cbc',
    label: 'AES-256-CBC',
    primitives: ['symmetric'],
    quantum: Q.SAFE,
    classical: C.ACCEPTABLE,
    replacement: 'aes-256-gcm',
    note: 'Prefer an AEAD mode (GCM or ChaCha20-Poly1305).',
  },
  chacha20: {
    id: 'chacha20',
    label: 'ChaCha20',
    primitives: ['symmetric'],
    quantum: Q.SAFE,
    classical: C.STRONG,
  },
  'chacha20-poly1305': {
    id: 'chacha20-poly1305',
    label: 'ChaCha20-Poly1305',
    primitives: ['symmetric'],
    quantum: Q.SAFE,
    classical: C.STRONG,
  },
  '3des': {
    id: '3des',
    label: 'Triple DES',
    primitives: ['symmetric'],
    quantum: Q.WEAKENED,
    classical: C.WEAK,
    replacement: 'aes-256-gcm',
    deprecated: true,
    note: '64-bit block: Sweet32. NIST disallowed after 2023.',
  },
  des: {
    id: 'des',
    label: 'DES',
    primitives: ['symmetric'],
    quantum: Q.BROKEN,
    classical: C.BROKEN,
    replacement: 'aes-256-gcm',
    deprecated: true,
  },
  rc4: {
    id: 'rc4',
    label: 'RC4',
    primitives: ['symmetric'],
    quantum: Q.BROKEN,
    classical: C.BROKEN,
    replacement: 'aes-256-gcm',
    deprecated: true,
    note: 'Biased keystream. Prohibited by RFC 7465.',
  },
  rc2: {
    id: 'rc2',
    label: 'RC2',
    primitives: ['symmetric'],
    quantum: Q.BROKEN,
    classical: C.BROKEN,
    replacement: 'aes-256-gcm',
    deprecated: true,
  },
  blowfish: {
    id: 'blowfish',
    label: 'Blowfish',
    primitives: ['symmetric'],
    quantum: Q.WEAKENED,
    classical: C.WEAK,
    replacement: 'aes-256-gcm',
    note: '64-bit block size.',
  },
  cast5: {
    id: 'cast5',
    label: 'CAST5',
    primitives: ['symmetric'],
    quantum: Q.WEAKENED,
    classical: C.WEAK,
    replacement: 'aes-256-gcm',
  },
  idea: {
    id: 'idea',
    label: 'IDEA',
    primitives: ['symmetric'],
    quantum: Q.WEAKENED,
    classical: C.WEAK,
    replacement: 'aes-256-gcm',
  },
  sm4: {
    id: 'sm4',
    label: 'SM4',
    primitives: ['symmetric'],
    quantum: Q.SAFE,
    classical: C.STRONG,
    note: '128-bit key -> ~64-bit post-quantum. Consider a 256-bit cipher for long-lived data.',
  },
  'camellia-256': {
    id: 'camellia-256',
    label: 'Camellia-256',
    primitives: ['symmetric'],
    quantum: Q.SAFE,
    classical: C.STRONG,
  },
  fernet: {
    id: 'fernet',
    label: 'Fernet (AES-128-CBC + HMAC-SHA256)',
    primitives: ['symmetric', 'mac'],
    quantum: Q.WEAKENED,
    classical: C.STRONG,
    replacement: 'aes-256-gcm',
    note: 'Python cryptography Fernet uses a 128-bit AES key.',
  },

  // -------------------------------------------------------------- hash ---
  md5: {
    id: 'md5',
    label: 'MD5',
    primitives: ['hash'],
    quantum: Q.BROKEN,
    classical: C.BROKEN,
    replacement: 'sha256',
    deprecated: true,
    note: 'Practical collisions since 2004. Never use for security.',
  },
  sha1: {
    id: 'sha1',
    label: 'SHA-1',
    primitives: ['hash'],
    quantum: Q.BROKEN,
    classical: C.BROKEN,
    replacement: 'sha256',
    deprecated: true,
    note: 'SHAttered (2017) and chosen-prefix collisions (2020).',
  },
  sha224: {
    id: 'sha224',
    label: 'SHA-224',
    primitives: ['hash'],
    quantum: Q.SAFE,
    classical: C.STRONG,
  },
  sha256: {
    id: 'sha256',
    label: 'SHA-256',
    primitives: ['hash'],
    quantum: Q.SAFE,
    classical: C.STRONG,
    note: '~128-bit post-quantum preimage security.',
  },
  sha384: {
    id: 'sha384',
    label: 'SHA-384',
    primitives: ['hash'],
    quantum: Q.SAFE,
    classical: C.STRONG,
  },
  sha512: {
    id: 'sha512',
    label: 'SHA-512',
    primitives: ['hash'],
    quantum: Q.SAFE,
    classical: C.STRONG,
  },
  'sha3-256': {
    id: 'sha3-256',
    label: 'SHA3-256',
    primitives: ['hash'],
    quantum: Q.SAFE,
    classical: C.STRONG,
  },
  'sha3-512': {
    id: 'sha3-512',
    label: 'SHA3-512',
    primitives: ['hash'],
    quantum: Q.SAFE,
    classical: C.STRONG,
  },
  shake128: {
    id: 'shake128',
    label: 'SHAKE128',
    primitives: ['hash'],
    quantum: Q.SAFE,
    classical: C.STRONG,
  },
  shake256: {
    id: 'shake256',
    label: 'SHAKE256',
    primitives: ['hash'],
    quantum: Q.SAFE,
    classical: C.STRONG,
  },
  ripemd160: {
    id: 'ripemd160',
    label: 'RIPEMD-160',
    primitives: ['hash'],
    quantum: Q.WEAKENED,
    classical: C.WEAK,
    replacement: 'sha256',
    note: 'Only ~80-bit collision resistance. Used in Bitcoin addresses.',
  },
  sm3: {
    id: 'sm3',
    label: 'SM3',
    primitives: ['hash'],
    quantum: Q.SAFE,
    classical: C.STRONG,
  },
  blake2b: {
    id: 'blake2b',
    label: 'BLAKE2b',
    primitives: ['hash'],
    quantum: Q.SAFE,
    classical: C.STRONG,
  },
  blake3: {
    id: 'blake3',
    label: 'BLAKE3',
    primitives: ['hash'],
    quantum: Q.SAFE,
    classical: C.STRONG,
  },
  whirlpool: {
    id: 'whirlpool',
    label: 'Whirlpool',
    primitives: ['hash'],
    quantum: Q.SAFE,
    classical: C.WEAK,
    replacement: 'sha512',
  },

  // --------------------------------------------------------------- mac ---
  'hmac-md5': {
    id: 'hmac-md5',
    label: 'HMAC-MD5',
    primitives: ['mac'],
    quantum: Q.BROKEN,
    classical: C.BROKEN,
    replacement: 'hmac-sha256',
    deprecated: true,
  },
  'hmac-sha1': {
    id: 'hmac-sha1',
    label: 'HMAC-SHA1',
    primitives: ['mac'],
    quantum: Q.WEAKENED,
    classical: C.WEAK,
    replacement: 'hmac-sha256',
    deprecated: true,
  },
  'hmac-sha256': {
    id: 'hmac-sha256',
    label: 'HMAC-SHA256',
    primitives: ['mac'],
    quantum: Q.SAFE,
    classical: C.STRONG,
  },
  poly1305: {
    id: 'poly1305',
    label: 'Poly1305',
    primitives: ['mac'],
    quantum: Q.SAFE,
    classical: C.STRONG,
  },
  cmac: {
    id: 'cmac',
    label: 'AES-CMAC',
    primitives: ['mac'],
    quantum: Q.SAFE,
    classical: C.STRONG,
  },

  // --------------------------------------------------------------- kdf ---
  pbkdf2: {
    id: 'pbkdf2',
    label: 'PBKDF2',
    primitives: ['kdf'],
    quantum: Q.SAFE,
    classical: C.ACCEPTABLE,
    note: 'Weak if the iteration count is low. Prefer Argon2id for passwords.',
  },
  bcrypt: {
    id: 'bcrypt',
    label: 'bcrypt',
    primitives: ['kdf'],
    quantum: Q.SAFE,
    classical: C.STRONG,
    note: 'Truncates passwords at 72 bytes.',
  },
  scrypt: {
    id: 'scrypt',
    label: 'scrypt',
    primitives: ['kdf'],
    quantum: Q.SAFE,
    classical: C.STRONG,
  },
  argon2: {
    id: 'argon2',
    label: 'Argon2id',
    primitives: ['kdf'],
    quantum: Q.SAFE,
    classical: C.STRONG,
    note: 'RFC 9106. The recommended password hash.',
  },

  // ---------------------------------------------------------- protocol ---
  'tls-1.0': {
    id: 'tls-1.0',
    label: 'TLS 1.0',
    primitives: ['protocol'],
    quantum: Q.WEAKENED,
    classical: C.BROKEN,
    replacement: 'tls-1.3',
    deprecated: true,
    note: 'RFC 8996 deprecates TLS 1.0 and 1.1. BEAST, POODLE-adjacent issues.',
  },
  'tls-1.1': {
    id: 'tls-1.1',
    label: 'TLS 1.1',
    primitives: ['protocol'],
    quantum: Q.WEAKENED,
    classical: C.BROKEN,
    replacement: 'tls-1.3',
    deprecated: true,
    note: 'RFC 8996 deprecates TLS 1.1.',
  },
  'tls-1.2': {
    id: 'tls-1.2',
    label: 'TLS 1.2',
    primitives: ['protocol'],
    quantum: Q.WEAKENED,
    classical: C.ACCEPTABLE,
    replacement: 'tls-1.3',
    note: 'Acceptable if the cipher suite is AEAD and the key exchange is hybrid.',
  },
  'tls-1.3': {
    id: 'tls-1.3',
    label: 'TLS 1.3',
    primitives: ['protocol'],
    quantum: Q.WEAKENED,
    classical: C.STRONG,
    note: 'The protocol is sound; the quantum risk lives in the key exchange group and certificate signature.',
  },
  'ssh-rsa': {
    id: 'ssh-rsa',
    label: 'ssh-rsa (RSA/SHA-1)',
    primitives: ['signature'],
    quantum: Q.BROKEN,
    classical: C.BROKEN,
    replacement: 'ml-dsa-65',
    deprecated: true,
    note: 'Disabled by default in OpenSSH 8.8+. SHA-1 signature.',
  },
  'ssh-dss': {
    id: 'ssh-dss',
    label: 'ssh-dss (DSA)',
    primitives: ['signature'],
    quantum: Q.BROKEN,
    classical: C.BROKEN,
    replacement: 'ml-dsa-65',
    deprecated: true,
  },
  'rsa-sha2-256': {
    id: 'rsa-sha2-256',
    label: 'rsa-sha2-256',
    primitives: ['signature'],
    quantum: Q.BROKEN,
    classical: C.STRONG,
    replacement: 'ml-dsa-65',
    standard: 'FIPS 204',
  },
  'rsa-sha2-512': {
    id: 'rsa-sha2-512',
    label: 'rsa-sha2-512',
    primitives: ['signature'],
    quantum: Q.BROKEN,
    classical: C.STRONG,
    replacement: 'ml-dsa-65',
    standard: 'FIPS 204',
  },
  'ecdsa-sha2-nistp256': {
    id: 'ecdsa-sha2-nistp256',
    label: 'ecdsa-sha2-nistp256',
    primitives: ['signature'],
    quantum: Q.BROKEN,
    classical: C.STRONG,
    replacement: 'ml-dsa-65',
    standard: 'FIPS 204',
  },
  'ssh-ed25519': {
    id: 'ssh-ed25519',
    label: 'ssh-ed25519',
    primitives: ['signature'],
    quantum: Q.BROKEN,
    classical: C.STRONG,
    replacement: 'ml-dsa-65',
    standard: 'FIPS 204',
  },
  'sntrup761x25519-sha512': {
    id: 'sntrup761x25519-sha512',
    label: 'sntrup761x25519-sha512',
    primitives: ['key-agreement'],
    quantum: Q.SAFE,
    classical: C.STRONG,
    note: 'OpenSSH hybrid KEX, enabled by default since 9.0.',
  },
  'mlkem768x25519-sha256': {
    id: 'mlkem768x25519-sha256',
    label: 'mlkem768x25519-sha256',
    primitives: ['key-agreement'],
    quantum: Q.SAFE,
    classical: C.STRONG,
    standard: 'OpenSSH 9.9+',
  },

  // ------------------------------------------------------------- misc ---
  'none': {
    id: 'none',
    label: 'No encryption',
    primitives: ['symmetric'],
    quantum: Q.BROKEN,
    classical: C.BROKEN,
    replacement: 'aes-256-gcm',
  },
  unknown: {
    id: 'unknown',
    label: 'Unknown algorithm',
    primitives: ['unknown'],
    quantum: Q.UNKNOWN,
    classical: C.ACCEPTABLE,
  },
};

/**
 * Normalise an algorithm name for lookup: lowercase, collapse separators.
 * "AES-256-GCM" -> "aes-256-gcm", "ECDSA_SHA256" -> "ecdsa_sha256".
 */
export function normaliseName(name) {
  return String(name)
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/_/g, '-');
}

/**
 * Aliases map vendor/API spellings onto registry ids.
 * Keys are already normalised.
 */
const ALIASES = {
  // RSA
  'rsa-sha256': 'rsa',
  'rsa-sha1': 'rsa',
  'rsa-sha512': 'rsa',
  'rsassa-pss': 'rsa',
  'rsa-pss': 'rsa',
  'rsaes-oaep': 'rsa',
  'rsaes-pkcs1-v1-5': 'rsa',
  'sha256withrsa': 'rsa',
  'sha1withrsa': 'rsa',
  'sha384withrsa': 'rsa',
  'sha512withrsa': 'rsa',
  'sha256withrsaencryption': 'rsa',
  'sha1withrsaencryption': 'rsa',
  'rs256': 'rsa',
  'rs384': 'rsa',
  'rs512': 'rsa',
  'ps256': 'rsa',
  'ps384': 'rsa',
  'ps512': 'rsa',
  'ssh-rsa-cert-v01': 'ssh-rsa',
  // EC
  'prime256v1': 'ecdh',
  'secp256r1': 'ecdh',
  'p-256': 'ecdh',
  'p-384': 'ecdh',
  'p-521': 'ecdh',
  'secp384r1': 'ecdh',
  'secp521r1': 'ecdh',
  'brainpoolp256r1': 'ecdh',
  'secp256r1-sha256': 'ecdsa',
  'ecdsa-with-sha256': 'ecdsa',
  'ecdsa-sha2-nistp384': 'ecdsa',
  'ecdsa-sha2-nistp521': 'ecdsa',
  'es256': 'ecdsa',
  'es384': 'ecdsa',
  'es512': 'ecdsa',
  'eddsa': 'ed25519',
  'ed25519ph': 'ed25519',
  // symmetric
  'aes': 'aes-128',
  'aes128': 'aes-128',
  'aes192': 'aes-192',
  'aes256': 'aes-256',
  'aes-128-cbc-hmac-sha256': 'aes-128-cbc',
  'aes-256-cbc-hmac-sha256': 'aes-256-cbc',
  'aes-256-ctr': 'aes-256',
  'aes-128-ctr': 'aes-128',
  'aes-128-gcm-siv': 'aes-128-gcm',
  'aes-256-gcm-siv': 'aes-256-gcm',
  'aes-gcm': 'aes-128-gcm',
  'tripledes': '3des',
  'des-ede3': '3des',
  'des-ede3-cbc': '3des',
  'des3': '3des',
  'chacha20poly1305': 'chacha20-poly1305',
  'xchacha20-poly1305': 'chacha20-poly1305',
  'aes-256-ccm': 'aes-256-gcm',
  // hashes
  'sha': 'sha1',
  'sha-1': 'sha1',
  'sha-224': 'sha224',
  'sha-256': 'sha256',
  'sha-384': 'sha384',
  'sha-512': 'sha512',
  'sha2-256': 'sha256',
  'sha2-512': 'sha512',
  'sha-3-256': 'sha3-256',
  'sha-3-512': 'sha3-512',
  'keccak-256': 'sha3-256',
  'sha512-256': 'sha512',
  'sha512-224': 'sha512',
  'ripemd-160': 'ripemd160',
  // mac
  'hmac-sha-256': 'hmac-sha256',
  'hmac-sha-1': 'hmac-sha1',
  'hs256': 'hmac-sha256',
  'hs384': 'hmac-sha256',
  'hs512': 'hmac-sha256',
  'aes-cmac': 'cmac',
  // kdf
  'argon2id': 'argon2',
  'argon2i': 'argon2',
  'argon2d': 'argon2',
  // curve / cipher spellings
  ec: 'ecdh',
  ecc: 'ecdsa',
  arc4: 'rc4',
  camellia: 'camellia-256',
  'shake-128': 'shake128',
  'shake-256': 'shake256',
  idea: 'idea',
  // protocol
  'tlsv1': 'tls-1.0',
  'tlsv1.0': 'tls-1.0',
  'tls1': 'tls-1.0',
  'tls10': 'tls-1.0',
  'tlsv1.1': 'tls-1.1',
  'tls11': 'tls-1.1',
  'tlsv1.2': 'tls-1.2',
  'tls12': 'tls-1.2',
  'tlsv1.3': 'tls-1.3',
  'tls13': 'tls-1.3',
  'ssl3': 'tls-1.0',
  'sslv3': 'tls-1.0',
  // pqc
  'mlkem768': 'ml-kem-768',
  'mlkem512': 'ml-kem-512',
  'mlkem1024': 'ml-kem-1024',
  'kyber768': 'ml-kem-768',
  'kyber512': 'ml-kem-512',
  'kyber1024': 'ml-kem-1024',
  'mldsa44': 'ml-dsa-44',
  'mldsa65': 'ml-dsa-65',
  'mldsa87': 'ml-dsa-87',
  'dilithium3': 'ml-dsa-65',
  'dilithium2': 'ml-dsa-44',
  'dilithium5': 'ml-dsa-87',
  'sphincs': 'slh-dsa-128s',
  'sphincs-sha2-128s': 'slh-dsa-128s',
  'x25519-mlkem768': 'x25519mlkem768',
  'x25519kyber768': 'x25519kyber768draft00',
  'x25519-kyber768draft00': 'x25519kyber768draft00',
};

/**
 * Normalise any TLS version token from any language or config dialect into a
 * registry id. Handles `TLSv1`, `TLSv1.1`, `TLS1_2_VERSION`, `VersionTLS10`,
 * `PROTOCOL_TLSv1_1`, `SSLv3` and friends.
 * @param {string} raw
 * @returns {'tls-1.0'|'tls-1.1'|'tls-1.2'|'tls-1.3'}
 */
export function tlsVersionId(raw) {
  const s = String(raw).toUpperCase();
  if (/1[._]?3/.test(s)) return 'tls-1.3';
  if (/1[._]?2/.test(s)) return 'tls-1.2';
  if (/1[._]?1/.test(s)) return 'tls-1.1';
  return 'tls-1.0';
}

/**
 * Look up an algorithm by name. Returns the `unknown` entry rather than null
 * so callers never have to null-check.
 * @param {string} name
 */
export function lookup(name) {
  if (!name) return ALGORITHMS.unknown;
  const n = normaliseName(name);
  if (ALGORITHMS[n]) return ALGORITHMS[n];
  if (ALIASES[n]) return ALGORITHMS[ALIASES[n]];
  // Try progressively trimming suffixes like "-cbc", "-gcm", "-hmac".
  const parts = n.split('-');
  for (let i = parts.length - 1; i > 0; i--) {
    const candidate = parts.slice(0, i).join('-');
    if (ALGORITHMS[candidate]) return ALGORITHMS[candidate];
    if (ALIASES[candidate]) return ALGORITHMS[ALIASES[candidate]];
  }
  return ALGORITHMS.unknown;
}

/**
 * Resolve an RSA/DSA key size to the most specific registry id.
 */
export function rsaVariant(bits) {
  if (!bits) return ALGORITHMS.rsa;
  if (bits <= 512) return ALGORITHMS['rsa-512'];
  if (bits <= 1024) return ALGORITHMS['rsa-1024'];
  if (bits <= 2048) return ALGORITHMS['rsa-2048'];
  if (bits <= 3072) return ALGORITHMS['rsa-3072'];
  return ALGORITHMS['rsa-4096'];
}

/** True when the algorithm has any quantum weakness at all. */
export function isQuantumWeak(algo) {
  return algo.quantum === Q.BROKEN || algo.quantum === Q.WEAKENED;
}

/**
 * Recommend a replacement that matches how the primitive is being used.
 * RSA is one registry entry but two different migrations: a KEM (ML-KEM-768)
 * when it protects confidentiality, and a signature scheme (ML-DSA-65) when
 * it authenticates. Getting this wrong sends engineers to the wrong FIPS.
 *
 * @param {object} algo registry entry
 * @param {string} primitive the usage primitive
 * @returns {string|null} registry id of the replacement
 */
export function replacementFor(algo, primitive) {
  if (!algo || algo.id === 'unknown') return null;

  if (primitive === 'signature') {
    if (algo.id === 'ed448') return 'ml-dsa-87';
    if (algo.id === 'rsa' || algo.id.startsWith('rsa-') || algo.id === 'ecdsa' || algo.id === 'ed25519' || algo.id === 'dsa' || algo.id === 'secp256k1' || algo.id === 'ssh-rsa') {
      return 'ml-dsa-65';
    }
    if (algo.id.startsWith('slh-dsa') || algo.id.startsWith('ml-dsa')) return algo.id;
  }

  if (primitive === 'key-agreement' || primitive === 'pke') {
    if (algo.id === 'ecdh' || algo.id === 'x25519' || algo.id === 'x448' || algo.id === 'dh' || algo.id === 'ecies') {
      return 'x25519mlkem768';
    }
    if (algo.id === 'rsa' || algo.id.startsWith('rsa-')) return 'ml-kem-768';
    if (algo.id.startsWith('ml-kem') || algo.id.startsWith('x25519mlkem')) return algo.id;
  }

  return algo.replacement || null;
}

/** True when the algorithm is outright broken by Shor/Grover. */
export function isQuantumBroken(algo) {
  return algo.quantum === Q.BROKEN;
}

export { Q as QUANTUM, C as CLASSICAL };
