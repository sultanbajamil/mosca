/**
 * MOSCA — source code rules
 * =========================
 *
 * Language-aware patterns that recognise *cryptographic API usage*, not
 * bare words. A rule fires on a construct that actually invokes or declares
 * a primitive: `crypto.createHash('md5')`, `KeyPairGenerator.getInstance("RSA")`,
 * `rsa.GenerateKey(...)`.
 *
 * Design notes
 * ------------
 * - Rules are deliberately conservative. A false positive in a security
 *   report destroys trust faster than a missed low-severity item.
 * - Every rule names the primitive it concerns so the risk engine can weigh
 *   confidentiality (KEM/cipher) differently from integrity (hash/signature).
 * - `confidence` is reported to the user: `high` means the call is
 *   unambiguous, `medium` means the argument needs human confirmation.
 */

/** @typedef {'high'|'medium'|'low'} Confidence */

/**
 * @typedef {Object} Rule
 * @property {string} id
 * @property {RegExp} re            Global regex, applied per line.
 * @property {string|Function} algo  Registry id, or (match) => id
 * @property {string} primitive
 * @property {Confidence} confidence
 * @property {string} [note]
 * @property {Function} [bits]      (match) => number|undefined
 */

const dyn = (fn) => fn;

import { tlsVersionId } from './algorithms.js';

/** Map a raw hash/cipher token to a registry id, tolerating case. */
const norm = (s) => String(s).toLowerCase().replace(/[_]/g, '-');

/** Language buckets keyed by file extension. */
export const LANGUAGE_BY_EXT = {
  '.js': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.jsx': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.py': 'python',
  '.java': 'java',
  '.kt': 'kotlin',
  '.kts': 'kotlin',
  '.go': 'go',
  '.c': 'c',
  '.h': 'c',
  '.cc': 'cpp',
  '.cpp': 'cpp',
  '.cxx': 'cpp',
  '.hpp': 'cpp',
  '.cs': 'csharp',
  '.rs': 'rust',
  '.php': 'php',
  '.rb': 'ruby',
  '.sh': 'shell',
  '.bash': 'shell',
  '.zsh': 'shell',
  '.ps1': 'powershell',
  '.swift': 'swift',
  '.scala': 'scala',
};

/** Human labels used in the report. */
export const LANGUAGE_LABELS = {
  javascript: 'JavaScript',
  typescript: 'TypeScript',
  python: 'Python',
  java: 'Java',
  kotlin: 'Kotlin',
  go: 'Go',
  c: 'C',
  cpp: 'C++',
  csharp: 'C#',
  rust: 'Rust',
  php: 'PHP',
  ruby: 'Ruby',
  shell: 'Shell',
  powershell: 'PowerShell',
  swift: 'Swift',
  scala: 'Scala',
};

// ---------------------------------------------------------------------------
// JavaScript / TypeScript
// ---------------------------------------------------------------------------

/** @type {Rule[]} */
const javascript = [
  {
    id: 'js-createHash',
    re: /createHash\(\s*['"`]([a-z0-9-]+)['"`]/gi,
    algo: (m) => norm(m[1]),
    primitive: 'hash',
    confidence: 'high',
  },
  {
    id: 'js-createHmac',
    re: /createHmac\(\s*['"`]([a-z0-9-]+)['"`]/gi,
    algo: (m) => `hmac-${norm(m[1])}`,
    primitive: 'mac',
    confidence: 'high',
  },
  {
    id: 'js-createCipher',
    re: /create(?:Cipher|Decipher)(?:iv)?\(\s*['"`]([a-z0-9-]+)['"`]/gi,
    algo: (m) => norm(m[1]),
    primitive: 'symmetric',
    confidence: 'high',
  },
  {
    id: 'js-createSign',
    re: /create(?:Sign|Verify)\(\s*['"`]([a-z0-9-]+)['"`]/gi,
    algo: (m) => norm(m[1]),
    primitive: 'signature',
    confidence: 'high',
  },
  {
    id: 'js-generateKeyPair',
    re: /generateKeyPair(?:Sync)?\(\s*['"`](rsa|ec|dsa|ed25519|ed448|x25519|x448|dh)['"`]/gi,
    algo: (m) => norm(m[1]),
    primitive: 'signature',
    confidence: 'high',
  },
  {
    id: 'js-rsa-modulus',
    re: /modulusLength\s*:\s*(\d{3,5})/g,
    algo: (m) => `rsa-${m[1]}`,
    primitive: 'pke',
    confidence: 'medium',
    bits: (m) => Number(m[1]),
    note: 'RSA modulus length declared in a key-generation options object.',
  },
  {
    id: 'js-webcrypto-generateKey',
    re: /subtle\.generateKey\(\s*\{[^}]*?name\s*:\s*['"`](RSA-PSS|RSA-OAEP|ECDSA|ECDH|Ed25519|X25519|AES-GCM|AES-CBC|AES-CTR|HMAC)['"`]/gi,
    algo: (m) => {
      const n = norm(m[1]);
      if (n.startsWith('rsa')) return 'rsa';
      if (n === 'ecdsa' || n === 'ecdh') return 'ecdsa';
      if (n === 'ed25519') return 'ed25519';
      if (n === 'x25519') return 'x25519';
      if (n === 'hmac') return 'hmac-sha256';
      return n; // aes-gcm / aes-cbc / aes-ctr
    },
    primitive: 'signature',
    confidence: 'high',
  },
  {
    id: 'js-webcrypto-digest',
    re: /subtle\.digest\(\s*['"`](SHA-1|SHA-256|SHA-384|SHA-512|MD5)['"`]/gi,
    algo: (m) => norm(m[1]),
    primitive: 'hash',
    confidence: 'high',
  },
  {
    id: 'js-jwt-algorithm',
    re: /algorithm[s]?\s*:\s*\[?\s*['"`](RS256|RS384|RS512|PS256|ES256|ES384|ES512|HS256|HS384|HS512|EdDSA|none)['"`]/gi,
    algo: (m) => {
      const a = m[1].toUpperCase();
      if (a.startsWith('RS') || a.startsWith('PS')) return 'rsa';
      if (a.startsWith('ES')) return 'ecdsa';
      if (a.startsWith('HS')) return 'hmac-sha256';
      if (a === 'EDDSA') return 'ed25519';
      return 'none';
    },
    primitive: 'signature',
    confidence: 'medium',
    note: 'JWT signing algorithm.',
  },
  {
    id: 'js-node-rsa',
    re: /new\s+NodeRSA\s*\(|require\(\s*['"]node-rsa['"]\s*\)|from\s+['"]node-rsa['"]/g,
    algo: 'rsa',
    primitive: 'pke',
    confidence: 'high',
  },
  {
    id: 'js-node-forge-rsa',
    re: /pki\.(?:rsa|ed25519)\.(?:generateKeyPair|privateKeyFromPem|publicKeyFromPem)/g,
    algo: (m) => (m[0].includes('ed25519') ? 'ed25519' : 'rsa'),
    primitive: 'pke',
    confidence: 'high',
  },
  {
    id: 'js-createDiffieHellman',
    re: /createDiffieHellman\(\s*(\d{3,4})?/g,
    algo: 'dh',
    primitive: 'key-agreement',
    confidence: 'high',
    bits: (m) => (m[1] ? Number(m[1]) : undefined),
  },
  {
    id: 'js-tls-minversion',
    re: /minVersion\s*:\s*['"`](TLSv1|TLSv1\.1)['"`]/g,
    algo: (m) => tlsVersionId(m[1]),
    primitive: 'protocol',
    confidence: 'high',
    note: 'A TLS 1.0/1.1 floor. Raise it to TLS 1.2 and let the server prefer 1.3.',
  },
  {
    id: 'js-tls-maxversion',
    re: /maxVersion\s*:\s*['"`](TLSv1(?:\.1)?|TLSv1\.2)['"`]/g,
    algo: (m) => tlsVersionId(m[1]),
    primitive: 'protocol',
    confidence: 'high',
    note: 'Capping the maximum version prevents TLS 1.3 and therefore hybrid key exchange.',
  },
  {
    id: 'js-ecb-mode',
    re: /create(?:Cipher|Decipher)(?:iv)?\(\s*['"`]([a-z0-9-]*-ecb)['"`]/gi,
    algo: (m) => norm(m[1]),
    primitive: 'symmetric',
    confidence: 'high',
    note: 'ECB mode leaks plaintext structure.',
  },
  {
    id: 'js-scrypt',
    re: /(?:scrypt|pbkdf2)(?:Sync)?\s*\(/g,
    algo: 'pbkdf2',
    primitive: 'kdf',
    confidence: 'medium',
  },
];

const typescript = javascript;

// ---------------------------------------------------------------------------
// Python
// ---------------------------------------------------------------------------

/** @type {Rule[]} */
const python = [
  {
    id: 'py-hashlib',
    re: /hashlib\.(md5|sha1|sha224|sha256|sha384|sha512|sha3_256|sha3_512|blake2b|shake_128)\s*\(/gi,
    algo: (m) => norm(m[1]),
    primitive: 'hash',
    confidence: 'high',
  },
  {
    id: 'py-crypto-hash',
    re: /(?:Crypto|Cryptodome)\.Hash\.(MD5|SHA1|SHA224|SHA256|SHA384|SHA512)\.new/gi,
    algo: (m) => norm(m[1]),
    primitive: 'hash',
    confidence: 'high',
  },
  {
    id: 'py-hazmat-hashes',
    re: /hashes\.(MD5|SHA1|SHA224|SHA256|SHA384|SHA512)\(\)/gi,
    algo: (m) => norm(m[1]),
    primitive: 'hash',
    confidence: 'high',
  },
  {
    id: 'py-crypto-pubkey',
    re: /(?:Crypto|Cryptodome)\.PublicKey\.(RSA|DSA|ECC)\.(?:generate|importKey)/gi,
    algo: (m) => norm(m[1]),
    primitive: 'pke',
    confidence: 'high',
  },
  {
    id: 'py-crypto-cipher',
    re: /(?:Crypto|Cryptodome)\.Cipher\.(AES|DES|DES3|ARC4|Blowfish)\.new/gi,
    algo: (m) => norm(m[1]),
    primitive: 'symmetric',
    confidence: 'high',
  },
  {
    id: 'py-hazmat-import',
    re: /from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+(rsa|ec|dsa|ed25519|x25519|ed448|x448|dh)/gi,
    algo: (m) => norm(m[1]),
    primitive: 'signature',
    confidence: 'high',
  },
  {
    id: 'py-rsa-generate',
    re: /rsa\.generate_private_key\s*\([^)]*?key_size\s*=\s*(\d{3,5})/gis,
    algo: (m) => `rsa-${m[1]}`,
    primitive: 'pke',
    confidence: 'high',
    bits: (m) => Number(m[1]),
  },
  {
    id: 'py-ec-curve',
    re: /ec\.generate_private_key\s*\(\s*ec\.(SECP256R1|SECP384R1|SECP521R1|SECP256K1|BRAINPOOLP256R1)/gi,
    algo: (m) => (m[1].includes('K1') ? 'secp256k1' : 'ecdh'),
    primitive: 'key-agreement',
    confidence: 'high',
  },
  {
    id: 'py-hazmat-algorithms',
    re: /algorithms\.(AES|TripleDES|Blowfish|ARC4|ChaCha20|Camellia)\s*\(/gi,
    algo: (m) => {
      const n = norm(m[1]);
      if (n === 'tripledes') return '3des';
      return n;
    },
    primitive: 'symmetric',
    confidence: 'high',
  },
  {
    id: 'py-fernet',
    re: /\bFernet\s*\(/g,
    algo: 'fernet',
    primitive: 'symmetric',
    confidence: 'high',
  },
  {
    id: 'py-ssl-protocol',
    re: /ssl\.PROTOCOL_(TLSv1(?:_1)?|TLS|SSLv3)/g,
    algo: (m) => tlsVersionId(m[1]),
    primitive: 'protocol',
    confidence: 'high',
  },
  {
    id: 'py-jwt',
    re: /jwt\.(?:encode|decode)\s*\([^)]*?algorithm[s]?\s*=\s*\[?\s*['"](RS256|RS512|ES256|HS256|none)['"]/gis,
    algo: (m) => {
      const a = m[1].toUpperCase();
      if (a.startsWith('RS')) return 'rsa';
      if (a.startsWith('ES')) return 'ecdsa';
      if (a.startsWith('HS')) return 'hmac-sha256';
      return 'none';
    },
    primitive: 'signature',
    confidence: 'high',
  },
  {
    id: 'py-ecb',
    re: /modes\.ECB\s*\(/g,
    algo: 'aes-128-cbc',
    primitive: 'symmetric',
    confidence: 'medium',
    note: 'ECB mode leaks plaintext structure.',
  },
  {
    id: 'py-paramiko',
    re: /paramiko\.(RSAKey|DSSKey|ECDSAKey)/g,
    algo: (m) => (m[1] === 'DSSKey' ? 'dsa' : m[1] === 'ECDSAKey' ? 'ecdsa' : 'rsa'),
    primitive: 'signature',
    confidence: 'high',
  },
  {
    id: 'py-hazmat-padding-ecb',
    re: /padding\.ECB/gi,
    algo: 'aes-128-cbc',
    primitive: 'symmetric',
    confidence: 'low',
  },
];

// ---------------------------------------------------------------------------
// Java / Kotlin
// ---------------------------------------------------------------------------

/** @type {Rule[]} */
const java = [
  {
    id: 'java-keypairgen',
    re: /KeyPairGenerator\.getInstance\(\s*"([A-Za-z0-9]+)"\s*(?:,\s*"([^"]+)")?/g,
    algo: (m) => {
      const n = m[1].toUpperCase();
      if (n === 'RSA') return 'rsa';
      if (n === 'EC') return 'ecdh';
      if (n === 'DSA') return 'dsa';
      if (n === 'ED25519' || n === 'EDDSA') return 'ed25519';
      if (n === 'X25519' || n === 'XDH') return 'x25519';
      if (n.startsWith('ML-DSA')) return 'ml-dsa-65';
      return 'unknown';
    },
    primitive: 'signature',
    confidence: 'high',
  },
  {
    id: 'java-keygen',
    re: /KeyGenerator\.getInstance\(\s*"([A-Za-z0-9]+)"/g,
    algo: (m) => norm(m[1]),
    primitive: 'symmetric',
    confidence: 'high',
  },
  {
    id: 'java-cipher',
    re: /Cipher\.getInstance\(\s*"([A-Za-z0-9/-]+)"/g,
    algo: (m) => norm(m[1].split('/')[0]),
    primitive: 'symmetric',
    confidence: 'high',
  },
  {
    id: 'java-messagedigest',
    re: /MessageDigest\.getInstance\(\s*"(MD5|SHA-1|SHA-224|SHA-256|SHA-384|SHA-512|SHA3-256)"\s*\)/g,
    algo: (m) => norm(m[1]),
    primitive: 'hash',
    confidence: 'high',
  },
  {
    id: 'java-signature',
    re: /Signature\.getInstance\(\s*"([A-Za-z0-9-]+)"/g,
    algo: (m) => {
      const n = m[1].toUpperCase();
      if (n.includes('ECDSA')) return 'ecdsa';
      if (n.includes('ED25519') || n.includes('EDDSA')) return 'ed25519';
      if (n.includes('ML-DSA')) return 'ml-dsa-65';
      if (n.includes('RSA')) return 'rsa';
      if (n.includes('DSA')) return 'dsa';
      return 'unknown';
    },
    primitive: 'signature',
    confidence: 'high',
  },
  {
    id: 'java-sslcontext',
    re: /SSLContext\.getInstance\(\s*"(TLSv1(?:\.1)?|TLSv1\.2|TLSv1\.3|SSLv3)"\s*\)/g,
    algo: (m) => tlsVersionId(m[1]),
    primitive: 'protocol',
    confidence: 'high',
  },
  {
    id: 'java-mac',
    re: /Mac\.getInstance\(\s*"(HmacMD5|HmacSHA1|HmacSHA256|HmacSHA512)"\s*\)/g,
    algo: (m) => `hmac-${norm(m[1].replace('Hmac', ''))}`,
    primitive: 'mac',
    confidence: 'high',
  },
  {
    id: 'java-rsa-keysize',
    re: /(?:initialize|keySize)\s*\(\s*(\d{3,5})\s*\)/g,
    algo: (m) => `rsa-${m[1]}`,
    primitive: 'pke',
    confidence: 'low',
    bits: (m) => Number(m[1]),
    note: 'Integer key size; confirm it belongs to an RSA KeyPairGenerator.',
  },
  {
    id: 'java-ecb',
    re: /Cipher\.getInstance\(\s*"[A-Za-z0-9]+\/ECB\//g,
    algo: 'aes-128-cbc',
    primitive: 'symmetric',
    confidence: 'high',
    note: 'ECB mode leaks plaintext structure.',
  },
  {
    id: 'java-jwt',
    re: /(?:SignatureAlgorithm|Jwts\.SIG)\.(HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS512)/g,
    algo: (m) => {
      const a = m[1].toUpperCase();
      if (a.startsWith('RS') || a.startsWith('PS')) return 'rsa';
      if (a.startsWith('ES')) return 'ecdsa';
      return 'hmac-sha256';
    },
    primitive: 'signature',
    confidence: 'high',
  },
  {
    id: 'java-bouncy-rsa',
    re: /new\s+(?:RSAKeyPairGenerator|JceOpenSSLPKCS8EncryptorBuilder)\s*\(/g,
    algo: 'rsa',
    primitive: 'pke',
    confidence: 'medium',
  },
];

const kotlin = java;

// ---------------------------------------------------------------------------
// Go
// ---------------------------------------------------------------------------

/** @type {Rule[]} */
const go = [
  {
    id: 'go-rsa-generate',
    re: /rsa\.Generate(?:MultiPrime)?Key\s*\(/g,
    algo: 'rsa',
    primitive: 'pke',
    confidence: 'high',
  },
  {
    id: 'go-ecdsa-generate',
    re: /ecdsa\.GenerateKey\s*\(/g,
    algo: 'ecdsa',
    primitive: 'signature',
    confidence: 'high',
  },
  {
    id: 'go-ed25519',
    re: /ed25519\.(?:GenerateKey|NewKeyFromSeed)\s*\(/g,
    algo: 'ed25519',
    primitive: 'signature',
    confidence: 'high',
  },
  {
    id: 'go-ecdh',
    re: /ecdh\.(X25519|P256|P384|P521)\s*\(/g,
    algo: (m) => (m[1] === 'X25519' ? 'x25519' : 'ecdh'),
    primitive: 'key-agreement',
    confidence: 'high',
  },
  {
    id: 'go-hash',
    re: /\b(md5|sha1|sha256|sha512)\.New\s*\(/g,
    algo: (m) => norm(m[1]),
    primitive: 'hash',
    confidence: 'high',
  },
  {
    id: 'go-des',
    re: /\b(des|rc4|blowfish)\.New(?:Cipher|TripleDESCipher)?\s*\(/g,
    algo: (m) => norm(m[1]),
    primitive: 'symmetric',
    confidence: 'high',
  },
  {
    id: 'go-tls-minversion',
    re: /MinVersion\s*:\s*tls\.(VersionTLS1[01]|VersionSSL30)/g,
    algo: (m) => tlsVersionId(m[1]),
    primitive: 'protocol',
    confidence: 'high',
    note: 'TLS 1.0/1.1 floor.',
  },
  {
    id: 'go-tls-maxversion',
    re: /MaxVersion\s*:\s*tls\.(VersionTLS1[0-2]|VersionSSL30)/g,
    algo: (m) => tlsVersionId(m[1]),
    primitive: 'protocol',
    confidence: 'high',
    note: 'Capping the maximum version prevents TLS 1.3 and therefore hybrid post-quantum key exchange.',
  },
  {
    id: 'go-cipher-suites',
    re: /tls\.(TLS_RSA_WITH_[A-Z0-9_]+|TLS_ECDHE_RSA_WITH_RC4_128_SHA|TLS_RSA_WITH_3DES_EDE_CBC_SHA)/g,
    algo: 'tls-1.2',
    primitive: 'protocol',
    confidence: 'medium',
    note: 'Static-RSA or legacy cipher suite.',
  },
  {
    id: 'go-jwt',
    re: /jwt\.(?:NewWithClaims|ParseWithClaims)?\([^)]*?(?:jwt\.)?(?:SigningMethodRS256|SigningMethodHS256|SigningMethodES256|SigningMethodEdDSA)/g,
    algo: (m) => {
      const s = m[0];
      if (s.includes('RS256')) return 'rsa';
      if (s.includes('ES256')) return 'ecdsa';
      if (s.includes('EdDSA')) return 'ed25519';
      return 'hmac-sha256';
    },
    primitive: 'signature',
    confidence: 'high',
  },
];

// ---------------------------------------------------------------------------
// C / C++
// ---------------------------------------------------------------------------

/** @type {Rule[]} */
const c = [
  {
    id: 'c-evp-digest',
    re: /EVP_(md5|sha1|sha256|sha512)\s*\(\s*\)/g,
    algo: (m) => norm(m[1]),
    primitive: 'hash',
    confidence: 'high',
  },
  {
    id: 'c-legacy-digest',
    re: /\b(MD5|SHA1)_(?:Init|Update|Final)\s*\(/g,
    algo: (m) => norm(m[1]),
    primitive: 'hash',
    confidence: 'high',
  },
  {
    id: 'c-rsa-generate',
    re: /RSA_generate_key(?:_ex)?\s*\(/g,
    algo: 'rsa',
    primitive: 'pke',
    confidence: 'high',
  },
  {
    id: 'c-ec-key',
    re: /EC_KEY_new_by_curve_name\s*\(\s*(NID_[A-Za-z0-9_]+)/g,
    algo: (m) => (m[1].includes('secp256k1') ? 'secp256k1' : 'ecdh'),
    primitive: 'key-agreement',
    confidence: 'high',
  },
  {
    id: 'c-evp-pkey-rsa',
    re: /EVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_(RSA|EC|DH|DSA|ED25519|X25519)/g,
    algo: (m) => {
      const n = m[1].toUpperCase();
      if (n === 'EC') return 'ecdh';
      if (n === 'ED25519') return 'ed25519';
      if (n === 'X25519') return 'x25519';
      return norm(n);
    },
    primitive: 'pke',
    confidence: 'high',
  },
  {
    id: 'c-legacy-cipher',
    re: /\b(DES|RC4|BF|CAST|IDEA)_(?:set_key|encrypt|ecb_encrypt|cbc_encrypt)/g,
    algo: (m) => norm(m[1]),
    primitive: 'symmetric',
    confidence: 'high',
  },
  {
    id: 'c-tls-minversion',
    re: /SSL_CTX_set_min_proto_version\s*\([^,]+,\s*(TLS1_VERSION|TLS1_1_VERSION)/g,
    algo: (m) => tlsVersionId(m[1]),
    primitive: 'protocol',
    confidence: 'high',
    note: 'Minimum protocol version allows TLS 1.0/1.1.',
  },
  {
    id: 'c-tls-maxversion',
    re: /SSL_CTX_set_max_proto_version\s*\([^,]+,\s*(TLS1_VERSION|TLS1_1_VERSION|TLS1_2_VERSION)/g,
    algo: (m) => tlsVersionId(m[1]),
    primitive: 'protocol',
    confidence: 'high',
    note: 'Maximum protocol version prevents TLS 1.3 and hybrid key exchange.',
  },
  {
    id: 'c-cipher-list',
    re: /SSL_CTX_set_cipher_list\s*\(\s*[^,]+,\s*"([^"]+)"/g,
    algo: 'tls-1.2',
    primitive: 'protocol',
    confidence: 'medium',
    note: 'Explicit cipher list; review for RC4/3DES/EXPORT/NULL.',
  },
  {
    id: 'c-openssl-api',
    re: /\b(OPENSSL_init_crypto|EVP_CIPHER_CTX_new)\s*\(/g,
    algo: 'aes-256',
    primitive: 'symmetric',
    confidence: 'low',
    note: 'OpenSSL context; inspect the selected cipher.',
  },
];

const cpp = c;

// ---------------------------------------------------------------------------
// C#
// ---------------------------------------------------------------------------

/** @type {Rule[]} */
const csharp = [
  {
    id: 'cs-rsa',
    re: /(?:new\s+RSACryptoServiceProvider|RSA\.Create\s*\(|new\s+RSACng)/g,
    algo: 'rsa',
    primitive: 'pke',
    confidence: 'high',
  },
  {
    id: 'cs-ecdsa',
    re: /(?:ECDsa\.Create\s*\(|new\s+ECDsaCng)/g,
    algo: 'ecdsa',
    primitive: 'signature',
    confidence: 'high',
  },
  {
    id: 'cs-ecdh',
    re: /(?:ECDiffieHellman\.Create\s*\(|new\s+ECDiffieHellmanCng)/g,
    algo: 'ecdh',
    primitive: 'key-agreement',
    confidence: 'high',
  },
  {
    id: 'cs-hash',
    re: /\b(MD5|SHA1|SHA256|SHA384|SHA512)\.(?:Create|HashData)\s*\(/g,
    algo: (m) => norm(m[1]),
    primitive: 'hash',
    confidence: 'high',
  },
  {
    id: 'cs-symmetric',
    re: /(?:Aes\.Create\s*\(|new\s+AesManaged|new\s+AesCryptoServiceProvider|TripleDES\.Create\s*\(|DES\.Create\s*\()/g,
    algo: (m) => (m[0].includes('TripleDES') ? '3des' : m[0].includes('DES') ? 'des' : 'aes-128'),
    primitive: 'symmetric',
    confidence: 'high',
  },
  {
    id: 'cs-hmac',
    re: /\b(HMACSHA1|HMACSHA256|HMACSHA512|HMACMD5)\s*\(/g,
    algo: (m) => `hmac-${norm(m[1].replace('HMAC', ''))}`,
    primitive: 'mac',
    confidence: 'high',
  },
  {
    id: 'cs-tls',
    re: /SslProtocols\.(Tls|Tls11|Tls12|Tls13|Ssl3)/g,
    algo: (m) => {
      const n = m[1];
      if (n === 'Tls') return 'tls-1.0';
      if (n === 'Tls11') return 'tls-1.1';
      if (n === 'Tls12') return 'tls-1.2';
      if (n === 'Tls13') return 'tls-1.3';
      return 'tls-1.0';
    },
    primitive: 'protocol',
    confidence: 'high',
  },
];

// ---------------------------------------------------------------------------
// Rust
// ---------------------------------------------------------------------------

/** @type {Rule[]} */
const rust = [
  {
    id: 'rs-rsa',
    re: /\brsa::(?:RsaPrivateKey|RsaPublicKey|Pkcs1v15)/g,
    algo: 'rsa',
    primitive: 'pke',
    confidence: 'high',
  },
  {
    id: 'rs-ring-rsa',
    re: /ring::signature::RSA_(?:PKCS1|PSS)_[0-9A-Z_]+/g,
    algo: 'rsa',
    primitive: 'signature',
    confidence: 'high',
  },
  {
    id: 'rs-p256',
    re: /\b(?:p256|p384|k256)::/g,
    algo: (m) => (m[0].startsWith('k256') ? 'secp256k1' : 'ecdsa'),
    primitive: 'signature',
    confidence: 'high',
  },
  {
    id: 'rs-ed25519',
    re: /\bed25519_dalek::|ring::signature::ED25519/g,
    algo: 'ed25519',
    primitive: 'signature',
    confidence: 'high',
  },
  {
    id: 'rs-x25519',
    re: /\bx25519_dalek::/g,
    algo: 'x25519',
    primitive: 'key-agreement',
    confidence: 'high',
  },
  {
    id: 'rs-hash',
    re: /\b(?:sha1|md5|sha2|sha3)::(?:Sha1|Md5|Sha256|Sha512)/g,
    algo: (m) => {
      const s = m[0];
      if (s.startsWith('sha1')) return 'sha1';
      if (s.startsWith('md5')) return 'md5';
      if (s.includes('Sha256')) return 'sha256';
      if (s.includes('Sha512')) return 'sha512';
      return 'sha256';
    },
    primitive: 'hash',
    confidence: 'high',
  },
  {
    id: 'rs-aes128',
    re: /\baes_gcm::Aes128Gcm\b|\baes::Aes128\b/g,
    algo: 'aes-128-gcm',
    primitive: 'symmetric',
    confidence: 'high',
  },
  {
    id: 'rs-aes256',
    re: /\baes_gcm::Aes256Gcm\b|\baes::Aes256\b/g,
    algo: 'aes-256-gcm',
    primitive: 'symmetric',
    confidence: 'high',
  },
];

// ---------------------------------------------------------------------------
// PHP
// ---------------------------------------------------------------------------

/** @type {Rule[]} */
const php = [
  {
    id: 'php-openssl-rsa',
    re: /openssl_(?:public_encrypt|private_decrypt|public_key|pkey_get_public)\s*\(/g,
    algo: 'rsa',
    primitive: 'pke',
    confidence: 'high',
  },
  {
    id: 'php-openssl-sign',
    re: /openssl_sign\s*\(|openssl_verify\s*\(/g,
    algo: 'rsa',
    primitive: 'signature',
    confidence: 'medium',
  },
  {
    id: 'php-hash',
    re: /\b(md5|sha1|sha256|sha512)\s*\(/g,
    algo: (m) => norm(m[1]),
    primitive: 'hash',
    confidence: 'high',
  },
  {
    id: 'php-mcrypt',
    re: /mcrypt_(?:encrypt|decrypt|module_open)/g,
    algo: '3des',
    primitive: 'symmetric',
    confidence: 'medium',
    note: 'mcrypt is removed in PHP 7.2+; legacy DES/3DES usage.',
  },
  {
    id: 'php-openssl-encrypt',
    re: /openssl_encrypt\s*\([^,]+,\s*['"]([a-z0-9-]+)['"]/g,
    algo: (m) => norm(m[1]),
    primitive: 'symmetric',
    confidence: 'high',
  },
  {
    id: 'php-password-hash',
    re: /password_hash\s*\([^,]+,\s*PASSWORD_(BCRYPT|ARGON2I|ARGON2ID|DEFAULT)/g,
    algo: (m) => (m[1] === 'BCRYPT' ? 'bcrypt' : 'argon2'),
    primitive: 'kdf',
    confidence: 'high',
  },
];

// ---------------------------------------------------------------------------
// Ruby
// ---------------------------------------------------------------------------

/** @type {Rule[]} */
const ruby = [
  {
    id: 'rb-openssl-pkey',
    re: /OpenSSL::PKey::(RSA|DSA|EC|Ed25519)\.new/g,
    algo: (m) => norm(m[1]),
    primitive: 'pke',
    confidence: 'high',
  },
  {
    id: 'rb-digest',
    re: /(?:OpenSSL::Digest|Digest)::(MD5|SHA1|SHA256|SHA512)/g,
    algo: (m) => norm(m[1]),
    primitive: 'hash',
    confidence: 'high',
  },
  {
    id: 'rb-cipher',
    re: /OpenSSL::Cipher\.new\(\s*['"]([a-z0-9-]+)['"]/g,
    algo: (m) => norm(m[1]),
    primitive: 'symmetric',
    confidence: 'high',
  },
  {
    id: 'rb-jwt',
    re: /JWT\.encode\([^)]*algorithm:\s*['"](RS256|HS256|ES256)['"]/g,
    algo: (m) => (m[1].startsWith('RS') ? 'rsa' : m[1].startsWith('ES') ? 'ecdsa' : 'hmac-sha256'),
    primitive: 'signature',
    confidence: 'high',
  },
];

// ---------------------------------------------------------------------------
// Shell / PowerShell
// ---------------------------------------------------------------------------

/** @type {Rule[]} */
const shell = [
  {
    id: 'sh-openssl-genrsa',
    re: /openssl\s+genrsa(?:\s+-out\s+\S+)?\s+(\d{3,5})?/g,
    algo: (m) => (m[1] ? `rsa-${m[1]}` : 'rsa'),
    primitive: 'pke',
    confidence: 'high',
    bits: (m) => (m[1] ? Number(m[1]) : undefined),
  },
  {
    id: 'sh-openssl-req-rsa',
    re: /openssl\s+req\b[^\n]*?rsa:(\d{3,5})/g,
    algo: (m) => `rsa-${m[1]}`,
    primitive: 'pke',
    confidence: 'high',
    bits: (m) => Number(m[1]),
  },
  {
    id: 'sh-ssh-keygen',
    re: /ssh-keygen\b[^\n]*?-t\s+(rsa|dsa|ecdsa|ed25519)/g,
    algo: (m) => norm(m[1]),
    primitive: 'signature',
    confidence: 'high',
  },
  {
    id: 'sh-openssl-dgst',
    re: /openssl\s+dgst\s+-(md5|sha1|sha256|sha512)/g,
    algo: (m) => norm(m[1]),
    primitive: 'hash',
    confidence: 'high',
  },
  {
    id: 'sh-openssl-enc',
    re: /openssl\s+enc\s+-(des3|des|rc4|bf|cast5)/g,
    algo: (m) => norm(m[1]),
    primitive: 'symmetric',
    confidence: 'high',
  },
  {
    id: 'sh-curl-tls',
    re: /curl\b[^\n]*?--tlsv(1(?:\.1)?|1\.2|1\.3)/g,
    algo: (m) => `tls-${m[1]}`,
    primitive: 'protocol',
    confidence: 'high',
  },
  {
    id: 'sh-ssh-kex',
    re: /KexAlgorithms\s*[=+]?\s*([a-z0-9@.,-]+)/g,
    algo: (m) => {
      const v = m[1].toLowerCase();
      if (v.includes('sntrup761') || v.includes('mlkem')) return 'sntrup761x25519-sha512';
      return 'ecdh';
    },
    primitive: 'key-agreement',
    confidence: 'medium',
  },
];

const powershell = [
  {
    id: 'ps-cert',
    re: /New-SelfSignedCertificate\b[^\n]*?-KeyAlgorithm\s+(RSA|ECDSA|Ed25519)/g,
    algo: (m) => norm(m[1]),
    primitive: 'signature',
    confidence: 'high',
  },
  {
    id: 'ps-tls',
    re: /\[Net\.SecurityProtocolType\]::(Tls|Tls11|Tls12|Tls13)/g,
    algo: (m) => {
      const n = m[1];
      if (n === 'Tls') return 'tls-1.0';
      if (n === 'Tls11') return 'tls-1.1';
      if (n === 'Tls12') return 'tls-1.2';
      return 'tls-1.3';
    },
    primitive: 'protocol',
    confidence: 'high',
  },
  {
    id: 'ps-hash',
    re: /Get-FileHash\b[^\n]*?-Algorithm\s+(MD5|SHA1|SHA256|SHA512)/g,
    algo: (m) => norm(m[1]),
    primitive: 'hash',
    confidence: 'high',
  },
];

// ---------------------------------------------------------------------------
// Swift / Scala
// ---------------------------------------------------------------------------

const swift = [
  {
    id: 'swift-rsa',
    re: /SecKeyCreate(?:RandomKey|EncryptedData|Signature)\b[^\n]*?(kSecAttrKeyTypeRSA)/g,
    algo: 'rsa',
    primitive: 'pke',
    confidence: 'high',
  },
  {
    id: 'swift-ec',
    re: /kSecAttrKeyTypeEC(?:SECP256R1|SECP384R1|SECP521R1)?/g,
    algo: 'ecdsa',
    primitive: 'signature',
    confidence: 'high',
  },
  {
    id: 'swift-commoncrypto',
    re: /\bCC_(?:MD5|SHA1|SHA256|DES|3DES)\b/g,
    algo: (m) => {
      const s = m[0];
      if (s.includes('MD5')) return 'md5';
      if (s.includes('SHA1')) return 'sha1';
      if (s.includes('3DES')) return '3des';
      if (s.includes('DES')) return 'des';
      return 'sha256';
    },
    primitive: 'hash',
    confidence: 'high',
  },
];

const scala = java;

/** @type {Record<string, Rule[]>} */
export const RULES = {
  javascript,
  typescript,
  python,
  java,
  kotlin,
  go,
  c,
  cpp,
  csharp,
  rust,
  php,
  ruby,
  shell,
  powershell,
  swift,
  scala,
};

/** Total rule count, surfaced in the CLI for credibility. */
export const RULE_COUNT = Object.values(RULES).reduce((n, r) => n + r.length, 0);

/**
 * Comment syntax per language, used to blank out comments before matching
 * so that documentation examples do not become findings.
 */
export const COMMENT_SYNTAX = {
  javascript: { line: ['//'], block: [['/*', '*/']] },
  typescript: { line: ['//'], block: [['/*', '*/']] },
  python: { line: ['#'], block: [['"""', '"""'], ["'''", "'''"]] },
  java: { line: ['//'], block: [['/*', '*/']] },
  kotlin: { line: ['//'], block: [['/*', '*/']] },
  go: { line: ['//'], block: [['/*', '*/']] },
  c: { line: ['//'], block: [['/*', '*/']] },
  cpp: { line: ['//'], block: [['/*', '*/']] },
  csharp: { line: ['//'], block: [['/*', '*/']] },
  rust: { line: ['//'], block: [['/*', '*/']] },
  php: { line: ['//', '#'], block: [['/*', '*/']] },
  ruby: { line: ['#'], block: [['=begin', '=end']] },
  shell: { line: ['#'], block: [] },
  powershell: { line: ['#'], block: [['<#', '#>']] },
  swift: { line: ['//'], block: [['/*', '*/']] },
  scala: { line: ['//'], block: [['/*', '*/']] },
};
