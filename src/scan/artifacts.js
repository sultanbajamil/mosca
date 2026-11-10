/**
 * MOSCA — on-disk cryptographic artifact scanner
 * ==============================================
 *
 * The source scanner sees `createSign('RSA-SHA256')`. It does not see the
 * 1024-bit private key sitting next to it, the PEM chain in `certs/`, the JWKS
 * used by the identity provider, or the `authorized_keys` file that keeps a
 * legacy RSA key alive.
 *
 * This scanner reads public structure only. For private keys it decodes the
 * algorithm identifier (and, for OpenSSH keys, the embedded public half) and
 * then throws the bytes away. No key material, base64 body or private
 * component is ever placed in a finding, a report or a CBOM.
 */

import fs from 'node:fs';
import path from 'node:path';
import {
  parseCertificate,
  parseSubjectPublicKeyInfo,
  parsePkcs1RsaPublicKey,
  readTLV,
  children,
  decodeOID,
  TAG,
  OID,
} from '../net/x509.js';
import { classifyCertificate } from '../net/x509-chain.js';
import { lookup, rsaVariant } from '../rules/algorithms.js';
import { walk, readTextFile, createIgnore, loadIgnoreFile } from '../util/fs.js';

const MAX_ARTIFACT_BYTES = 1024 * 1024;

/** Lockfiles are the dependency scanner's job; do not re-read them here. */
const SKIP_BASENAMES = new Set([
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'poetry.lock',
  'Cargo.lock',
  'go.sum',
]);

const PEM_PATTERN = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;

const CURVE_BITS = {
  'P-256': 256,
  'P-384': 384,
  'P-521': 521,
  secp256k1: 256,
  'nistp256': 256,
  'nistp384': 384,
  'nistp521': 521,
};

/** Line number (1-based) for a character offset. */
function lineAt(content, index) {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) {
    if (content[i] === '\n') line += 1;
  }
  return line;
}

function decodeBase64(body) {
  const cleaned = body.replace(/\s+/g, '');
  if (!cleaned) return null;
  try {
    const buf = Buffer.from(cleaned, 'base64');
    return buf.length > 0 ? buf : null;
  } catch {
    return null;
  }
}

/** Map a PKCS#8 / SPKI algorithm identifier to a registry id without reading key material. */
function algorithmFromIdentifier(oid, curveOid) {
  if (oid === '1.2.840.113549.1.1.1') return { algorithm: 'rsa', primitive: 'signature', label: 'RSA' };
  if (oid === '1.2.840.10045.2.1') {
    const curve = curveOid ? OID[curveOid] : null;
    const algorithm = curve?.algo === 'secp256k1' ? 'secp256k1' : 'ecdsa';
    return { algorithm, primitive: 'signature', label: curve?.name || 'EC', bits: curve?.bits || null, curve: curve?.name || null };
  }
  if (oid === '1.3.101.112') return { algorithm: 'ed25519', primitive: 'signature', label: 'Ed25519', bits: 256 };
  if (oid === '1.3.101.113') return { algorithm: 'ed448', primitive: 'signature', label: 'Ed448', bits: 456 };
  if (oid === '1.3.101.110') return { algorithm: 'x25519', primitive: 'key-agreement', label: 'X25519', bits: 256 };
  if (oid === '1.3.101.111') return { algorithm: 'x448', primitive: 'key-agreement', label: 'X448', bits: 448 };
  if (oid === '1.2.840.10040.4.1') return { algorithm: 'dsa', primitive: 'signature', label: 'DSA' };
  const info = OID[oid];
  if (info?.algo) return { algorithm: info.algo, primitive: info.primitive || 'signature', label: info.name };
  return null;
}

/**
 * Parse a PKCS#8 PrivateKeyInfo's algorithm identifier.
 * The private-key OCTET STRING is never read.
 * @param {Buffer} der
 */
export function parsePkcs8Algorithm(der) {
  const root = readTLV(der, 0);
  if (root.tag !== TAG.SEQUENCE) return null;
  const kids = [...children(der, root)];
  if (kids.length < 2) return null;
  const algNode = kids[1];
  if (!algNode || algNode.tag !== TAG.SEQUENCE) return null;
  const algKids = [...children(der, algNode)];
  if (!algKids[0] || algKids[0].tag !== TAG.OID) return null;
  const oid = decodeOID(der, algKids[0]);
  let curveOid = null;
  if (algKids[1] && algKids[1].tag === TAG.OID) curveOid = decodeOID(der, algKids[1]);
  const info = algorithmFromIdentifier(oid, curveOid);
  return info ? { ...info, oid, curveOid } : { oid, curveOid, algorithm: 'unknown', primitive: 'signature', label: oid };
}

// ---------------------------------------------------------------------------
// OpenSSH private key: public half only
// ---------------------------------------------------------------------------

function readSshString(buf, offset) {
  if (offset + 4 > buf.length) return null;
  const length = buf.readUInt32BE(offset);
  if (length > buf.length - offset - 4) return null;
  return { value: buf.subarray(offset + 4, offset + 4 + length), next: offset + 4 + length };
}

function sshMpintBits(value) {
  let i = 0;
  while (i < value.length && value[i] === 0) i++;
  if (i >= value.length) return 0;
  return (value.length - i - 1) * 8 + value[i].toString(2).length;
}

/**
 * Extract the public key type and size from an OpenSSH private key.
 * Encrypted keys still carry this public blob in the clear.
 * @param {Buffer} der
 */
export function parseOpenSshPrivateKey(der) {
  const magic = 'openssh-key-v1\u0000';
  if (der.length < magic.length || der.subarray(0, magic.length).toString('latin1') !== magic) return null;
  let p = magic.length;
  const cipher = readSshString(der, p);
  if (!cipher) return null;
  p = cipher.next;
  const kdf = readSshString(der, p);
  if (!kdf) return null;
  p = kdf.next;
  const kdfOptions = readSshString(der, p);
  if (!kdfOptions) return null;
  p = kdfOptions.next;
  if (p + 4 > der.length) return null;
  p += 4; // number of keys
  const publicBlob = readSshString(der, p);
  if (!publicBlob) return null;

  const typeString = readSshString(publicBlob.value, 0);
  if (!typeString) return null;
  const type = typeString.value.toString('latin1');
  let bits = null;

  if (type === 'ssh-rsa') {
    const e = readSshString(publicBlob.value, typeString.next);
    const n = e ? readSshString(publicBlob.value, e.next) : null;
    bits = n ? sshMpintBits(n.value) : null;
  } else if (type === 'ssh-ed25519') {
    bits = 256;
  } else if (type.startsWith('ecdsa-sha2-')) {
    const curve = readSshString(publicBlob.value, typeString.next);
    const name = curve?.value.toString('latin1') || type.replace('ecdsa-sha2-', '');
    bits = CURVE_BITS[name] || null;
  } else if (type === 'ssh-dss') {
    const p1 = readSshString(publicBlob.value, typeString.next);
    const p2 = p1 ? readSshString(publicBlob.value, p1.next) : null;
    const p3 = p2 ? readSshString(publicBlob.value, p2.next) : null;
    const p4 = p3 ? readSshString(publicBlob.value, p3.next) : null;
    bits = p4 ? sshMpintBits(p4.value) : null;
    if (p1) bits = sshMpintBits(p1.value);
  }

  return { type, bits, encrypted: cipher.value.toString('latin1') !== 'none' };
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

function artifactFinding({ rel, line, id, title, algorithm, primitive, format, artifactType, evidence, note, confidence = 'high' }) {
  const algo = lookup(algorithm);
  return {
    id,
    kind: 'artifact',
    title,
    algorithm: algo.id,
    algorithmLabel: algo.label,
    primitive,
    location: { file: rel, line, column: 1 },
    snippet: null,
    matched: null,
    confidence,
    note: note || null,
    artifact: { format, type: artifactType },
    // Evidence carries metadata only: never key bytes, never a base64 body.
    evidence: evidence || {},
  };
}

function certificateFinding(parsed, { rel, line, format }) {
  const entry = classifyCertificate(parsed, 0, new Date());
  const bits = entry.keyBits ? ` (${entry.keyBits} bits)` : '';
  return artifactFinding({
    rel,
    line,
    id: 'artifact-certificate',
    title: `Certificate ${entry.subject} uses ${entry.keyLabel}${bits}`,
    algorithm: entry.keyAlgorithm,
    primitive: 'signature',
    format,
    artifactType: 'certificate',
    evidence: {
      subject: entry.subject,
      issuer: entry.issuer,
      keyAlgorithm: entry.keyAlgorithm,
      keyBits: entry.keyBits,
      signature: entry.signatureAlgorithm,
      signatureHash: entry.signatureHash,
      notAfter: entry.notAfter?.toISOString?.() || null,
    },
    note: entry.legacySignature
      ? 'The certificate signature uses a classically broken hash.'
      : 'Certificates stored on disk are part of the long-lived trust surface; inventory them before the PQ migration.',
  });
}

function publicKeyFinding(info, { rel, line, format, source }) {
  const algorithm =
    info.algorithm === 'rsa' && info.bits ? rsaVariant(info.bits).id : info.algorithm || 'unknown';
  const bits = info.bits ? ` (${info.bits} bits)` : '';
  return artifactFinding({
    rel,
    line,
    id: 'artifact-public-key',
    title: `${info.label || lookup(algorithm).label} public key${bits} in ${source}`,
    algorithm,
    primitive: info.primitive || 'signature',
    format,
    artifactType: 'public-key',
    evidence: { keyAlgorithm: algorithm, keyBits: info.bits || null, curve: info.curve || null },
    note: 'Public keys are not secret, but they fix the algorithm and size of every signature the corresponding private key will produce.',
  });
}

function privateKeyFinding(info, { rel, line, format, source }) {
  const algorithm = info.algorithm || lookup('unknown').id;
  const bits = info.bits ? ` (${info.bits} bits)` : '';
  return artifactFinding({
    rel,
    line,
    id: 'artifact-private-key',
    title: `${info.label || 'Private'} private key${bits} stored in ${source}`,
    algorithm,
    primitive: info.primitive || 'signature',
    format,
    artifactType: 'private-key',
    evidence: { keyAlgorithm: algorithm, keyBits: info.bits || null, curve: info.curve || null, encrypted: info.encrypted ?? null },
    note: 'A private key on disk is both a confidentiality risk and a migration anchor. Never copy key material into tickets or reports.',
  });
}

// ---------------------------------------------------------------------------
// PEM / DER
// ---------------------------------------------------------------------------

function scanPem(content, rel, findings) {
  PEM_PATTERN.lastIndex = 0;
  let match;
  while ((match = PEM_PATTERN.exec(content)) !== null) {
    const label = match[1].trim().toUpperCase();
    const body = match[2];
    const line = lineAt(content, match.index);
    const der = decodeBase64(body);
    if (!der) continue;

    try {
      if (label === 'CERTIFICATE' || label === 'X509 CERTIFICATE' || label === 'TRUSTED CERTIFICATE') {
        findings.push(certificateFinding(parseCertificate(der), { rel, line, format: 'PEM' }));
      } else if (label === 'PUBLIC KEY') {
        findings.push(publicKeyFinding(parseSubjectPublicKeyInfo(der), { rel, line, format: 'PEM', source: path.basename(rel) }));
      } else if (label === 'RSA PUBLIC KEY') {
        findings.push(publicKeyFinding(parsePkcs1RsaPublicKey(der), { rel, line, format: 'PEM', source: path.basename(rel) }));
      } else if (label === 'PRIVATE KEY' || label === 'ENCRYPTED PRIVATE KEY') {
        const info = parsePkcs8Algorithm(der);
        if (info) findings.push(privateKeyFinding(info, { rel, line, format: 'PEM', source: path.basename(rel) }));
      } else if (label === 'RSA PRIVATE KEY' || label === 'EC PRIVATE KEY' || label === 'DSA PRIVATE KEY') {
        // PKCS#1 / SEC1: the algorithm is in the label. Do not decode the body.
        const algorithm = label.startsWith('RSA') ? 'rsa' : label.startsWith('EC') ? 'ecdsa' : 'dsa';
        findings.push(
          privateKeyFinding(
            { algorithm, primitive: 'signature', label: lookup(algorithm).label, bits: null },
            { rel, line, format: 'PEM', source: path.basename(rel) },
          ),
        );
      } else if (label === 'OPENSSH PRIVATE KEY') {
        const info = parseOpenSshPrivateKey(der);
        if (info) {
          const algorithm = lookup(info.type).id;
          findings.push(
            privateKeyFinding(
              { algorithm, primitive: 'signature', label: lookup(algorithm).label, bits: info.bits, encrypted: info.encrypted },
              { rel, line, format: 'OpenSSH', source: path.basename(rel) },
            ),
          );
        }
      }
    } catch {
      // A malformed or unsupported PEM block is not a finding.
    }
  }
}

/**
 * Inspect a DER blob: an X.509 certificate first, then a PKCS#8 private key.
 * @param {Buffer} buffer
 * @param {{rel:string, line?:number, format?:string}} input
 */
export function scanDerArtifact(buffer, { rel, line = 1, format = 'DER' }) {
  try {
    return [certificateFinding(parseCertificate(buffer), { rel, line, format })];
  } catch {
    /* not a certificate */
  }
  try {
    const info = parsePkcs8Algorithm(buffer);
    if (info && info.algorithm !== 'unknown') {
      return [privateKeyFinding(info, { rel, line, format, source: path.basename(rel) })];
    }
  } catch {
    /* not PKCS#8 */
  }
  return [];
}

// ---------------------------------------------------------------------------
// JWK / JWKS
// ---------------------------------------------------------------------------

function base64UrlBits(value) {
  try {
    const buf = Buffer.from(String(value).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    return buf.length * 8;
  } catch {
    return null;
  }
}

function jwkInfo(key) {
  const kty = String(key.kty || '').toUpperCase();
  const alg = key.alg ? String(key.alg) : '';

  if (kty === 'RSA') {
    const bits = key.n ? base64UrlBits(key.n) : null;
    const algo = rsaVariant(bits);
    return { algorithm: algo.id, primitive: 'signature', label: algo.label, bits, curve: null };
  }
  if (kty === 'EC') {
    const crv = String(key.crv || '');
    const algorithm = crv.toLowerCase() === 'secp256k1' ? 'secp256k1' : 'ecdsa';
    return { algorithm, primitive: 'signature', label: `EC ${crv || ''}`.trim(), bits: CURVE_BITS[crv] || null, curve: crv || null };
  }
  if (kty === 'OKP') {
    const crv = String(key.crv || '');
    if (/x25519/i.test(crv)) return { algorithm: 'x25519', primitive: 'key-agreement', label: 'X25519', bits: 256 };
    if (/x448/i.test(crv)) return { algorithm: 'x448', primitive: 'key-agreement', label: 'X448', bits: 448 };
    if (/ed448/i.test(crv)) return { algorithm: 'ed448', primitive: 'signature', label: 'Ed448', bits: 456 };
    return { algorithm: 'ed25519', primitive: 'signature', label: 'Ed25519', bits: 256 };
  }
  if (kty === 'oct') {
    if (/^HS/i.test(alg)) return { algorithm: 'hmac-sha256', primitive: 'mac', label: 'HMAC secret', bits: null };
    if (/A128/i.test(alg)) return { algorithm: 'aes-128', primitive: 'symmetric', label: 'AES-128 secret', bits: 128 };
    if (/A256/i.test(alg)) return { algorithm: 'aes-256', primitive: 'symmetric', label: 'AES-256 secret', bits: 256 };
    return { algorithm: 'unknown', primitive: 'symmetric', label: 'Symmetric secret', bits: null };
  }
  if (alg) {
    const algo = lookup(alg);
    return { algorithm: algo.id, primitive: algo.primitives?.[0] || 'signature', label: algo.label, bits: null };
  }
  return null;
}

/**
 * Inspect JSON text for JWK or JWKS structures.
 * @param {string} content
 * @param {string} rel
 */
export function scanJwkContent(content, rel) {
  let doc;
  try {
    doc = JSON.parse(content);
  } catch {
    return [];
  }
  if (!doc || typeof doc !== 'object') return [];

  const keys = Array.isArray(doc.keys) ? doc.keys : doc.kty ? [doc] : [];
  const findings = [];
  let cursor = 0;
  for (const key of keys) {
    if (!key || typeof key !== 'object') continue;
    const info = jwkInfo(key);
    if (!info) continue;
    const index = content.indexOf('"kty"', cursor);
    if (index >= 0) cursor = index + 5;
    findings.push(
      artifactFinding({
        rel,
        line: index >= 0 ? lineAt(content, index) : 1,
        id: 'artifact-jwk',
        title: `JWK ${info.label}${info.bits ? ` (${info.bits} bits)` : ''}${key.alg ? ` for ${key.alg}` : ''}`,
        algorithm: info.algorithm,
        primitive: info.primitive,
        format: 'JWK',
        artifactType: 'jwk',
        evidence: { kty: key.kty || null, crv: key.crv || null, alg: key.alg || null, keyBits: info.bits || null, keyOps: key.key_ops || null },
        note: 'Identity-provider signing keys are long-lived by design. Record the algorithm and plan a dual-signing period.',
      }),
    );
  }
  return findings;
}

// ---------------------------------------------------------------------------
// SSH public keys
// ---------------------------------------------------------------------------

const SSH_KEY_LINE = /(?:^|[\s,=])(ssh-rsa|ssh-dss|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|ssh-ed25519)\s+([A-Za-z0-9+/=]{20,})/;

/**
 * Inspect `authorized_keys`, `known_hosts` and `*.pub` text.
 * @param {string} content
 * @param {string} rel
 */
export function scanSshKeyContent(content, rel) {
  const findings = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line || line.trimStart().startsWith('#')) continue;
    const match = SSH_KEY_LINE.exec(line);
    if (!match) continue;
    const type = match[1];
    const algorithm = lookup(type);
    const bits =
      type === 'ssh-rsa' ? null : type === 'ssh-ed25519' ? 256 : type.startsWith('ecdsa') ? CURVE_BITS[type.split('-').pop()] || null : null;
    findings.push(
      artifactFinding({
        rel,
        line: i + 1,
        id: 'artifact-ssh-public-key',
        title: `${algorithm.label} key authorised in ${path.basename(rel)}`,
        algorithm: algorithm.id,
        primitive: 'signature',
        format: 'OpenSSH',
        artifactType: 'ssh-public-key',
        evidence: { keyType: type, keyBits: bits },
        note:
          type === 'ssh-rsa'
            ? 'ssh-rsa uses SHA-1 and is classically broken. Remove it from authorized_keys and known_hosts.'
            : 'SSH public keys pin the trust anchor. Post-quantum host keys (ML-DSA) require a client and server upgrade.',
      }),
    );
  }
  return findings;
}

// ---------------------------------------------------------------------------
// File and directory entry points
// ---------------------------------------------------------------------------

/**
 * Inspect one artifact file.
 * @param {string} file absolute path
 * @param {string} rel repo-relative path
 */
export function scanArtifactFile(file, rel) {
  const base = path.basename(rel).toLowerCase();
  if (SKIP_BASENAMES.has(base)) return [];

  let stat;
  try {
    stat = fs.statSync(file);
  } catch {
    return [];
  }
  if (!stat.isFile() || stat.size === 0 || stat.size > MAX_ARTIFACT_BYTES) return [];

  if (base === 'authorized_keys' || base === 'authorized_keys2' || base === 'known_hosts' || base === 'known_hosts2' || base.endsWith('.pub')) {
    const text = readTextFile(file, MAX_ARTIFACT_BYTES);
    return text == null ? [] : scanSshKeyContent(text, rel);
  }

  const ext = path.extname(base);
  if (ext === '.json') {
    const text = readTextFile(file, MAX_ARTIFACT_BYTES);
    return text == null ? [] : scanJwkContent(text, rel);
  }

  if (ext === '.der' || ext === '.cer') {
    try {
      return scanDerArtifact(fs.readFileSync(file), { rel, line: 1, format: 'DER' });
    } catch {
      return [];
    }
  }

  const text = readTextFile(file, MAX_ARTIFACT_BYTES);
  if (text != null) {
    const findings = [];
    scanPem(text, rel, findings);
    return findings;
  }

  // Binary without a recognisable extension: try DER once.
  try {
    return scanDerArtifact(fs.readFileSync(file), { rel, line: 1, format: 'DER' });
  } catch {
    return [];
  }
}

/**
 * Scan a repository for cryptographic artifacts.
 * @param {string} root
 * @param {{ignore?:string[], maxFiles?:number}} [opts]
 */
export function scanArtifactsDirectory(root, opts = {}) {
  const { ignore: extraIgnore = [], maxFiles = 50000 } = opts;
  // The default ignore list hides exactly the files this scanner exists for.
  const ignore = createIgnore([...loadIgnoreFile(root), ...extraIgnore], { defaults: false });
  const files = walk(root, { ignore, maxFiles });

  const findings = [];
  const byType = {};
  let filesScanned = 0;

  for (const file of files) {
    const found = scanArtifactFile(file.path, file.rel);
    if (found.length) {
      filesScanned += 1;
      for (const finding of found) {
        byType[finding.artifact?.type || 'unknown'] = (byType[finding.artifact?.type || 'unknown'] || 0) + 1;
      }
      findings.push(...found);
    }
  }

  return { findings, stats: { filesScanned, byType, totalFiles: files.length } };
}

export { MAX_ARTIFACT_BYTES };
