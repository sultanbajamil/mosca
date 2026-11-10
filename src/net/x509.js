/**
 * MOSCA — minimal DER / X.509 reader
 * ==================================
 *
 * A dependency-free ASN.1 DER parser, scoped to what a certificate audit
 * needs: signature algorithm, public-key algorithm and size, validity,
 * subject/issuer, SANs and basic constraints.
 *
 * Why not a library? A supply-chain auditor that pulls 300 transitive
 * packages to read a certificate is not credible. This file is ~400 lines
 * and is covered by unit tests with real DER fixtures.
 */

// ---------------------------------------------------------------------------
// TLV primitives
// ---------------------------------------------------------------------------

export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  SEQUENCE: 0x30,
  SET: 0x31,
  PRINTABLE_STRING: 0x13,
  IA5_STRING: 0x16,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
};

/**
 * @typedef {{tag:number, start:number, headerLen:number, length:number,
 *            valueStart:number, valueEnd:number, end:number}} TLV
 */

/**
 * Read one DER TLV at `offset`.
 * @param {Buffer} buf
 * @param {number} offset
 * @returns {TLV}
 */
export function readTLV(buf, offset) {
  if (offset >= buf.length) throw new Error(`DER: offset ${offset} past end`);
  const tag = buf[offset];
  let p = offset + 1;
  let length = buf[p++];
  if (length === undefined) throw new Error('DER: truncated length');
  if (length & 0x80) {
    const n = length & 0x7f;
    if (n === 0) throw new Error('DER: indefinite length is not valid DER');
    if (n > 4) throw new Error('DER: length too large');
    length = 0;
    for (let i = 0; i < n; i++) length = length * 256 + buf[p++];
  }
  const valueStart = p;
  const valueEnd = p + length;
  if (valueEnd > buf.length) throw new Error('DER: value past end of buffer');
  return { tag, start: offset, headerLen: p - offset, length, valueStart, valueEnd, end: valueEnd };
}

/**
 * Iterate the direct children of a constructed TLV.
 * @param {Buffer} buf
 * @param {TLV} node
 */
export function* children(buf, node) {
  let p = node.valueStart;
  while (p < node.valueEnd) {
    const child = readTLV(buf, p);
    yield child;
    p = child.end;
    if (child.length === 0 && child.end === p) break;
  }
}

/** Decode an OBJECT IDENTIFIER TLV into dotted form. */
export function decodeOID(buf, node) {
  const bytes = buf.subarray(node.valueStart, node.valueEnd);
  if (bytes.length === 0) return '';
  const first = bytes[0];
  const parts = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (let i = 1; i < bytes.length; i++) {
    value = value * 128 + (bytes[i] & 0x7f);
    if ((bytes[i] & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join('.');
}

/** Decode an INTEGER TLV as a BigInt (unsigned for our purposes). */
export function decodeInteger(buf, node) {
  const bytes = buf.subarray(node.valueStart, node.valueEnd);
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

/** Bit length of a non-negative BigInt. */
export function bitLength(value) {
  if (value <= 0n) return 0;
  return value.toString(2).length;
}

/** Decode a string TLV to a JS string. */
export function decodeString(buf, node) {
  const bytes = buf.subarray(node.valueStart, node.valueEnd);
  switch (node.tag) {
    case TAG.UTF8_STRING:
      return bytes.toString('utf8');
    case TAG.IA5_STRING:
    case TAG.PRINTABLE_STRING:
      return bytes.toString('latin1');
    default:
      return bytes.toString('utf8');
  }
}

/** Parse UTCTime / GeneralizedTime into a Date (UTC). */
export function decodeTime(buf, node) {
  const s = buf.subarray(node.valueStart, node.valueEnd).toString('latin1');
  const m = /^(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:\.\d+)?(Z|[+-]\d{4})?$/.exec(s);
  if (!m) return null;
  let year = Number(m[1]);
  if (m[1].length === 2) year += year < 50 ? 2000 : 1900;
  const [, , mo, d, h, mi, sec] = m;
  const date = new Date(Date.UTC(year, Number(mo) - 1, Number(d), Number(h), Number(mi), Number(sec || 0)));
  return Number.isNaN(date.getTime()) ? null : date;
}

// ---------------------------------------------------------------------------
// OID tables
// ---------------------------------------------------------------------------

export const OID = {
  // signature algorithms
  '1.2.840.113549.1.1.4': { name: 'md5WithRSAEncryption', algo: 'md5', primitive: 'signature' },
  '1.2.840.113549.1.1.5': { name: 'sha1WithRSAEncryption', algo: 'rsa', primitive: 'signature', hash: 'sha1' },
  '1.2.840.113549.1.1.10': { name: 'RSASSA-PSS', algo: 'rsa', primitive: 'signature' },
  '1.2.840.113549.1.1.11': { name: 'sha256WithRSAEncryption', algo: 'rsa', primitive: 'signature', hash: 'sha256' },
  '1.2.840.113549.1.1.12': { name: 'sha384WithRSAEncryption', algo: 'rsa', primitive: 'signature', hash: 'sha384' },
  '1.2.840.113549.1.1.13': { name: 'sha512WithRSAEncryption', algo: 'rsa', primitive: 'signature', hash: 'sha512' },
  '1.2.840.10045.4.1': { name: 'ecdsa-with-SHA1', algo: 'ecdsa', primitive: 'signature', hash: 'sha1' },
  '1.2.840.10045.4.3.1': { name: 'ecdsa-with-SHA224', algo: 'ecdsa', primitive: 'signature', hash: 'sha224' },
  '1.2.840.10045.4.3.2': { name: 'ecdsa-with-SHA256', algo: 'ecdsa', primitive: 'signature', hash: 'sha256' },
  '1.2.840.10045.4.3.3': { name: 'ecdsa-with-SHA384', algo: 'ecdsa', primitive: 'signature', hash: 'sha384' },
  '1.2.840.10045.4.3.4': { name: 'ecdsa-with-SHA512', algo: 'ecdsa', primitive: 'signature', hash: 'sha512' },
  '1.3.101.112': { name: 'Ed25519', algo: 'ed25519', primitive: 'signature' },
  '1.3.101.113': { name: 'Ed448', algo: 'ed448', primitive: 'signature' },
  '2.16.840.1.101.3.4.3.17': { name: 'ML-DSA-44', algo: 'ml-dsa-44', primitive: 'signature' },
  '2.16.840.1.101.3.4.3.18': { name: 'ML-DSA-65', algo: 'ml-dsa-65', primitive: 'signature' },
  '2.16.840.1.101.3.4.3.19': { name: 'ML-DSA-87', algo: 'ml-dsa-87', primitive: 'signature' },
  '2.16.840.1.101.3.4.3.20': { name: 'SLH-DSA-SHA2-128s', algo: 'slh-dsa-128s', primitive: 'signature' },
  '2.16.840.1.101.3.4.3.21': { name: 'SLH-DSA-SHA2-128f', algo: 'slh-dsa-128f', primitive: 'signature' },
  '2.16.840.1.101.3.4.3.22': { name: 'SLH-DSA-SHA2-192s', algo: 'slh-dsa-192s', primitive: 'signature' },
  '2.16.840.1.101.3.4.3.23': { name: 'SLH-DSA-SHA2-192f', algo: 'slh-dsa-192f', primitive: 'signature' },
  '2.16.840.1.101.3.4.3.24': { name: 'SLH-DSA-SHA2-256s', algo: 'slh-dsa-256s', primitive: 'signature' },
  '2.16.840.1.101.3.4.3.25': { name: 'SLH-DSA-SHA2-256f', algo: 'slh-dsa-256f', primitive: 'signature' },
  // public key algorithms
  '1.2.840.113549.1.1.1': { name: 'rsaEncryption', algo: 'rsa', primitive: 'pke' },
  '1.2.840.10045.2.1': { name: 'id-ecPublicKey', algo: 'ecdsa', primitive: 'signature' },
  '1.3.101.110': { name: 'X25519', algo: 'x25519', primitive: 'key-agreement' },
  '1.3.101.111': { name: 'X448', algo: 'x448', primitive: 'key-agreement' },
  '1.2.840.10040.4.1': { name: 'id-dsa', algo: 'dsa', primitive: 'signature' },
  '1.2.840.113549.1.3.1': { name: 'dhKeyAgreement', algo: 'dh', primitive: 'key-agreement' },
  // named curves
  '1.2.840.10045.3.1.7': { name: 'prime256v1 (P-256)', bits: 256, algo: 'ecdh' },
  '1.3.132.0.34': { name: 'secp384r1 (P-384)', bits: 384, algo: 'ecdh' },
  '1.3.132.0.35': { name: 'secp521r1 (P-521)', bits: 521, algo: 'ecdh' },
  '1.3.132.0.10': { name: 'secp256k1', bits: 256, algo: 'secp256k1' },
  '1.3.36.3.3.2.8.1.1.7': { name: 'brainpoolP256r1', bits: 256, algo: 'ecdh' },
};

/** Look up a signature algorithm OID, with a sane fallback. */
export function sigAlgFromOid(oid) {
  return OID[oid] || { name: `unknown (${oid})`, algo: 'unknown', primitive: 'signature' };
}

// ---------------------------------------------------------------------------
// X.509
// ---------------------------------------------------------------------------

/** Attribute OIDs we surface from a Name. */
const NAME_ATTRS = {
  '2.5.4.3': 'CN',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '1.2.840.113549.1.9.1': 'emailAddress',
};

const EXT = {
  subjectAltName: '2.5.29.17',
  basicConstraints: '2.5.29.19',
  keyUsage: '2.5.29.15',
  extendedKeyUsage: '2.5.29.37',
};

/** Parse an X.501 Name (SEQUENCE OF SET OF AttributeTypeAndValue). */
function parseName(buf, node) {
  const out = {};
  for (const rdn of children(buf, node)) {
    for (const atv of children(buf, rdn)) {
      const kids = [...children(buf, atv)];
      if (kids.length < 2) continue;
      const oid = decodeOID(buf, kids[0]);
      const key = NAME_ATTRS[oid];
      if (!key) continue;
      const value = decodeString(buf, kids[1]);
      if (out[key] === undefined) out[key] = value;
      else if (Array.isArray(out[key])) out[key].push(value);
      else out[key] = [out[key], value];
    }
  }
  return out;
}

/** Parse the SubjectPublicKeyInfo, returning algorithm, curve and key size. */
function parseSPKI(buf, node) {
  const kids = [...children(buf, node)];
  const algNode = kids[0];
  const bitNode = kids[1];
  const algKids = [...children(buf, algNode)];
  const algOid = decodeOID(buf, algKids[0]);
  const info = OID[algOid] || { name: `unknown (${algOid})`, algo: 'unknown' };

  const result = {
    oid: algOid,
    algorithm: info.algo,
    algorithmName: info.name,
    curve: null,
    bits: info.bits || null,
    keyBytes: bitNode ? bitNode.length - 1 : 0,
  };

  // EC: curve is in the AlgorithmIdentifier parameters.
  if (algOid === '1.2.840.10045.2.1' && algKids[1]) {
    const curveOid = decodeOID(buf, algKids[1]);
    const curve = OID[curveOid];
    result.curveOid = curveOid;
    result.curve = curve ? curve.name : `unknown (${curveOid})`;
    result.bits = curve?.bits || null;
  }

  // RSA: parse the modulus out of the BIT STRING payload.
  if (algOid === '1.2.840.113549.1.1.1' && bitNode) {
    try {
      const inner = readTLV(buf, bitNode.valueStart + 1); // skip unused-bits byte
      const rsaKids = [...children(buf, inner)];
      if (rsaKids[0] && rsaKids[0].tag === TAG.INTEGER) {
        result.bits = bitLength(decodeInteger(buf, rsaKids[0]));
      }
    } catch {
      /* leave bits null */
    }
  }

  // DSA / DH: parameters carry the prime size.
  if ((algOid === '1.2.840.10040.4.1' || algOid === '1.2.840.113549.1.3.1') && algKids[1]) {
    try {
      const params = algKids[1];
      const first = readTLV(buf, params.valueStart);
      if (first.tag === TAG.INTEGER) result.bits = bitLength(decodeInteger(buf, first));
    } catch {
      /* ignore */
    }
  }

  if (algOid === '1.3.101.112') result.bits = 256;
  if (algOid === '1.3.101.113') result.bits = 456;
  if (algOid === '1.3.101.110') result.bits = 256;
  if (algOid === '1.3.101.111') result.bits = 448;

  return result;
}

/**
 * Parse a standalone SubjectPublicKeyInfo DER structure (PEM `PUBLIC KEY`).
 * @param {Buffer} der
 */
export function parseSubjectPublicKeyInfo(der) {
  const root = readTLV(der, 0);
  if (root.tag !== TAG.SEQUENCE) throw new Error('SPKI: not a SEQUENCE');
  return parseSPKI(der, root);
}

/**
 * Parse a PKCS#1 RSAPublicKey DER structure (PEM `RSA PUBLIC KEY`).
 * @param {Buffer} der
 */
export function parsePkcs1RsaPublicKey(der) {
  const root = readTLV(der, 0);
  if (root.tag !== TAG.SEQUENCE) throw new Error('RSAPublicKey: not a SEQUENCE');
  const kids = [...children(der, root)];
  if (!kids[0] || kids[0].tag !== TAG.INTEGER) throw new Error('RSAPublicKey: missing modulus');
  const bits = bitLength(decodeInteger(der, kids[0]));
  return {
    oid: '1.2.840.113549.1.1.1',
    algorithm: 'rsa',
    algorithmName: 'rsaEncryption',
    curve: null,
    bits,
    keyBytes: Math.ceil(bits / 8),
  };
}

/** Parse the extensions block into a friendly object. */
function parseExtensions(buf, node) {
  const out = { san: [], keyUsage: [], extendedKeyUsage: [], isCA: false };
  for (const ext of children(buf, node)) {
    const kids = [...children(buf, ext)];
    if (kids.length < 2) continue;
    const oid = decodeOID(buf, kids[0]);
    const valueNode = kids[kids.length - 1];
    if (valueNode.tag !== TAG.OCTET_STRING) continue;
    try {
      const inner = readTLV(buf, valueNode.valueStart);
      if (oid === EXT.subjectAltName) {
        for (const gn of children(buf, inner)) {
          // GeneralName: [2] dNSName, [7] iPAddress, [1] rfc822Name
          if (gn.tag === 0x82) out.san.push(buf.subarray(gn.valueStart, gn.valueEnd).toString('latin1'));
          else if (gn.tag === 0x87) out.san.push(formatIp(buf.subarray(gn.valueStart, gn.valueEnd)));
          else if (gn.tag === 0x81) out.san.push(buf.subarray(gn.valueStart, gn.valueEnd).toString('latin1'));
        }
      } else if (oid === EXT.basicConstraints) {
        for (const bc of children(buf, inner)) {
          if (bc.tag === TAG.BOOLEAN) out.isCA = buf[bc.valueStart] !== 0;
        }
      } else if (oid === EXT.keyUsage) {
        const bits = buf.subarray(inner.valueStart + 1, inner.valueEnd);
        const names = ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly'];
        for (let i = 0; i < names.length; i++) {
          const byte = bits[Math.floor(i / 8)];
          if (byte === undefined) break;
          if (byte & (0x80 >> i % 8)) out.keyUsage.push(names[i]);
        }
      } else if (oid === EXT.extendedKeyUsage) {
        for (const eku of children(buf, inner)) out.extendedKeyUsage.push(decodeOID(buf, eku));
      }
    } catch {
      /* one malformed extension must not abort the parse */
    }
  }
  return out;
}

function formatIp(bytes) {
  if (bytes.length === 4) return [...bytes].join('.');
  if (bytes.length === 16) {
    const groups = [];
    for (let i = 0; i < 16; i += 2) groups.push(bytes.readUInt16BE(i).toString(16));
    return groups.join(':');
  }
  return bytes.toString('hex');
}

/**
 * Parse a DER-encoded X.509 certificate.
 * @param {Buffer} der
 */
export function parseCertificate(der) {
  const root = readTLV(der, 0);
  if (root.tag !== TAG.SEQUENCE) throw new Error('X.509: certificate is not a SEQUENCE');
  const [tbs, outerSigAlg, sigValue] = [...children(der, root)];
  if (!tbs || !outerSigAlg) throw new Error('X.509: malformed certificate');

  const tbsKids = [...children(der, tbs)];
  let i = 0;
  let version = 1;
  if (tbsKids[0] && tbsKids[0].tag === 0xa0) {
    const v = readTLV(der, tbsKids[0].valueStart);
    version = Number(decodeInteger(der, v)) + 1;
    i = 1;
  }
  const serialNumber = tbsKids[i] ? decodeInteger(der, tbsKids[i]).toString(16) : '';
  i += 1;
  const innerSigAlg = tbsKids[i];
  i += 1;
  const issuerNode = tbsKids[i];
  i += 1;
  const validityNode = tbsKids[i];
  i += 1;
  const subjectNode = tbsKids[i];
  i += 1;
  const spkiNode = tbsKids[i];
  i += 1;

  const sigOid = decodeOID(der, [...children(der, outerSigAlg)][0]);
  const innerSigOid = innerSigAlg ? decodeOID(der, [...children(der, innerSigAlg)][0]) : sigOid;
  const sig = sigAlgFromOid(sigOid);

  let notBefore = null;
  let notAfter = null;
  if (validityNode) {
    const [nb, na] = [...children(der, validityNode)];
    notBefore = nb ? decodeTime(der, nb) : null;
    notAfter = na ? decodeTime(der, na) : null;
  }

  let extensions = { san: [], keyUsage: [], extendedKeyUsage: [], isCA: false };
  for (let k = i; k < tbsKids.length; k++) {
    if (tbsKids[k].tag === 0xa3) {
      const inner = readTLV(der, tbsKids[k].valueStart);
      extensions = parseExtensions(der, inner);
    }
  }

  const subject = subjectNode ? parseName(der, subjectNode) : {};
  const issuer = issuerNode ? parseName(der, issuerNode) : {};

  return {
    version,
    serialNumber,
    subject,
    issuer,
    notBefore,
    notAfter,
    sigAlgOid: sigOid,
    innerSigAlgOid: innerSigOid,
    sigAlgName: sig.name,
    sigAlgo: sig.algo,
    sigHash: sig.hash || null,
    publicKey: spkiNode ? parseSPKI(der, spkiNode) : null,
    san: extensions.san,
    keyUsage: extensions.keyUsage,
    extendedKeyUsage: extensions.extendedKeyUsage,
    isCA: extensions.isCA,
    signatureBytes: sigValue ? sigValue.length : 0,
    derLength: der.length,
  };
}
