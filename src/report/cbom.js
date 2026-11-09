/**
 * MOSCA — CycloneDX 1.6 Cryptography Bill of Materials
 * ====================================================
 *
 * Emits a CBOM that downstream tools (Dependency-Track, sbom-tool, custom
 * policy engines) can consume. The `cryptoProperties` object follows the
 * CycloneDX 1.6 specification:
 *
 *   https://cyclonedx.org/docs/1.6/json/#components_items_cryptoProperties
 *
 * A CBOM is the artefact regulators and customers increasingly ask for.
 * Producing one from a scan is the difference between "we have a problem"
 * and "here is the inventory, with owners and locations".
 */

import crypto from 'node:crypto';
import { lookup } from '../rules/algorithms.js';

/** Map registry primitives onto the CycloneDX enum. */
const PRIMITIVE_MAP = {
  'key-agreement': 'key-agreement',
  pke: 'pke',
  signature: 'signature',
  symmetric: 'block-cipher',
  hash: 'hash',
  mac: 'mac',
  kdf: 'key-derivation',
  protocol: 'other',
  certificate: 'other',
  unknown: 'unknown',
};

/** NIST post-quantum security category (0 = not applicable). */
const NIST_LEVEL = {
  'ml-kem-512': 1,
  'ml-kem-768': 3,
  'ml-kem-1024': 5,
  'ml-dsa-44': 2,
  'ml-dsa-65': 3,
  'ml-dsa-87': 5,
  'slh-dsa-128s': 1,
  'slh-dsa-128f': 1,
  'slh-dsa-192s': 3,
  'slh-dsa-256s': 5,
  'aes-128': 1,
  'aes-128-gcm': 1,
  'aes-128-cbc': 1,
  'aes-192': 3,
  'aes-256': 5,
  'aes-256-gcm': 5,
  'aes-256-cbc': 5,
  'chacha20': 5,
  'chacha20-poly1305': 5,
  sha256: 1,
  sha384: 3,
  sha512: 5,
  'sha3-256': 1,
  'sha3-512': 5,
  'x25519mlkem768': 3,
  'mlkem768x25519-sha256': 3,
};

/** Classical security level in bits, where known. */
const CLASSICAL_BITS = {
  'aes-128': 128,
  'aes-192': 192,
  'aes-256': 256,
  'chacha20': 256,
  'chacha20-poly1305': 256,
  sha256: 128,
  sha384: 192,
  sha512: 256,
  'sha3-256': 128,
  'sha3-512': 256,
  md5: 0,
  sha1: 0,
};

/** Extract a parameter-set identifier such as "2048" or "P-256". */
function parameterSet(algo, item) {
  if (algo.id.startsWith('rsa-')) return algo.id.slice(4);
  if (algo.id.startsWith('ml-kem-')) return algo.id.slice(7);
  if (algo.id.startsWith('ml-dsa-')) return algo.id.slice(7);
  if (algo.id === 'aes-128' || algo.id === 'aes-128-gcm' || algo.id === 'aes-128-cbc') return '128';
  if (algo.id === 'aes-192') return '192';
  if (algo.id === 'aes-256' || algo.id === 'aes-256-gcm' || algo.id === 'aes-256-cbc') return '256';
  if (item?.evidence?.bits) return String(item.evidence.bits);
  return undefined;
}

function modeOf(algoId) {
  if (algoId.includes('gcm')) return 'gcm';
  if (algoId.includes('cbc')) return 'cbc';
  if (algoId.includes('ctr')) return 'ctr';
  return undefined;
}

/**
 * Build a CycloneDX 1.6 CBOM document.
 * @param {{analysis:object, projectName?:string, version?:string, toolVersion?:string}} input
 */
export function buildCbom({ analysis, projectName = 'scanned-project', version = '1.0.0', toolVersion = '1.0.0' }) {
  const components = [];
  const seen = new Set();

  for (const item of analysis.items) {
    const algo = lookup(item.algorithm);
    if (algo.id === 'unknown') continue;
    const ref = `crypto/algorithm/${algo.id}`;
    if (seen.has(ref)) {
      const existing = components.find((c) => c['bom-ref'] === ref);
      if (existing) {
        existing.evidence.occurrences = (existing.evidence.occurrences || 0) + 1;
        if (item.location?.file && !existing.properties.some((p) => p.value === item.location.file)) {
          existing.properties.push({ name: 'mosca:location', value: item.location.file });
        }
      }
      continue;
    }
    seen.add(ref);

    const props = [
      { name: 'mosca:quantumStatus', value: item.quantum },
      { name: 'mosca:classicalStatus', value: item.classical },
      { name: 'mosca:severity', value: item.severity },
      { name: 'mosca:primitive', value: item.primitive },
    ];
    if (item.replacement) props.push({ name: 'mosca:replacement', value: item.replacement });
    if (item.standard) props.push({ name: 'mosca:standard', value: item.standard });
    if (item.mosca) props.push({ name: 'mosca:moscaInequality', value: item.mosca.inequality });
    if (item.location?.file) props.push({ name: 'mosca:location', value: item.location.file });

    components.push({
      type: 'cryptographic-asset',
      'bom-ref': ref,
      name: algo.label,
      description: algo.note || undefined,
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: PRIMITIVE_MAP[item.primitive] || 'other',
          parameterSetIdentifier: parameterSet(algo, item),
          curve: item.evidence?.curve || undefined,
          executionEnvironment: 'software-plain-software',
          implementationPlatform: item.language || 'unknown',
          certificationLevel: algo.standard?.includes('FIPS') ? ['fips140-2'] : [],
          mode: modeOf(algo.id),
          padding: algo.id.includes('cbc') ? 'pkcs7' : 'none',
          cryptoFunctions: functionsFor(item.primitive),
          classicalSecurityLevel: CLASSICAL_BITS[algo.id] ?? undefined,
          nistQuantumSecurityLevel: NIST_LEVEL[algo.id] ?? 0,
        },
      },
      properties: props,
      evidence: {
        occurrences: 1,
        identity: { field: 'name', confidence: 0.9, concludedValue: algo.label },
      },
    });
  }

  // Certificates observed on live endpoints become first-class assets.
  for (const ep of analysis.endpoints || []) {
    if (!ep.certificate) continue;
    const cert = ep.certificate;
    const ref = `crypto/certificate/${ep.host}:${ep.port}`;
    components.push({
      type: 'cryptographic-asset',
      'bom-ref': ref,
      name: `Certificate ${cert.subject}`,
      cryptoProperties: {
        assetType: 'certificate',
        certificateProperties: {
          subjectName: cert.subject,
          issuerName: cert.issuer,
          notValidBefore: cert.notBefore ? cert.notBefore.toISOString() : undefined,
          notValidAfter: cert.notAfter ? cert.notAfter.toISOString() : undefined,
          signatureAlgorithmRef: `crypto/algorithm/${cert.signature.algorithm}`,
          subjectPublicKeyRef: `crypto/algorithm/${cert.publicKey.algorithm}`,
          certificateFormat: 'X.509',
        },
      },
      properties: [
        { name: 'mosca:endpoint', value: `${ep.host}:${ep.port}` },
        { name: 'mosca:signatureAlgorithm', value: cert.signature.name },
        { name: 'mosca:publicKeyAlgorithm', value: `${cert.publicKey.label}${cert.publicKey.bits ? ` ${cert.publicKey.bits}` : ''}` },
      ],
    });
  }

  // Protocols.
  const protocolSeen = new Set();
  for (const ep of analysis.endpoints || []) {
    if (!ep.protocol || protocolSeen.has(ep.protocol)) continue;
    protocolSeen.add(ep.protocol);
    const id = ep.protocol.replace(/\s+/g, '-').toLowerCase();
    components.push({
      type: 'cryptographic-asset',
      'bom-ref': `crypto/protocol/${id}`,
      name: ep.protocol,
      cryptoProperties: {
        assetType: 'protocol',
        protocolProperties: {
          type: 'tls',
          version: ep.protocol.replace('TLS ', ''),
          cipherSuites: ep.cipher
            ? [{ name: ep.cipher, algorithms: [{ ref: 'crypto/algorithm/aes-128-gcm' }] }]
            : [],
        },
      },
      properties: [
        { name: 'mosca:keyExchangeGroup', value: ep.group || 'unknown' },
        { name: 'mosca:hybridKeyExchange', value: String(ep.hybrid) },
      ],
    });
  }

  const bom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: analysis.summary.generatedAt,
      tools: {
        components: [
          {
            type: 'application',
            name: 'mosca',
            version: toolVersion,
            description: 'Post-quantum cryptography exposure scanner',
          },
        ],
      },
      component: {
        type: 'application',
        name: projectName,
        version,
      },
      properties: [
        { name: 'mosca:quantumReadinessIndex', value: String(analysis.summary.quantumReadinessIndex) },
        { name: 'mosca:crqcYear', value: String(analysis.summary.crqcYear) },
        {
          name: 'mosca:harvestNowDecryptLaterExposure',
          value: analysis.summary.hndlApplicable ? `${analysis.summary.hndlExposure}%` : 'n/a',
        },
      ],
    },
    components,
  };

  return bom;
}

function functionsFor(primitive) {
  switch (primitive) {
    case 'symmetric': return ['encrypt', 'decrypt'];
    case 'hash': return ['digest'];
    case 'mac': return ['sign', 'verify'];
    case 'signature': return ['sign', 'verify'];
    case 'key-agreement': return ['keygen', 'derive'];
    case 'pke': return ['encrypt', 'decrypt'];
    case 'kdf': return ['derive'];
    default: return [];
  }
}
