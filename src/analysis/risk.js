/**
 * MOSCA — risk engine
 * ===================
 *
 * This is where the tool earns its name. Every finding is scored with a
 * model built on **Mosca's inequality**:
 *
 *     if (data shelf life + migration lead time) > years until a CRQC
 *         then the data is already exposed
 *
 * The inequality is the reason harvest-now-decrypt-later works: an adversary
 * records ciphertext today and waits. If the secret must stay secret for
 * longer than the machine takes to arrive, the recording is already a
 * disclosure in progress.
 *
 * The score is a weighted sum of five factors, each normalised to [0, 1]:
 *
 *   quantum     0.40  how badly the primitive falls to a quantum computer
 *   durability  0.20  how long the protected data must stay confidential
 *   breadth     0.15  how widely the primitive is used (migration cost)
 *   classical   0.15  whether it is already broken today
 *   surface     0.10  internet-facing endpoint vs. internal code
 *
 * The weights are configurable (see src/config.js) and documented in
 * docs/METHODOLOGY.md, including the reasoning for each value.
 */

import { lookup, replacementFor, QUANTUM, CLASSICAL } from '../rules/algorithms.js';
import { shelfLifeFor, resolveCrqcYear } from '../config.js';
import { fingerprint } from './baseline.js';

export const SEVERITY_ORDER = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
export const SEVERITY_LABEL = { 0: 'info', 1: 'low', 2: 'medium', 3: 'high', 4: 'critical' };

const SURFACE = { endpoint: 1, config: 0.6, source: 0.3 };
const SURFACE_WEIGHT = { endpoint: 3, config: 2, source: 1 };

const QUANTUM_FACTOR = { broken: 1, weakened: 0.5, unknown: 0.4, safe: 0 };
const CLASSICAL_FACTOR = { broken: 1, weak: 0.6, acceptable: 0.2, strong: 0 };

/** Primitives whose risk is about confidentiality (retroactive disclosure). */
const CONFIDENTIALITY = new Set(['key-agreement', 'pke', 'symmetric', 'kdf']);

/**
 * Estimate migration lead time in years from how widespread a primitive is.
 * A primitive used once can be replaced in a sprint; one used in a thousand
 * places is a multi-year programme.
 */
export function migrationLeadTime(count) {
  return 1 + Math.min(4, Math.log2(Math.max(1, count) + 1) / 2);
}

/**
 * Score one finding.
 * @param {object} f enriched finding
 * @param {{weights:object, yearsToCRQC:number}} ctx
 */
export function scoreFinding(f, ctx) {
  const w = ctx.weights;
  const q = QUANTUM_FACTOR[f.quantum] ?? 0.4;
  const dur = Math.min(1, (f.shelfLife || 0) / 30);
  const breadth = Math.min(1, Math.log2((f.count || 1) + 1) / 6);
  const cls = CLASSICAL_FACTOR[f.classical] ?? 0.2;
  const surf = SURFACE[f.kind] ?? 0.3;

  const raw =
    w.quantum * q + w.durability * dur + w.breadth * breadth + w.classical * cls + w.surface * surf;

  return Math.round(raw * 1000) / 10;
}

/** Map a score to a severity band. */
export function severityFromScore(score, f) {
  if (f.positive) return 'info';
  if (f.classical === 'broken') return 'critical';
  if (f.quantum === 'safe') return 'info';
  if (score >= 70) return 'critical';
  if (score >= 45) return 'high';
  if (score >= 25) return 'medium';
  if (score >= 10) return 'low';
  return 'info';
}

/** Move a severity up or down by one band. */
function shift(severity, delta) {
  const idx = Math.max(0, Math.min(4, SEVERITY_ORDER[severity] + delta));
  return SEVERITY_LABEL[idx];
}

/**
 * The main analysis entry point.
 *
 * @param {{findings:object[], endpoints:object[], sshEndpoints?:object[], config:object, now?:Date}} input
 */
export function analyse({ findings, endpoints = [], sshEndpoints = [], config, now = new Date() }) {
  const crqcYear = resolveCrqcYear(config);
  const currentYear = now.getUTCFullYear();
  const yearsToCRQC = Math.max(0, crqcYear - currentYear);
  const weights = config.weights;
  const liveEndpoints = [...endpoints, ...sshEndpoints];

  // ------------------------------------------------------------------ counts
  const algorithmCounts = new Map();
  for (const f of findings) {
    algorithmCounts.set(f.algorithm, (algorithmCounts.get(f.algorithm) || 0) + 1);
  }

  // ------------------------------------------------------------- enrichment
  const items = findings.map((f) => {
    const algo = lookup(f.algorithm);
    const count = algorithmCounts.get(f.algorithm) || 1;
    const isEndpoint = f.kind === 'endpoint';
    const shelf = isEndpoint
      ? { years: config.defaultShelfLife, label: 'transport payload' }
      : shelfLifeFor(f.location?.file || '', config.dataClasses, config.defaultShelfLife);

    const lead = migrationLeadTime(count);
    const exposed = shelf.years + lead > yearsToCRQC;
    const confidentiality = CONFIDENTIALITY.has(f.primitive);

    const enriched = {
      ...f,
      algorithmLabel: f.algorithmLabel || algo.label,
      quantum: f.quantum || algo.quantum,
      classical: f.classical || algo.classical,
      replacement: f.replacement || replacementFor(algo, f.primitive) || null,
      standard: f.standard || algo.standard || null,
      hybrid: algo.hybrid || null,
      count,
      shelfLife: shelf.years,
      dataClass: shelf.label,
      leadTime: Math.round(lead * 10) / 10,
      yearsToCRQC,
      mosca: {
        exposed,
        shelfLife: shelf.years,
        leadTime: Math.round(lead * 10) / 10,
        yearsToCRQC,
        inequality: `${shelf.years} + ${Math.round(lead * 10) / 10} ${exposed ? '>' : '≤'} ${yearsToCRQC}`,
        kind: confidentiality ? 'confidentiality' : 'integrity',
      },
    };
    // Stable identity for baseline diffs and SARIF deduplication. Computed
    // before sorting so it never depends on presentation order.
    enriched.fingerprint = fingerprint(enriched);

    const inherentlySafe =
      enriched.quantum === 'safe' && (enriched.classical === 'strong' || enriched.classical === 'acceptable');
    const positive = Boolean(f.positive || inherentlySafe);
    enriched.positive = positive;
    enriched.score = positive ? 0 : scoreFinding(enriched, { weights, yearsToCRQC });
    let severity = positive ? 'info' : severityFromScore(enriched.score, enriched);
    // Internet-facing and long-lived data escalates one band.
    if (!positive && isEndpoint && severity !== 'critical' && exposed) severity = shift(severity, 1);
    if (f.confidence === 'low' && !positive) severity = shift(severity, -1);
    enriched.severity = severity;
    enriched.priority = priorityFor(severity, enriched.score);
    enriched.replacementLabel = enriched.replacement ? lookup(enriched.replacement).label : null;
    return enriched;
  });

  // Sort: severity desc, then score desc, then file/line.
  items.sort((a, b) => {
    const d = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    if (d !== 0) return d;
    if (b.score !== a.score) return b.score - a.score;
    return String(a.location?.file || a.location?.host || '').localeCompare(
      String(b.location?.file || b.location?.host || ''),
    );
  });

  // ------------------------------------------------------------- aggregates
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byPrimitive = {};
  const byKind = { source: 0, config: 0, endpoint: 0 };
  const byAlgorithm = new Map();
  const byFile = new Map();

  let weightedTotal = 0;
  let weightedSafe = 0;
  let effortDays = 0;

  for (const item of items) {
    bySeverity[item.severity] = (bySeverity[item.severity] || 0) + 1;
    byPrimitive[item.primitive] = (byPrimitive[item.primitive] || 0) + 1;
    byKind[item.kind] = (byKind[item.kind] || 0) + 1;

    const w = SURFACE_WEIGHT[item.kind] || 1;
    weightedTotal += w;
    const safety = item.quantum === 'safe' ? 1 : item.quantum === 'weakened' ? 0.5 : item.quantum === 'unknown' ? 0.3 : 0;
    weightedSafe += w * safety;

    if (!item.positive) {
      const base = item.kind === 'endpoint' ? 3 : item.kind === 'config' ? 1 : 0.5;
      effortDays += base * (item.quantum === 'broken' ? 1 : 0.5);
    }

    const algo = byAlgorithm.get(item.algorithm) || {
      algorithm: item.algorithm,
      label: item.algorithmLabel,
      quantum: item.quantum,
      classical: item.classical,
      replacement: item.replacement,
      standard: item.standard,
      count: 0,
      files: new Set(),
      endpoints: new Set(),
      maxSeverity: 'info',
      maxScore: 0,
    };
    algo.count += 1;
    if (item.location?.file) algo.files.add(item.location.file);
    if (item.location?.host) algo.endpoints.add(item.location.host);
    if (SEVERITY_ORDER[item.severity] > SEVERITY_ORDER[algo.maxSeverity]) {
      algo.maxSeverity = item.severity;
      algo.replacement = item.replacement;
      algo.replacementLabel = item.replacementLabel;
    }
    if (item.score > algo.maxScore) algo.maxScore = item.score;
    byAlgorithm.set(item.algorithm, algo);

    if (item.location?.file) {
      const entry = byFile.get(item.location.file) || { file: item.location.file, count: 0, critical: 0, high: 0, maxScore: 0 };
      entry.count += 1;
      if (item.severity === 'critical') entry.critical += 1;
      if (item.severity === 'high') entry.high += 1;
      entry.maxScore = Math.max(entry.maxScore, item.score);
      byFile.set(item.location.file, entry);
    }
  }

  const quantumReadinessIndex = weightedTotal === 0 ? 100 : Math.round((weightedSafe / weightedTotal) * 1000) / 10;

  // HNDL exposure: share of inspected endpoints (TLS and SSH) whose key
  // exchange is classical-only. One recording of a classical handshake is
  // enough, whichever protocol carried it.
  const kexItems = items.filter((i) => i.kind === 'endpoint' && i.primitive === 'key-agreement');
  const classicalKex = kexItems.filter((i) => i.quantum === 'broken');
  const hndlExposure = kexItems.length === 0 ? 0 : Math.round((classicalKex.length / kexItems.length) * 1000) / 10;

  const endpointsWithPqc = liveEndpoints.filter((e) => e.hybrid).length;

  const summary = {
    generatedAt: now.toISOString(),
    crqcYear,
    yearsToCRQC,
    currentYear,
    totalFindings: items.length,
    actionable: items.filter((i) => !i.positive && i.severity !== 'info').length,
    bySeverity,
    byPrimitive,
    byKind,
    quantumReadinessIndex,
    hndlExposure,
    hndlApplicable: liveEndpoints.length > 0,
    endpointsInspected: liveEndpoints.length,
    tlsEndpoints: endpoints.length,
    sshEndpoints: sshEndpoints.length,
    endpointsWithPqc,
    exposedItems: items.filter((i) => i.mosca?.exposed && !i.positive).length,
    effortDays: Math.round(effortDays),
    sensitivity: computeSensitivity(items, currentYear),
    topRisk: items.find((i) => !i.positive) || null,
  };

  const algorithms = [...byAlgorithm.values()]
    .map((a) => ({ ...a, files: [...a.files], endpoints: [...a.endpoints] }))
    .sort((a, b) => SEVERITY_ORDER[b.maxSeverity] - SEVERITY_ORDER[a.maxSeverity] || b.count - a.count);

  const files = [...byFile.values()].sort((a, b) => b.maxScore - a.maxScore || b.count - a.count);

  return {
    items,
    summary,
    algorithms,
    files,
    roadmap: buildRoadmap(items),
    config,
  };
}

/**
 * Sensitivity analysis across plausible CRQC dates.
 *
 * The point is not to predict the date. It is to show which decisions are
 * robust: if a migration only looks urgent under the most aggressive
 * assumption, that is a very different conversation from an exposure that
 * exists under every assumption.
 *
 * @param {object[]} items enriched findings
 * @param {number} currentYear
 */
export function computeSensitivity(items, currentYear) {
  const years = [2029, 2033, 2038, 2045];
  const actionable = items.filter((i) => !i.positive && i.severity !== 'info');
  return years.map((year) => {
    const yearsToCRQC = Math.max(0, year - currentYear);
    const exposed = actionable.filter((i) => i.shelfLife + i.leadTime > yearsToCRQC).length;
    return {
      year,
      yearsToCRQC,
      exposedItems: exposed,
      exposedShare: actionable.length === 0 ? 0 : Math.round((exposed / actionable.length) * 1000) / 10,
      totalActionable: actionable.length,
    };
  });
}

function priorityFor(severity, score) {
  if (severity === 'critical') return 'P0';
  if (severity === 'high') return 'P1';
  if (severity === 'medium') return 'P2';
  if (severity === 'low') return 'P3';
  return '—';
}

/**
 * A migration roadmap ordered by dependency, not just severity: you cannot
 * deploy ML-DSA signatures before your PKI can carry them, and you cannot
 * turn on hybrid TLS before the terminator supports it.
 */
export function buildRoadmap(items) {
  const phases = [
    {
      id: 'phase-0',
      name: 'Stop the bleeding',
      window: '0–3 months',
      goal: 'Remove primitives that are broken *today*, independent of quantum computing.',
      standards: ['RFC 8996', 'NIST SP 800-131A Rev.2'],
      match: (i) => i.classical === 'broken' || i.severity === 'critical',
    },
    {
      id: 'phase-1',
      name: 'Inventory and crypto-agility',
      window: '0–6 months',
      goal: 'Produce a maintained CBOM, centralise algorithm policy, and make the stack able to swap primitives without a rewrite.',
      standards: ['CycloneDX 1.6 CBOM', 'NIST IR 8547 (draft)'],
      match: (i) => i.primitive === 'protocol' || i.primitive === 'certificate',
    },
    {
      id: 'phase-2',
      name: 'Hybrid key exchange',
      window: '3–12 months',
      goal: 'Enable X25519MLKEM768 on every internet-facing terminator and SSH bastion. This closes harvest-now-decrypt-later first, because it is the only exposure that cannot be undone later.',
      standards: ['FIPS 203', 'draft-ietf-tls-ecdhe-mlkem', 'OpenSSH 9.9+'],
      match: (i) => i.primitive === 'key-agreement' && i.quantum !== 'safe',
    },
    {
      id: 'phase-3',
      name: 'Post-quantum signatures',
      window: '6–18 months',
      goal: 'Move code signing, certificate authorities and identity tokens to ML-DSA-65, with SLH-DSA where hash-based assumptions are required.',
      standards: ['FIPS 204', 'FIPS 205', 'CNSA 2.0'],
      match: (i) => i.primitive === 'signature' && i.quantum !== 'safe',
    },
    {
      id: 'phase-4',
      name: 'Symmetric and hashing hygiene',
      window: '12–24 months',
      goal: 'AES-256 everywhere, SHA-384 or SHA3 for long-lived integrity, Argon2id for password storage.',
      standards: ['NIST SP 800-131A', 'FIPS 197', 'RFC 9106'],
      match: (i) => i.quantum === 'weakened' || i.classical === 'weak',
    },
    {
      id: 'phase-5',
      name: 'Verify and decommission',
      window: 'ongoing',
      goal: 'Re-scan continuously, pin the CBOM in CI, and retire classical-only endpoints as clients upgrade.',
      standards: ['CycloneDX', 'SARIF 2.1.0'],
      match: () => false,
    },
  ];

  const assigned = new Map(phases.map((p) => [p.id, []]));
  for (const item of items) {
    if (item.positive || item.quantum === 'safe') continue;
    const phase = phases.find((p) => p.match(item));
    if (phase) assigned.get(phase.id).push(item);
  }

  return phases.map((p) => {
    const list = assigned.get(p.id);
    return {
      id: p.id,
      name: p.name,
      window: p.window,
      goal: p.goal,
      standards: p.standards,
      count: list.length,
      items: list.slice(0, 50),
      effortDays: Math.round(
        list.reduce((sum, i) => sum + (i.kind === 'endpoint' ? 3 : i.kind === 'config' ? 1 : 0.5), 0),
      ),
    };
  });
}

/** Human-readable severity for a numeric order. */
export function severityName(order) {
  return SEVERITY_LABEL[order] || 'info';
}

export { QUANTUM, CLASSICAL };
