/**
 * MOSCA — global PQC readiness benchmark
 * ======================================
 *
 * A single scan answers "is this host ready?". A benchmark answers the
 * question executives and journalists actually ask: "how ready is the sector,
 * and when does its data become readable?".
 *
 * The engine is deliberately small and injectable: `runBenchmark` accepts the
 * two probe functions, a concurrency limit and a timeout, so the aggregation,
 * grading and HTML rendering can be tested without touching the network.
 */

import { inspectEndpoint } from './net/tls.js';
import {
  probeSsh,
  LEGACY_HOST_KEYS,
  WEAK_KEX,
  WEAK_CIPHERS,
  WEAK_MACS,
} from './net/ssh.js';
import { gradeFor } from './report/badge.js';

export const DEFAULT_CONCURRENCY = 10;
export const DEFAULT_TIMEOUT = 5000;
export const DEFAULT_MIGRATION_LEAD = 1;

const TLS_WEAK_CIPHER = /RC4|3DES|DES_|_DES|NULL|EXPORT/i;

function clamp(value, min = 0, max = 100) {
  return Math.max(min, Math.min(max, value));
}

function avg(values) {
  if (!values.length) return 0;
  return Math.round((values.reduce((sum, value) => sum + value, 0) / values.length) * 10) / 10;
}

function pct(part, total) {
  return total === 0 ? 0 : Math.round((part / total) * 1000) / 10;
}

/** Run an async worker pool; results keep input order. */
export async function pool(items, limit, worker) {
  const results = new Array(items.length);
  let next = 0;
  const width = Math.max(1, Math.min(limit, items.length));
  async function run() {
    while (true) {
      const index = next++;
      if (index >= items.length) return;
      results[index] = await worker(items[index], index);
    }
  }
  await Promise.all(Array.from({ length: width }, run));
  return results;
}

/** Normalise a live TLS record into the benchmark shape. */
function normaliseTls(result) {
  if (!result) return { reachable: false, error: 'no result' };
  return {
    reachable: Boolean(result.reachable),
    error: result.error || null,
    protocol: result.protocol || null,
    cipher: result.cipher || null,
    group: result.group || null,
    groupLabel: result.groupLabel || result.group || null,
    hybrid: Boolean(result.hybrid),
    serverPrefersHybrid: Boolean(result.serverPrefersHybrid),
    legacyTls: result.legacyTls || [],
  };
}

/** Normalise a live SSH record into the benchmark shape. */
function normaliseSsh(result) {
  if (!result) return { reachable: false, error: 'no result' };
  const kex = result.kexAlgorithms || [];
  const hybridAlgorithm = result.hybridAlgorithm || kex.find((name) => /mlkem|sntrup/i.test(name)) || null;
  return {
    reachable: Boolean(result.reachable),
    error: result.error || null,
    banner: result.banner || null,
    software: result.software || null,
    hybrid: Boolean(result.hybrid || hybridAlgorithm),
    hybridAlgorithm,
    agreedKex: hybridAlgorithm || kex[0] || null,
    kexAlgorithms: kex,
    hostKeyAlgorithms: result.serverHostKeyAlgorithms || [],
    encryption: result.encryption || [],
    macs: result.macs || [],
  };
}

/** Enumerate the classical debt a single target still carries. */
export function classicalDebt(target) {
  const debt = [];
  const tls = target.tls || {};
  const ssh = target.ssh || {};
  if (tls.reachable) {
    if (tls.protocol === 'TLS 1.0' || tls.protocol === 'TLS 1.1') debt.push(tls.protocol);
    if (tls.cipher && TLS_WEAK_CIPHER.test(tls.cipher)) debt.push(tls.cipher);
    if (tls.legacyTls?.length) debt.push(`accepts ${tls.legacyTls.join('/')}`);
  }
  if (ssh.reachable) {
    const legacyHost = (ssh.hostKeyAlgorithms || []).find((name) => LEGACY_HOST_KEYS.has(name));
    if (legacyHost) debt.push(legacyHost);
    const weakKex = (ssh.kexAlgorithms || []).find((name) => WEAK_KEX.has(name));
    if (weakKex) debt.push(weakKex);
    const weakCipher = (ssh.encryption || []).find((name) => WEAK_CIPHERS.has(name));
    if (weakCipher) debt.push(weakCipher);
    const weakMac = (ssh.macs || []).find((name) => WEAK_MACS.has(name));
    if (weakMac) debt.push(weakMac);
  }
  return [...new Set(debt)];
}

/**
 * Score one target 0–100. The weights prioritise key exchange because it is
 * the only debt that cannot be repaired after a recording has been made.
 */
export function scoreTarget(target) {
  const tls = target.tls || {};
  const ssh = target.ssh || {};
  if (!tls.reachable && !ssh.reachable) return null;
  let score = 100;
  if (tls.reachable) {
    if (!tls.hybrid) score -= 40;
    if (tls.protocol === 'TLS 1.0' || tls.protocol === 'TLS 1.1') score -= 20;
    if (tls.cipher && TLS_WEAK_CIPHER.test(tls.cipher)) score -= 15;
  } else {
    score -= 5;
  }
  if (ssh.reachable) {
    if (!ssh.hybrid) score -= 15;
  }
  const debt = classicalDebt(target);
  score -= Math.min(20, debt.length * 5);
  return clamp(Math.round(score));
}

/** Build the per-target view used by the leaderboard and the HTML page. */
export function describeTarget(target) {
  const tls = normaliseTls(target.tls);
  const ssh = normaliseSsh(target.ssh);
  const reachable = tls.reachable || ssh.reachable;
  const hasClassical = (tls.reachable && !tls.hybrid) || (ssh.reachable && !ssh.hybrid);
  const hybrid = (tls.reachable && tls.hybrid) || (ssh.reachable && ssh.hybrid);
  const debt = classicalDebt({ tls, ssh });
  const score = scoreTarget({ tls, ssh });
  const grade = score == null ? { grade: '—', label: 'Not observed', color: '#5d6a82' } : gradeFor(score);
  const kex = tls.reachable
    ? tls.groupLabel || tls.group || 'unknown'
    : ssh.reachable
      ? ssh.agreedKex || 'unknown'
      : 'unknown';
  return {
    name: target.name || target.host,
    host: target.host,
    sector: target.sector,
    sectorName: target.sectorName,
    dataLifetimeYears: Number(target.dataLifetimeYears) || 7,
    reachable,
    hybrid,
    hasClassical,
    tls,
    ssh,
    kex,
    sshKex: ssh.agreedKex || null,
    protocol: tls.protocol || (ssh.reachable ? 'SSH 2.0' : null),
    debt,
    score,
    grade: grade.grade,
    gradeLabel: grade.label,
    gradeColor: grade.color,
    error: tls.error || ssh.error || null,
  };
}

/** Aggregate a sector, including the HNDL exposure at a CRQC assumption. */
export function aggregateSector(id, name, targets, { crqcYear, currentYear, dataLifetimeYears = 7 }) {
  const observed = targets.filter((target) => target.score != null);
  const hybrid = observed.filter((target) => target.hybrid);
  const classical = observed.filter((target) => target.hasClassical);
  const yearsToCRQC = Math.max(0, crqcYear - currentYear);
  const hndlExposed = classical.filter(
    (target) => (Number(target.dataLifetimeYears) || dataLifetimeYears) + DEFAULT_MIGRATION_LEAD > yearsToCRQC,
  );
  const groupDistribution = {};
  for (const target of observed) {
    const key = target.tls?.hybrid
      ? target.tls.groupLabel || 'Hybrid KEM'
      : target.tls?.groupLabel || target.sshKex || 'unknown';
    groupDistribution[key] = (groupDistribution[key] || 0) + 1;
  }
  const debt = {};
  for (const target of observed) {
    for (const item of target.debt) debt[item] = (debt[item] || 0) + 1;
  }
  const score = avg(observed.map((target) => target.score));
  const grade = observed.length ? gradeFor(score) : { grade: '—', label: 'No data', color: '#5d6a82' };
  return {
    id,
    name,
    dataLifetimeYears,
    total: targets.length,
    observed: observed.length,
    unreachable: targets.length - observed.length,
    qri: score,
    grade: grade.grade,
    gradeLabel: grade.label,
    gradeColor: grade.color,
    pqcHybridAdoption: pct(hybrid.length, observed.length),
    hndlExposure: pct(hndlExposed.length, observed.length),
    hndlExposed: hndlExposed.length,
    hybridTargets: hybrid.length,
    groupDistribution,
    debt,
    targets: targets.map((target) => target.name),
  };
}

/**
 * Expand a `benchmarks/targets.json`-shaped document so every target carries
 * its sector name and confidentiality lifetime. Keeping this in the engine
 * means the CLI, the script and the tests all interpret the file the same way.
 * @param {{targets?:object[], sectors?:object}} document
 */
export function expandTargets(document = {}) {
  const sectors = document.sectors || {};
  return (document.targets || []).map((target) => {
    const meta = sectors[target.sector] || {};
    const lifetime = Number(target.dataLifetimeYears ?? meta.dataLifetimeYears);
    return {
      ...target,
      sectorName: target.sectorName || meta.name || target.sector,
      dataLifetimeYears: Number.isFinite(lifetime) && lifetime > 0 ? lifetime : 7,
    };
  });
}

/**
 * Evaluate one target with two probe functions. Both are injected so the
 * engine can be tested, mocked or run against a replayed snapshot.
 */
export async function evaluateTarget(target, { probeTls, probeSsh, timeout = DEFAULT_TIMEOUT } = {}) {
  const sshRequest =
    target.sshProbe === true && probeSsh
      ? probeSsh(target, { timeout })
      : Promise.resolve({ reachable: false, error: 'SSH not probed' });
  const [tls, ssh] = await Promise.allSettled([
    probeTls ? probeTls(target, { timeout }) : Promise.reject(new Error('no TLS probe supplied')),
    sshRequest,
  ]);
  return {
    ...target,
    tls: tls.status === 'fulfilled' ? tls.value : { reachable: false, error: tls.reason?.message || String(tls.reason) },
    ssh: ssh.status === 'fulfilled' ? ssh.value : { reachable: false, error: ssh.reason?.message || String(ssh.reason) },
  };
}

/**
 * Run the whole benchmark.
 * @param {{targets:object[], probeTls?:Function, probeSsh?:Function, concurrency?:number, timeout?:number, crqcYear?:number, now?:Date, toolVersion?:string, generatedAt?:string}} opts
 */
export async function runBenchmark({
  targets = [],
  probeTls,
  probeSsh,
  concurrency = DEFAULT_CONCURRENCY,
  timeout = DEFAULT_TIMEOUT,
  crqcYear = 2033,
  now = new Date(),
  toolVersion = '3.1.0',
  generatedAt = null,
} = {}) {
  const currentYear = now.getUTCFullYear();
  const evaluated = await pool(targets, Math.max(1, Math.min(10, concurrency)), (target) =>
    evaluateTarget(target, { probeTls, probeSsh, timeout }),
  );
  const described = evaluated.map(describeTarget);
  const grouped = new Map();
  for (const target of described) {
    if (!grouped.has(target.sector)) grouped.set(target.sector, { name: target.sectorName, dataLifetimeYears: target.dataLifetimeYears, targets: [] });
    grouped.get(target.sector).targets.push(target);
  }
  const sectors = [...grouped.entries()].map(([id, group]) =>
    aggregateSector(id, group.name || id, group.targets, {
      crqcYear,
      currentYear,
      dataLifetimeYears: group.dataLifetimeYears,
    }),
  ).sort((a, b) => b.qri - a.qri || a.name.localeCompare(b.name));

  const overall = aggregateSector('global', 'Global', described, {
    crqcYear,
    currentYear,
    dataLifetimeYears: avg(described.map((target) => target.dataLifetimeYears)) || 7,
  });

  return {
    title: 'The State of Post-Quantum Readiness',
    generatedAt: generatedAt || now.toISOString(),
    currentYear,
    crqcYear,
    toolVersion,
    concurrency,
    timeout,
    targets: described.sort((a, b) => (b.score ?? -1) - (a.score ?? -1) || a.name.localeCompare(b.name)),
    sectors,
    overall,
  };
}

/** Live probes used by the CLI and `scripts/benchmark-world.js`. */
export function liveProbes() {
  return {
    probeTls: async (target, { timeout }) =>
      normaliseTls(await inspectEndpoint(`${target.host}${target.port ? `:${target.port}` : ''}`, { timeout, legacy: false })),
    probeSsh: async (target, { timeout }) =>
      normaliseSsh(await probeSsh({ host: target.host, port: target.sshPort || 22, timeout, clientVersion: 'MOSCA_3.1' })),
  };
}

/** Build the report from a replay snapshot with raw probe results. */
export function replayBenchmark(snapshot) {
  const raw = new Map();
  for (const target of snapshot.targets || []) raw.set(target.name || target.host, target);
  return runBenchmark({
    targets: (snapshot.targets || []).map((target) => ({ ...target, sshProbe: true })),
    probeTls: async (target) => {
      const entry = raw.get(target.name || target.host);
      return entry?.tls || { reachable: false, error: 'not recorded' };
    },
    probeSsh: async (target) => {
      const entry = raw.get(target.name || target.host);
      return entry?.ssh || { reachable: false, error: 'not recorded' };
    },
    crqcYear: snapshot.crqcYear || 2033,
    now: snapshot.generatedAt ? new Date(snapshot.generatedAt) : new Date(),
    generatedAt: snapshot.generatedAt,
    toolVersion: snapshot.toolVersion || '3.1.0',
  });
}

export { gradeFor };
