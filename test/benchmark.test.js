/**
 * Benchmark engine and report. The probes are injected, so these tests never
 * touch the network: the score, the sector aggregation and the HNDL arithmetic
 * are all pure functions over recorded handshake shapes.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  pool,
  expandTargets,
  classicalDebt,
  scoreTarget,
  describeTarget,
  runBenchmark,
  replayBenchmark,
} from '../src/benchmark.js';
import { buildBenchmarkHtml, buildBenchmarkCardSvg } from '../src/report/benchmark-html.js';

const NOW = new Date('2026-01-01T00:00:00Z');

function hybridTls(overrides = {}) {
  return {
    reachable: true,
    protocol: 'TLS 1.3',
    cipher: 'TLS_AES_256_GCM_SHA384',
    group: 0x11ec,
    groupLabel: 'X25519+ML-KEM-768',
    hybrid: true,
    legacyTls: [],
    ...overrides,
  };
}

function classicalTls(overrides = {}) {
  return {
    reachable: true,
    protocol: 'TLS 1.3',
    cipher: 'TLS_AES_256_GCM_SHA384',
    group: 0x001d,
    groupLabel: 'X25519',
    hybrid: false,
    legacyTls: [],
    ...overrides,
  };
}

function hybridSsh() {
  return {
    reachable: true,
    banner: 'SSH-2.0-OpenSSH_9.9',
    software: 'OpenSSH_9.9',
    hybrid: true,
    hybridAlgorithm: 'mlkem768x25519-sha256',
    kexAlgorithms: ['mlkem768x25519-sha256', 'curve25519-sha256'],
    serverHostKeyAlgorithms: ['ssh-ed25519'],
    encryption: ['chacha20-poly1305@openssh.com'],
    macs: ['hmac-sha2-256'],
  };
}

test('pool preserves order and never exceeds its width', async () => {
  let active = 0;
  let peak = 0;
  const result = await pool([1, 2, 3, 4, 5], 2, async (value) => {
    active += 1;
    peak = Math.max(peak, active);
    await new Promise((resolve) => setTimeout(resolve, 2));
    active -= 1;
    return value * 2;
  });
  assert.deepEqual(result, [2, 4, 6, 8, 10]);
  assert.equal(peak <= 2, true);
});

test('expandTargets inherits sector names and data lifetimes', () => {
  const targets = expandTargets({
    sectors: {
      health: { name: 'Healthcare', dataLifetimeYears: 25 },
      tech: { name: 'Technology', dataLifetimeYears: 7 },
    },
    targets: [
      { name: 'A', host: 'a.example', sector: 'health' },
      { name: 'B', host: 'b.example', sector: 'tech', dataLifetimeYears: 30 },
      { name: 'C', host: 'c.example', sector: 'unknown' },
    ],
  });
  assert.equal(targets[0].sectorName, 'Healthcare');
  assert.equal(targets[0].dataLifetimeYears, 25);
  assert.equal(targets[1].dataLifetimeYears, 30);
  assert.equal(targets[2].dataLifetimeYears, 7);
});

test('classicalDebt names every legacy signal', () => {
  const debt = classicalDebt({
    tls: classicalTls({ protocol: 'TLS 1.1', cipher: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', legacyTls: ['TLS 1.1'] }),
    ssh: {
      reachable: true,
      hostKeyAlgorithms: ['ssh-rsa'],
      kexAlgorithms: ['diffie-hellman-group1-sha1'],
      encryption: ['aes128-cbc'],
      macs: ['hmac-md5'],
    },
  });
  assert.ok(debt.includes('TLS 1.1'));
  assert.ok(debt.some((item) => item.includes('3DES')));
  assert.ok(debt.includes('ssh-rsa'));
  assert.ok(debt.includes('diffie-hellman-group1-sha1'));
  assert.ok(debt.includes('aes128-cbc'));
  assert.ok(debt.includes('hmac-md5'));
  // The summary string is de-duplicated but retains the weakest signals.
  assert.equal(new Set(debt).size, debt.length);
});

test('scoreTarget rewards hybrid KEX and penalises classical debt', () => {
  assert.equal(scoreTarget({ tls: hybridTls(), ssh: { reachable: false } }), 100);
  assert.equal(scoreTarget({ tls: classicalTls(), ssh: { reachable: false } }), 60);
  assert.equal(scoreTarget({ tls: { reachable: false }, ssh: hybridSsh() }), 95);
  assert.equal(
    scoreTarget({ tls: classicalTls({ protocol: 'TLS 1.1', legacyTls: ['TLS 1.1'] }), ssh: { reachable: false } }),
    30,
  );
  assert.equal(scoreTarget({ tls: { reachable: false }, ssh: { reachable: false } }), null);
});

test('describeTarget exposes the negotiated KEX and a grade', () => {
  const described = describeTarget({
    name: 'Bank',
    host: 'bank.example',
    sector: 'finance',
    sectorName: 'Finance',
    dataLifetimeYears: 10,
    tls: classicalTls({ legacyTls: ['TLS 1.0'] }),
    ssh: { reachable: false },
  });
  assert.equal(described.hybrid, false);
  assert.equal(described.hasClassical, true);
  assert.equal(described.kex, 'X25519');
  assert.equal(described.score, 55); // 60 for classical TLS, 5 for one debt signal
  assert.equal(described.grade, 'D');
  assert.equal(described.debt.length, 1);
});

test('runBenchmark aggregates sectors, adoption and HNDL exposure', async () => {
  const targets = [
    { name: 'Hybrid Bank', host: 'a.example', sector: 'finance', sectorName: 'Finance', dataLifetimeYears: 10 },
    { name: 'Classical Bank', host: 'b.example', sector: 'finance', sectorName: 'Finance', dataLifetimeYears: 10 },
    { name: 'Hybrid Git', host: 'c.example', sector: 'technology', sectorName: 'Technology', dataLifetimeYears: 5, sshProbe: true },
  ];

  const result = await runBenchmark({
    targets,
    crqcYear: 2033,
    now: NOW,
    probeTls: async (target) =>
      target.name === 'Classical Bank' ? classicalTls() : target.name === 'Hybrid Git' ? { reachable: false, error: 'no TLS' } : hybridTls(),
    probeSsh: async () => hybridSsh(),
  });

  assert.equal(result.currentYear, 2026);
  assert.equal(result.crqcYear, 2033);
  assert.equal(result.targets.length, 3);
  assert.equal(result.overall.observed, 3);
  assert.equal(result.overall.pqcHybridAdoption, 66.7);
  // Only the classical finance endpoint is exposed: 10-year lifetime + 1 > 7.
  assert.equal(result.overall.hndlExposure, 33.3);
  assert.equal(result.overall.hndlExposed, 1);
  assert.equal(result.sectors.length, 2);
  assert.equal(result.sectors[0].id, 'technology');
  assert.equal(result.sectors[0].qri, 95);
  assert.equal(result.sectors[1].qri, 80);
  assert.equal(result.sectors[1].hndlExposure, 50);
  // Leaderboard order: highest score first.
  assert.equal(result.targets[0].name, 'Hybrid Bank');
});

test('the concurrency and timeout options are honoured', async () => {
  const targets = Array.from({ length: 12 }, (_, index) => ({
    name: `Target ${index}`,
    host: `t${index}.example`,
    sector: 'technology',
    dataLifetimeYears: 7,
  }));
  let active = 0;
  let peak = 0;
  const timeouts = new Set();
  const result = await runBenchmark({
    targets,
    concurrency: 50, // capped at 10
    timeout: 1234,
    crqcYear: 2033,
    now: NOW,
    probeTls: async (_target, options) => {
      timeouts.add(options.timeout);
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 3));
      active -= 1;
      return hybridTls();
    },
  });
  assert.equal(peak <= 10, true);
  assert.deepEqual([...timeouts], [1234]);
  assert.equal(result.overall.observed, 12);
});

test('a snapshot replay reproduces the benchmark exactly', async () => {
  const targets = [
    { name: 'A', host: 'a.example', sector: 'government', sectorName: 'Government', dataLifetimeYears: 25 },
    { name: 'B', host: 'b.example', sector: 'finance', sectorName: 'Finance', dataLifetimeYears: 10 },
  ];
  const live = await runBenchmark({
    targets,
    crqcYear: 2033,
    now: NOW,
    generatedAt: NOW.toISOString(),
    probeTls: async (target) => (target.name === 'A' ? classicalTls() : hybridTls()),
  });
  const snapshot = {
    generatedAt: live.generatedAt,
    crqcYear: live.crqcYear,
    toolVersion: live.toolVersion,
    targets: live.targets.map((target) => ({
      name: target.name,
      host: target.host,
      sector: target.sector,
      sectorName: target.sectorName,
      dataLifetimeYears: target.dataLifetimeYears,
      tls: target.tls,
      ssh: target.ssh,
    })),
  };
  const replay = await replayBenchmark(snapshot);
  assert.equal(replay.overall.qri, live.overall.qri);
  assert.equal(replay.overall.hndlExposure, live.overall.hndlExposure);
  assert.deepEqual(
    replay.sectors.map((sector) => [sector.id, sector.qri]),
    live.sectors.map((sector) => [sector.id, sector.qri]),
  );
});

test('the benchmark HTML is self-contained and interactive', async () => {
  const result = await runBenchmark({
    targets: [
      { name: 'Bank <script>', host: 'bank.example', sector: 'finance', sectorName: 'Finance', dataLifetimeYears: 10 },
      { name: 'Clinic', host: 'clinic.example', sector: 'healthcare', sectorName: 'Healthcare', dataLifetimeYears: 25 },
    ],
    crqcYear: 2033,
    now: NOW,
    probeTls: async (target) => (target.name === 'Clinic' ? classicalTls() : hybridTls()),
  });
  const html = buildBenchmarkHtml({ benchmark: result, title: 'The State of Post-Quantum Readiness' });

  assert.match(html, /^<!DOCTYPE html>/);
  assert.match(html, /id="crqc"/);
  assert.match(html, /min="2027"/);
  assert.match(html, /max="2045"/);
  assert.match(html, /data-sector="finance"/);
  assert.match(html, /id="leaderboard-body"/);
  assert.match(html, /id="insight-1"/);
  assert.match(html, /id="hndl-value"/);
  assert.doesNotMatch(html, /<link[^>]+stylesheet/i);
  assert.doesNotMatch(html, /<script[^>]+src=/i);
  assert.doesNotMatch(html, /https:\/\/fonts\./i);
  // Targets are escaped before they reach the document.
  assert.doesNotMatch(html, /Bank <script>/);
  assert.match(html, /Bank \\u003cscript\\u003e/);
});

test('the social card is a standalone SVG with the benchmark headline', async () => {
  const result = await runBenchmark({
    targets: [
      { name: 'Bank', host: 'bank.example', sector: 'finance', sectorName: 'Finance', dataLifetimeYears: 10 },
      { name: 'Clinic', host: 'clinic.example', sector: 'healthcare', sectorName: 'Healthcare', dataLifetimeYears: 25 },
    ],
    crqcYear: 2033,
    now: NOW,
    probeTls: async (target) => (target.name === 'Clinic' ? classicalTls() : hybridTls()),
  });
  const svg = buildBenchmarkCardSvg({ benchmark: result });

  assert.match(svg, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg"/);
  assert.match(svg, /width="1200" height="630"/);
  assert.match(svg, /The State of Post-Quantum Readiness/);
  assert.match(svg, /GLOBAL QRI/);
  assert.match(svg, /HYBRID ADOPTION/);
  assert.match(svg, /HNDL EXPOSURE/);
  assert.match(svg, /sultanbajamil\.github\.io\/mosca\/state-of-pqc\.html/);
  assert.match(svg, /<\/svg>/);
  // No external resource is referenced.
  assert.doesNotMatch(svg, /<image|<script|href="https?:/);
});
