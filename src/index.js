/**
 * MOSCA — main entry point
 * ========================
 * Orchestrates source scan, config scan, endpoint inspection, risk analysis
 * and reporting.
 */

import path from 'node:path';
import fs from 'node:fs';
import { scanSourceDirectory } from './scan/source.js';
import { scanConfigDirectory } from './scan/config.js';
import { scanArtifactsDirectory } from './scan/artifacts.js';
import { scanDependenciesDirectory } from './scan/deps.js';
import { inspectEndpoint } from './net/tls.js';
import { probeSsh, deriveSshFindings, parseSshTarget } from './net/ssh.js';
import { inspectStarttls } from './net/starttls.js';
import { inspectQuic } from './net/quic.js';
import { inspectIkev2 } from './net/ikev2.js';
import { analyse } from './analysis/risk.js';
import { buildCbom } from './report/cbom.js';
import { buildSarif } from './report/sarif.js';
import { buildHtmlReport } from './report/html.js';
import { loadConfig } from './config.js';
import { c } from './util/log.js';

/**
 * Run a complete MOSCA scan.
 * @param {{root?:string, config?:object, endpoints?:string[], ssh?:string[], quiet?:boolean}} opts
 */
export async function scan(opts = {}) {
  const {
    root = process.cwd(),
    config: userConfig = {},
    endpoints: extraEndpoints = [],
    ssh: extraSsh = [],
    starttls: extraStarttls = [],
    quic: extraQuic = [],
    ikev2: extraIkev2 = [],
    quiet = false,
  } = opts;

  const started = Date.now();
  const { config, path: configPath } = loadConfig(path.join(root, 'mosca.json'));
  const mergedConfig = { ...config, ...userConfig };

  // ------------------------------------------------------------ source scan
  let sourceResult = {
    findings: [],
    stats: { filesScanned: 0, bytesScanned: 0, byLanguage: {}, byFile: {}, totalFiles: 0 },
  };
  const progress = (msg) => {
    if (!quiet && process.stderr.isTTY) process.stderr.write(c.gray(`  ${msg}\r`));
  };
  if (isDirectory(root)) {
    progress('scanning source…');
    sourceResult = scanSourceDirectory(root, { ignore: mergedConfig.ignore, maxFiles: 50000 });
  }

  // ------------------------------------------------------------ config scan
  let configResult = { findings: [], stats: { filesScanned: 0, byFile: {} } };
  if (isDirectory(root)) {
    progress('scanning configuration…');
    configResult = scanConfigDirectory(root, { ignore: mergedConfig.ignore, maxFiles: 50000 });
  }

  // ---------------------------------------------------------- artifact scan
  let artifactResult = { findings: [], stats: { filesScanned: 0, byType: {}, totalFiles: 0 } };
  if (isDirectory(root) && mergedConfig.artifacts !== false) {
    progress('scanning key and certificate artifacts…');
    artifactResult = scanArtifactsDirectory(root, { ignore: mergedConfig.ignore, maxFiles: 50000 });
  }

  // -------------------------------------------------------- dependency scan
  let dependencyResult = { findings: [], packages: [], stats: { filesScanned: 0, packagesMatched: 0, totalFiles: 0 } };
  if (isDirectory(root) && mergedConfig.dependencies !== false) {
    progress('scanning cryptographic dependencies…');
    dependencyResult = scanDependenciesDirectory(root, { ignore: mergedConfig.ignore, maxFiles: 50000 });
  }

  // ---------------------------------------------------------- endpoint scan
  const requestedEndpoints = Array.isArray(extraEndpoints) ? extraEndpoints : [];
  const allEndpoints = [...(mergedConfig.endpoints || []), ...requestedEndpoints].filter(Boolean);
  let endpointResults = [];
  if (allEndpoints.length > 0) {
    progress(`inspecting ${allEndpoints.length} endpoint(s)…`);
    endpointResults = await Promise.all(
      allEndpoints.map((t) =>
        inspectEndpoint(t, { timeout: 10000, legacy: true }).catch((err) => ({
          target: String(t),
          host: String(t).split(':')[0],
          port: 443,
          reachable: false,
          error: err.message,
          findings: [],
        })),
      ),
    );
  }
  if (!quiet && process.stderr.isTTY) process.stderr.write(' '.repeat(40) + '\r');

  // -------------------------------------------------------------- SSH scan
  const requestedSsh = Array.isArray(extraSsh) ? extraSsh : [];
  const allSsh = [...(mergedConfig.ssh || []), ...requestedSsh].filter(Boolean);
  let sshResults = [];
  if (allSsh.length > 0) {
    progress(`inspecting ${allSsh.length} SSH endpoint(s)…`);
    sshResults = await Promise.all(
      allSsh.map(async (target) => {
        const { host, port } = parseSshTarget(target);
        try {
          const result = await probeSsh({ host, port, timeout: 8000 });
          return { ...result, findings: deriveSshFindings(result) };
        } catch (err) {
          return {
            target: String(target),
            host,
            port,
            reachable: false,
            error: err.message,
            kexAlgorithms: [],
            serverHostKeyAlgorithms: [],
            encryption: [],
            macs: [],
            hybrid: false,
            findings: [],
          };
        }
      }),
    );
  }
  if (!quiet && process.stderr.isTTY) process.stderr.write(' '.repeat(40) + '\r');

  // ------------------------------------------------- STARTTLS / QUIC / IKEv2
  const requestedStarttls = Array.isArray(extraStarttls) ? extraStarttls : [];
  const allStarttls = [...(mergedConfig.starttls || []), ...requestedStarttls].filter(Boolean);
  let starttlsResults = [];
  if (allStarttls.length > 0) {
    progress(`inspecting ${allStarttls.length} STARTTLS endpoint(s)…`);
    starttlsResults = await Promise.all(
      allStarttls.map((target) =>
        inspectStarttls(target, { timeout: 10000 }).catch((err) => ({
          target: String(target),
          protocol: 'smtp',
          host: String(target),
          port: null,
          reachable: false,
          error: err.message,
          findings: [],
        })),
      ),
    );
  }

  const requestedQuic = Array.isArray(extraQuic) ? extraQuic : [];
  const allQuic = [...(mergedConfig.quic || []), ...requestedQuic].filter(Boolean);
  let quicResults = [];
  if (allQuic.length > 0) {
    progress(`inspecting ${allQuic.length} QUIC endpoint(s)…`);
    quicResults = await Promise.all(
      allQuic.map((target) =>
        inspectQuic(target, { timeout: 10000 }).catch((err) => ({
          target: String(target),
          host: String(target),
          port: 443,
          reachable: false,
          error: err.message,
          findings: [],
        })),
      ),
    );
  }

  const requestedIkev2 = Array.isArray(extraIkev2) ? extraIkev2 : [];
  const allIkev2 = [...(mergedConfig.ikev2 || []), ...requestedIkev2].filter(Boolean);
  let ikev2Results = [];
  if (allIkev2.length > 0) {
    progress(`inspecting ${allIkev2.length} IKEv2 gateway(s)…`);
    ikev2Results = await Promise.all(
      allIkev2.map((target) =>
        inspectIkev2(target, { timeout: 4000 }).catch((err) => ({
          target: String(target),
          host: String(target),
          port: 500,
          reachable: false,
          error: err.message,
          findings: [],
        })),
      ),
    );
  }
  if (!quiet && process.stderr.isTTY) process.stderr.write(' '.repeat(40) + '\r');

  // ----------------------------------------------------------- analysis
  const allFindings = [
    ...sourceResult.findings,
    ...configResult.findings,
    ...artifactResult.findings,
    ...dependencyResult.findings,
    ...endpointResults.flatMap((e) => e.findings || []),
    ...sshResults.flatMap((e) => e.findings || []),
    ...starttlsResults.flatMap((e) => e.findings || []),
    ...quicResults.flatMap((e) => e.findings || []),
    ...ikev2Results.flatMap((e) => e.findings || []),
  ];
  const analysis = analyse({ findings: allFindings, endpoints: endpointResults, sshEndpoints: sshResults, config: mergedConfig });
  analysis.endpoints = endpointResults;
  analysis.sshEndpoints = sshResults;
  analysis.starttlsEndpoints = starttlsResults;
  analysis.quicEndpoints = quicResults;
  analysis.ikev2Endpoints = ikev2Results;
  analysis.artifacts = artifactResult;
  analysis.dependencies = dependencyResult;

  const meta = {
    root,
    sourceStats: sourceResult.stats,
    configStats: configResult.stats,
    artifactStats: artifactResult.stats,
    dependencyStats: dependencyResult.stats,
    dependencyPackages: dependencyResult.packages,
    durationMs: Date.now() - started,
    configPath,
  };

  return {
    analysis,
    meta,
    endpoints: endpointResults,
    sshEndpoints: sshResults,
    starttlsEndpoints: starttlsResults,
    quicEndpoints: quicResults,
    ikev2Endpoints: ikev2Results,
    artifacts: artifactResult,
    dependencies: dependencyResult,
  };
}

/** Determine the process exit code from the analysis and a threshold. */
export function exitCode(analysis, failOn, { newOnly = false } = {}) {
  if (!failOn) return 0;
  const order = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const threshold = order[failOn];
  if (threshold === undefined) return 0;
  const considered = analysis.items.filter(
    (i) => !i.positive && (!newOnly || i.baselineStatus === 'new'),
  );
  const worst = Math.max(...considered.map((i) => order[i.severity] ?? 0), 0);
  return worst >= threshold ? 1 : 0;
}

/** True when `p` is a directory. */
function isDirectory(p) {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
}

export { buildHtmlReport, buildCbom, buildSarif, analyse };
export { buildBaseline, loadBaseline, applyBaseline, fingerprint } from './analysis/baseline.js';
