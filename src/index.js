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
import { inspectEndpoint } from './net/tls.js';
import { analyse } from './analysis/risk.js';
import { buildCbom } from './report/cbom.js';
import { buildSarif } from './report/sarif.js';
import { buildHtmlReport } from './report/html.js';
import { loadConfig } from './config.js';
import { c } from './util/log.js';

/**
 * Run a complete MOSCA scan.
 * @param {{root?:string, config?:object, endpoints?:string[], quiet?:boolean}} opts
 */
export async function scan(opts = {}) {
  const { root = process.cwd(), config: userConfig = {}, endpoints: extraEndpoints = [], quiet = false } = opts;

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

  // ----------------------------------------------------------- analysis
  const allFindings = [...sourceResult.findings, ...configResult.findings, ...endpointResults.flatMap((e) => e.findings || [])];
  const analysis = analyse({ findings: allFindings, endpoints: endpointResults, config: mergedConfig });
  analysis.endpoints = endpointResults;

  const meta = {
    root,
    sourceStats: sourceResult.stats,
    configStats: configResult.stats,
    durationMs: Date.now() - started,
    configPath,
  };

  return { analysis, meta, endpoints: endpointResults };
}

/** Determine the process exit code from the analysis and a threshold. */
export function exitCode(analysis, failOn) {
  if (!failOn) return 0;
  const order = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const threshold = order[failOn];
  if (threshold === undefined) return 0;
  const worst = Math.max(...analysis.items.filter((i) => !i.positive).map((i) => order[i.severity] ?? 0), 0);
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
