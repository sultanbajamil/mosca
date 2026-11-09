/**
 * MOSCA — command line interface
 * ==============================
 * Commands: scan, tls, demo, init, help.
 * No argument-parsing dependency: the grammar is small enough to own.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan, exitCode } from './index.js';
import { buildCbom } from './report/cbom.js';
import { buildSarif } from './report/sarif.js';
import { buildHtmlReport } from './report/html.js';
import { printBanner, printSummary, printFindings, printEndpoints, printSshEndpoints, printRoadmap, printNextSteps } from './report/terminal.js';
import { loadConfig, mergeConfig, CRQC_SCENARIOS } from './config.js';
import { inspectEndpoint } from './net/tls.js';
import { probeSsh, deriveSshFindings, parseSshTarget } from './net/ssh.js';
import { c, quantumColor } from './util/log.js';
import { analyse } from './analysis/risk.js';
import { buildBaseline, loadBaseline, applyBaseline } from './analysis/baseline.js';
import { RULE_COUNT } from './rules/source.js';
import { CONFIG_RULES } from './rules/config.js';
import { ALGORITHMS, lookup } from './rules/algorithms.js';

const VERSION = '2.0.0';
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, '..');

/** Parse `--flag value`, `--flag=value`, `--flag`, and positionals. */
export function parseArgs(argv) {
  const out = { _: [] };
  const takesValue = new Set([
    'tls',
    'ssh',
    'out',
    'format',
    'fail-on',
    'config',
    'scenario',
    'crqc-year',
    'shelf-life',
    'top',
    'port',
    'baseline',
    'write-baseline',
  ]);
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--') {
      out._.push(...argv.slice(i + 1));
      break;
    }
    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=');
      if (eq !== -1) {
        const key = arg.slice(2, eq);
        const value = arg.slice(eq + 1);
        out[key] = out[key] === undefined ? value : `${out[key]},${value}`;
      } else {
        const key = arg.slice(2);
        if (takesValue.has(key) && i + 1 < argv.length && !argv[i + 1].startsWith('--')) {
          const value = argv[++i];
          out[key] = out[key] === undefined ? value : `${out[key]},${value}`;
        } else {
          out[key] = true;
        }
      }
    } else if (arg.startsWith('-') && arg.length === 2) {
      out[arg.slice(1)] = true;
    } else {
      out._.push(arg);
    }
  }
  return out;
}

const HELP = `
${c.bold('MOSCA')} — post-quantum exposure scanner

${c.bold('USAGE')}
  mosca scan [path] [options]      Scan source, config, TLS and SSH
  mosca tls <host...>              Probe TLS endpoints for post-quantum readiness
  mosca ssh <host...>              Probe SSH servers for hybrid KEX and weak algorithms
  mosca explain <algorithm>        Explain an algorithm and its migration path
  mosca demo                       Scan the bundled vulnerable example
  mosca init                       Write a starter mosca.json
  mosca rules                      Show the rule inventory

${c.bold('SCAN OPTIONS')}
  --tls <host,...>        TLS endpoints to inspect (also: mosca.json "endpoints")
  --ssh <host,...>        SSH endpoints to inspect (also: mosca.json "ssh")
  --out <dir>             Output directory (default: ./mosca-report)
  --format <list>         html,json,cbom,sarif,term  (default: html,term)
  --fail-on <severity>    Exit 1 at or above: low|medium|high|critical
  --baseline <file>       Compare against a baseline; gate only on new findings
  --write-baseline <file> Write this run's findings as the new baseline
  --config <file>         Config file path
  --scenario <name>       aggressive (2029) | moderate (2033) | conservative (2038)
  --crqc-year <year>      Explicit CRQC year, overrides --scenario
  --shelf-life <years>    Default data confidentiality lifetime
  --top <n>               Findings shown in the terminal (default 20)
  --json                  Shorthand for --format json
  --quiet                 Suppress the terminal report
  --no-color              Disable ANSI colour output

${c.bold('EXAMPLES')}
  ${c.gray('# scan the current repository')}
  mosca scan

  ${c.gray('# scan source, a TLS endpoint and an SSH bastion')}
  mosca scan . --tls example.com --ssh bastion.example.com

  ${c.gray('# accept existing debt, then fail CI only on regressions')}
  mosca scan . --write-baseline .mosca-baseline.json
  mosca scan . --baseline .mosca-baseline.json --fail-on high

  ${c.gray('# explain why RSA is exposed and what replaces it')}
  mosca explain rsa

  ${c.gray('# just probe endpoints')}
  mosca tls cloudflare.com github.com
  mosca ssh git.example.com:2222
`;

export async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);

  if (args.version || args.v) {
    console.log(VERSION);
    return 0;
  }
  if (args.help || args.h || args._.length === 0) {
    printBanner(VERSION);
    console.log(HELP);
    return 0;
  }

  const command = args._[0];

  try {
    switch (command) {
      case 'scan':
        return await runScan(args, args._[1] || '.');
      case 'tls':
        return await runTls(args);
      case 'ssh':
        return await runSsh(args);
      case 'explain':
        return runExplain(args);
      case 'demo':
        return await runDemo(args);
      case 'init':
        return runInit(args);
      case 'rules':
        return runRules();
      default:
        // Treat a bare path as a scan target.
        if (fs.existsSync(command)) return await runScan(args, command);
        console.error(c.red(`Unknown command: ${command}`));
        console.log(HELP);
        return 2;
    }
  } catch (err) {
    console.error(c.red(`\n  Error: ${err.message}`));
    if (process.env.MOSCA_DEBUG) console.error(err.stack);
    return 2;
  }
}

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

async function runScan(args, target) {
  const root = path.resolve(target);
  if (!fs.existsSync(root)) {
    console.error(c.red(`  Path does not exist: ${root}`));
    return 2;
  }

  const quiet = Boolean(args.quiet);
  if (!quiet) printBanner(VERSION);

  const overrides = buildOverrides(args);
  const endpoints = splitList(args.tls);
  const sshTargets = splitList(args.ssh);

  // Load the baseline before scanning so a typo fails fast instead of after
  // a long network probe.
  const baselineDoc = args.baseline ? loadBaseline(path.resolve(args.baseline)) : null;

  const { analysis, meta, endpoints: endpointResults, sshEndpoints } = await scan({
    root,
    config: overrides,
    endpoints,
    ssh: sshTargets,
    quiet,
  });

  if (baselineDoc) applyBaseline(analysis, baselineDoc);

  const formats = args.json ? ['json'] : splitList(args.format) || ['html', 'term'];

  if (!quiet && (formats.includes('term') || formats.length === 0)) {
    printSummary(analysis, meta);
    printEndpoints(endpointResults);
    printSshEndpoints(sshEndpoints);
    printFindings(analysis.items, { limit: Number(args.top) || 20 });
    printRoadmap(analysis.roadmap);
    printNextSteps(analysis);
  }

  const outDir = path.resolve(args.out || path.join(root, 'mosca-report'));
  const written = [];

  if (formats.includes('html')) {
    fs.mkdirSync(outDir, { recursive: true });
    const html = buildHtmlReport({
      analysis,
      meta,
      endpoints: endpointResults,
      projectName: path.basename(root),
      toolVersion: VERSION,
    });
    const file = path.join(outDir, 'mosca-report.html');
    fs.writeFileSync(file, html, 'utf8');
    written.push(file);
  }
  if (formats.includes('cbom')) {
    fs.mkdirSync(outDir, { recursive: true });
    const cbom = buildCbom({ analysis, projectName: path.basename(root), toolVersion: VERSION });
    const file = path.join(outDir, 'bom.cdx.json');
    fs.writeFileSync(file, JSON.stringify(cbom, null, 2), 'utf8');
    written.push(file);
  }
  if (formats.includes('sarif')) {
    fs.mkdirSync(outDir, { recursive: true });
    const sarif = buildSarif({ analysis, root, toolVersion: VERSION });
    const file = path.join(outDir, 'mosca.sarif');
    fs.writeFileSync(file, JSON.stringify(sarif, null, 2), 'utf8');
    written.push(file);
  }
  if (formats.includes('json')) {
    const payload = { analysis, meta, endpoints: endpointResults, sshEndpoints };
    if (args.json && !args.out) {
      // Stream to stdout for piping.
      console.log(JSON.stringify(payload, null, 2));
    } else {
      fs.mkdirSync(outDir, { recursive: true });
      const file = path.join(outDir, 'mosca.json');
      fs.writeFileSync(file, JSON.stringify(payload, null, 2), 'utf8');
      written.push(file);
    }
  }

  if (args['write-baseline']) {
    const file = path.resolve(args['write-baseline']);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const doc = buildBaseline(analysis, { toolVersion: VERSION });
    fs.writeFileSync(file, JSON.stringify(doc, null, 2) + '\n', 'utf8');
    written.push(file);
  }

  if (!quiet) {
    if (written.length) {
      console.log(c.gray('  Artefacts written:'));
      for (const file of written) console.log(`    ${c.cyan('•')} ${file}`);
      console.log('');
    }
    console.log(c.gray(`  ${RULE_COUNT} source rules · ${CONFIG_RULES.length} config rules · completed in ${meta.durationMs} ms\n`));
  }

  return exitCode(analysis, args['fail-on'], { newOnly: Boolean(baselineDoc) });
}

function buildOverrides(args) {
  const overrides = {};
  if (args.scenario) {
    if (!CRQC_SCENARIOS[args.scenario]) {
      throw new Error(`Unknown scenario "${args.scenario}". Use aggressive, moderate or conservative.`);
    }
    overrides.scenario = args.scenario;
  }
  if (args['crqc-year']) overrides.crqcYear = Number(args['crqc-year']);
  if (args['shelf-life']) overrides.defaultShelfLife = Number(args['shelf-life']);
  if (args.config) {
    const { config } = loadConfig(args.config);
    return mergeConfig(config, overrides);
  }
  return overrides;
}

// ---------------------------------------------------------------------------
// tls
// ---------------------------------------------------------------------------

async function runTls(args) {
  const hosts = args._.slice(1);
  if (!hosts.length) {
    console.error(c.red('  Usage: mosca tls <host...> [--port 443]'));
    return 2;
  }
  printBanner(VERSION);
  const port = args.port ? Number(args.port) : null;
  const targets = hosts.map((h) => (port && !h.includes(':') ? `${h}:${port}` : h));

  const results = await Promise.all(targets.map((t) => inspectEndpoint(t, { timeout: 10000, legacy: true })));

  console.log(c.bold('  TLS POSTURE') + '\n');
  for (const ep of results) {
    const host = `${ep.host}${ep.port !== 443 ? `:${ep.port}` : ''}`;
    if (!ep.reachable) {
      console.log(`  ${c.red('✕')} ${c.bold(host)}  ${c.gray(ep.error || 'unreachable')}`);
      continue;
    }
    const kex = ep.hybrid ? c.green(`● ${ep.groupLabel}`) : c.red(`○ ${ep.groupLabel || ep.group || 'unknown'}`);
    const cert = ep.certificate;
    console.log(`  ${c.green('✓')} ${c.bold(host)}`);
    console.log(`      protocol   ${c.cyan(ep.protocol || '?')}`);
    console.log(`      key xchg   ${kex}${ep.hybrid ? c.gray('  (post-quantum hybrid)') : c.gray('  (breaks under Shor)')}`);
    if (ep.cipher) console.log(`      cipher     ${ep.cipher}`);
    if (cert) {
      console.log(`      cert       ${cert.signature.name} · ${cert.publicKey.label} ${cert.publicKey.bits || ''} · expires in ${cert.daysRemaining} days`);
    }
    if (ep.legacyTls?.length) console.log(`      ${c.red('legacy')}     accepts ${ep.legacyTls.join(', ')}`);
    const bad = ep.findings.filter((f) => !f.positive && f.id !== 'endpoint-hybrid-kex');
    if (bad.length) {
      for (const f of bad) console.log(`      ${c.yellow('!')} ${f.title}`);
    }
    console.log('');
  }

  // Compact verdict.
  const hybrid = results.filter((r) => r.hybrid).length;
  console.log(c.gray(`  ${hybrid} of ${results.length} endpoint${results.length === 1 ? '' : 's'} negotiate post-quantum hybrid key exchange.`));
  console.log('');
  return 0;
}

// ---------------------------------------------------------------------------
// ssh
// ---------------------------------------------------------------------------

async function runSsh(args) {
  const hosts = args._.slice(1);
  if (!hosts.length) {
    console.error(c.red('  Usage: mosca ssh <host...> [--port 22]'));
    return 2;
  }
  printBanner(VERSION);

  const results = await Promise.all(
    hosts.map(async (target) => {
      const { host, port } = parseSshTarget(args.port && !target.includes(':') ? `${target}:${args.port}` : target);
      try {
        const result = await probeSsh({ host, port, timeout: 10000 });
        return { ...result, findings: deriveSshFindings(result) };
      } catch (err) {
        return { target: `${host}:${port}`, host, port, reachable: false, error: err.message, findings: [] };
      }
    }),
  );

  console.log(c.bold('  SSH POSTURE') + '\n');
  for (const ep of results) {
    const host = `${ep.host}${ep.port !== 22 ? `:${ep.port}` : ''}`;
    if (!ep.reachable) {
      console.log(`  ${c.red('✕')} ${c.bold(host)}  ${c.gray(ep.error || 'unreachable')}`);
      continue;
    }
    const kex = ep.hybrid
      ? c.green(`● ${ep.hybridAlgorithm}`)
      : c.red(`○ ${ep.kexAlgorithms[0] || 'unknown'}`);
    console.log(`  ${c.green('✓')} ${c.bold(host)}`);
    console.log(`      banner      ${c.cyan(ep.banner || '?')}`);
    console.log(`      key xchg    ${kex}${ep.hybrid ? c.gray('  (post-quantum hybrid)') : c.gray('  (breaks under Shor)')}`);
    if (ep.serverHostKeyAlgorithms?.length) {
      console.log(`      host keys   ${ep.serverHostKeyAlgorithms.slice(0, 4).join(', ')}${ep.serverHostKeyAlgorithms.length > 4 ? c.gray(` +${ep.serverHostKeyAlgorithms.length - 4}`) : ''}`);
    }
    const bad = ep.findings.filter((f) => !f.positive);
    for (const f of bad) console.log(`      ${c.yellow('!')} ${f.title}`);
    console.log('');
  }

  const hybrid = results.filter((r) => r.hybrid).length;
  console.log(c.gray(`  ${hybrid} of ${results.length} SSH endpoint${results.length === 1 ? '' : 's'} advertise post-quantum hybrid key exchange.`));
  console.log('');
  return 0;
}

// ---------------------------------------------------------------------------
// explain
// ---------------------------------------------------------------------------

function runExplain(args) {
  const name = args._[1];
  if (!name) {
    console.error(c.red('  Usage: mosca explain <algorithm>'));
    return 2;
  }
  const algo = lookup(name);
  if (algo.id === 'unknown') {
    const needle = String(name).toLowerCase();
    const matches = Object.values(ALGORITHMS)
      .filter((a) => a.id !== 'unknown' && (a.id.includes(needle) || a.label.toLowerCase().includes(needle)))
      .slice(0, 8);
    console.error(c.red(`  Unknown algorithm: ${name}`));
    if (matches.length) {
      console.log(c.gray('  Did you mean:'));
      for (const m of matches) console.log(`    ${c.cyan(m.id)}  ${c.gray(m.label)}`);
    }
    return 2;
  }

  const replacement = algo.replacement ? lookup(algo.replacement) : null;
  if (args.json) {
    console.log(JSON.stringify({ ...algo, replacementLabel: replacement?.label || null }, null, 2));
    return 0;
  }

  const qColor = algo.quantum === 'safe' ? c.green : algo.quantum === 'weakened' ? c.yellow : c.red;
  const cColor = algo.classical === 'strong' ? c.green : algo.classical === 'acceptable' ? c.cyan : c.red;

  printBanner(VERSION);
  console.log(`  ${c.bold(algo.label)}  ${c.gray(`(${algo.id})`)}\n`);
  console.log(`  ${c.gray('Primitives')}     ${(algo.primitives || []).join(', ')}`);
  console.log(`  ${c.gray('Quantum')}        ${qColor(algo.quantum)}`);
  console.log(`  ${c.gray('Classical')}      ${cColor(algo.classical)}`);
  if (replacement) console.log(`  ${c.gray('Replace with')}   ${c.green(replacement.label)} ${c.gray(`(${replacement.id})`)}`);
  if (algo.standard) console.log(`  ${c.gray('Standard')}       ${algo.standard}`);
  if (algo.hybrid) console.log(`  ${c.gray('Hybrid form')}    ${algo.hybrid}`);
  if (algo.deprecated) console.log(`  ${c.gray('Status')}         ${c.red('deprecated')}`);
  if (algo.note) {
    console.log(`\n  ${algo.note.split('. ').join('.\n  ')}`);
  }
  console.log('');
  return 0;
}

// ---------------------------------------------------------------------------
// demo
// ---------------------------------------------------------------------------

async function runDemo(args) {
  const demoRoot = path.join(PROJECT_ROOT, 'examples', 'vulnerable-app');
  if (!fs.existsSync(demoRoot)) {
    console.error(c.red('  Demo project not found. Run from the repository root.'));
    return 2;
  }
  const outDir = path.resolve(args.out || path.join(PROJECT_ROOT, 'demo-report'));
  console.log(c.gray('  Demo: scanning examples/vulnerable-app (synthetic, intentionally insecure)\n'));
  return runScan({ ...args, out: outDir, quiet: args.quiet, _: ['scan', demoRoot] }, demoRoot);
}

// ---------------------------------------------------------------------------
// init / rules
// ---------------------------------------------------------------------------

function runInit(args) {
  const target = path.resolve(args._[1] || 'mosca.json');
  if (fs.existsSync(target) && !args.force) {
    console.error(c.red(`  ${target} already exists. Use --force to overwrite.`));
    return 2;
  }
  const template = {
    scenario: 'moderate',
    defaultShelfLife: 7,
    endpoints: [],
    ssh: [],
    ignore: [],
    failOn: null,
    dataClasses: [
      { pattern: '**/health/**', years: 25, label: 'health records' },
      { pattern: '**/pii/**', years: 15, label: 'personal data' },
      { pattern: '**/finance/**', years: 10, label: 'financial records' },
    ],
  };
  fs.writeFileSync(target, JSON.stringify(template, null, 2) + '\n', 'utf8');
  console.log(c.green(`  Wrote ${target}`));
  console.log(c.gray('  Edit "endpoints" to include live hosts, then run: mosca scan .'));
  return 0;
}

function runRules() {
  printBanner(VERSION);
  console.log(c.bold('  RULE INVENTORY') + '\n');
  console.log(`  Source rules    ${c.bold(String(RULE_COUNT))}`);
  console.log(`  Config rules    ${c.bold(String(CONFIG_RULES.length))}`);
  console.log(`  Languages       ${c.bold('16')}`);
  console.log(`  Algorithms      ${c.bold(String(Object.keys(ALGORITHMS).length))} classified in the registry`);
  console.log(`  Protocols       ${c.bold('TLS 1.0–1.3, SSH 2.0')}`);
  console.log('');
  return 0;
}

// ---------------------------------------------------------------------------

function splitList(value) {
  if (!value || value === true) return null;
  return String(value)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}
