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
import { printBanner, printSummary, printFindings, printEndpoints, printSshEndpoints, printCaptureSummary, printRoadmap, printNextSteps } from './report/terminal.js';
import { loadConfig, mergeConfig, CRQC_SCENARIOS } from './config.js';
import { inspectEndpoint } from './net/tls.js';
import { probeSsh, deriveSshFindings, parseSshTarget } from './net/ssh.js';
import { c, quantumColor, padEnd } from './util/log.js';
import { analyse } from './analysis/risk.js';
import { buildBaseline, loadBaseline, applyBaseline } from './analysis/baseline.js';
import { COMPLIANCE_IDS, evaluateAllCompliance } from './analysis/compliance.js';
import { buildFixPlan, buildPatch, renderFixReport } from './fix.js';
import { buildMermaid, buildMermaidMarkdown } from './report/mermaid.js';
import { inspectStarttls } from './net/starttls.js';
import { inspectQuic } from './net/quic.js';
import { inspectIkev2 } from './net/ikev2.js';
import { analysePcapFile, summariseCaptures } from './net/pcap.js';
import { writeBadges } from './report/badge.js';
import { runBenchmark, replayBenchmark, expandTargets, liveProbes } from './benchmark.js';
import { buildBenchmarkHtml } from './report/benchmark-html.js';
import { RULE_COUNT } from './rules/source.js';
import { CONFIG_RULES } from './rules/config.js';
import { ALGORITHMS, lookup } from './rules/algorithms.js';

const VERSION = '3.1.0';
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, '..');

/** Parse `--flag value`, `--flag=value`, `--flag`, and positionals. */
export function parseArgs(argv) {
  const out = { _: [] };
  const takesValue = new Set([
    'tls',
    'ssh',
    'starttls',
    'quic',
    'ikev2',
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
    'compliance',
    'fail-on-compliance',
    'fix-out',
    'addke',
    'pcap',
    'badge',
    'targets',
    'snapshot',
    'concurrency',
    'timeout',
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
  mosca scan [path] [options]      Scan source, config, artefacts, dependencies, TLS and SSH
  mosca tls <host...>              Probe TLS endpoints for post-quantum readiness
  mosca ssh <host...>              Probe SSH servers for hybrid KEX and weak algorithms
  mosca starttls <target...>       Probe SMTP, IMAP, POP3, PostgreSQL and LDAP STARTTLS
  mosca quic <host...>             Probe QUIC / HTTP/3 with a protected Initial packet
  mosca ikev2 <host...>            Probe IPsec gateways for RFC 9370 hybrid key exchange
  mosca pcap <file.pcap>           Harvest TLS and SSH handshakes from a recorded capture
  mosca benchmark [options]        Scan the global PQC readiness benchmark
  mosca fix [path]                 Propose a patch for automatic fixes and advisories for the rest
  mosca explain <algorithm>        Explain an algorithm and its migration path
  mosca demo                       Scan the bundled vulnerable example
  mosca init                       Write a starter mosca.json
  mosca rules                      Show the rule inventory

${c.bold('SCAN OPTIONS')}
  --tls <host,...>        TLS endpoints to inspect (also: mosca.json "endpoints")
  --ssh <host,...>        SSH endpoints to inspect (also: mosca.json "ssh")
  --starttls <target,...> STARTTLS targets: smtp://, imap://, pop3://, postgres://, ldap://
  --quic <host,...>       QUIC / HTTP/3 endpoints to inspect
  --ikev2 <host,...>      IKEv2 gateways to inspect for RFC 9370 hybrid KEX
  --pcap <file,...>       PCAP/PCAPNG captures to harvest for recorded TLS and SSH sessions
  --badge <dir>           Write mosca-qri-badge.svg and mosca-hndl-badge.svg
  --out <dir>             Output directory (default: ./mosca-report)
  --format <list>         html,json,cbom,sarif,term,mermaid  (default: html,term)
  --fail-on <severity>    Exit 1 at or above: low|medium|high|critical
  --compliance <id>       Compliance report: cnsa2 | nist-2030 | pci-dss | hipaa | all
  --fail-on-compliance <id>
                          Exit 1 when the selected standard fails
  --fix                   Write a proposed patch and print the fix plan
  --fix-out <file>        Patch path (default: <out>/mosca-fix.patch)
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

${c.bold('BENCHMARK OPTIONS')}
  --targets <file>        Target document (default: benchmarks/targets.json)
  --snapshot <file>       Replay recorded results instead of probing live
  --concurrency <n>       Parallel probes, capped at 10 (default: 10)
  --timeout <ms>          Per-probe timeout (default: 5000)
  --crqc-year <year>      CRQC assumption for HNDL exposure
  --out <dir>             Output directory (default: ./mosca-benchmark)
  --badge <dir>           Write readiness badges alongside the report

${c.bold('EXAMPLES')}
  ${c.gray('# scan the current repository')}
  mosca scan

  ${c.gray('# scan source, a TLS endpoint and an SSH bastion')}
  mosca scan . --tls example.com --ssh bastion.example.com

  ${c.gray('# accept existing debt, then fail CI only on regressions')}
  mosca scan . --write-baseline .mosca-baseline.json
  mosca scan . --baseline .mosca-baseline.json --fail-on high

  ${c.gray('# gate a merger on CNSA 2.0 and publish Mermaid diagrams')}
  mosca scan . --compliance cnsa2 --fail-on-compliance cnsa2 --format html,term,mermaid

  ${c.gray('# propose fixes without applying them')}
  mosca fix . --out .mosca-report

  ${c.gray('# just probe endpoints')}
  mosca tls cloudflare.com github.com
  mosca ssh git.example.com:2222
  mosca starttls smtp://mail.example.com:587
  mosca quic cloudflare.com
  mosca ikev2 vpn.example.com

  ${c.gray('# read a capture without sending a single packet')}
  mosca pcap capture.pcap --out capture-report

  ${c.gray('# compare global PQC readiness by sector')}
  mosca benchmark --out benchmark-report
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
      case 'starttls':
        return await runStarttls(args);
      case 'quic':
        return await runQuic(args);
      case 'ikev2':
        return await runIkev2(args);
      case 'pcap':
        return await runPcap(args);
      case 'benchmark':
        return await runBenchmarkCommand(args);
      case 'fix':
        return await runFix(args, args._[1] || '.');
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
  const starttlsTargets = splitList(args.starttls);
  const quicTargets = splitList(args.quic);
  const ikev2Targets = splitList(args.ikev2);
  const pcapTargets = splitList(args.pcap);

  // Load the baseline before scanning so a typo fails fast instead of after
  // a long network probe.
  const baselineDoc = args.baseline ? loadBaseline(path.resolve(args.baseline)) : null;

  const { analysis, meta, endpoints: endpointResults, sshEndpoints, starttlsEndpoints, quicEndpoints, ikev2Endpoints, captures, capturedSessions, artifacts, dependencies } = await scan({
    root,
    config: overrides,
    endpoints,
    ssh: sshTargets,
    starttls: starttlsTargets,
    quic: quicTargets,
    ikev2: ikev2Targets,
    pcap: pcapTargets,
    quiet,
  });

  if (baselineDoc) applyBaseline(analysis, baselineDoc);

  const complianceSelection = selectionValue(args.compliance || args['fail-on-compliance']);
  const compliance = evaluateAllCompliance(analysis, complianceSelection);
  analysis.compliance = compliance;

  const formats = args.json ? ['json'] : splitList(args.format) || ['html', 'term'];

  if (!quiet && (formats.includes('term') || formats.length === 0)) {
    printSummary(analysis, meta);
    printEndpoints(endpointResults);
    printSshEndpoints(sshEndpoints);
    printCaptureSummary(analysis.capture, capturedSessions);
    printFindings(analysis.items, { limit: Number(args.top) || 20 });
    printRoadmap(analysis.roadmap);
    printCompliance(compliance);
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
  if (formats.includes('mermaid')) {
    fs.mkdirSync(outDir, { recursive: true });
    const mmd = path.join(outDir, 'mosca.mmd');
    fs.writeFileSync(mmd, buildMermaid(analysis) + '\n', 'utf8');
    written.push(mmd);
    const diagrams = path.join(outDir, 'mosca-diagrams.md');
    fs.writeFileSync(diagrams, buildMermaidMarkdown(analysis), 'utf8');
    written.push(diagrams);
  }
  if (formats.includes('json')) {
    const payload = { analysis, meta, endpoints: endpointResults, sshEndpoints, starttlsEndpoints, quicEndpoints, ikev2Endpoints, captures, capturedSessions, artifacts, dependencies };
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

  if (args.badge) {
    const badge = writeBadges({ dir: typeof args.badge === 'string' ? args.badge : path.join(outDir, 'badges'), analysis });
    written.push(badge.qri, badge.hndl);
  }

  if (args.fix) {
    const plan = buildFixPlan(analysis);
    const patchFile = path.resolve(args['fix-out'] || path.join(outDir, 'mosca-fix.patch'));
    const result = buildPatch(plan, { root });
    fs.mkdirSync(path.dirname(patchFile), { recursive: true });
    if (result.patch) {
      fs.writeFileSync(patchFile, result.patch, 'utf8');
      written.push(patchFile);
    }
    if (!quiet) {
      console.log(c.bold('  FIX PLAN') + '\n');
      console.log(renderFixReport(plan).replace(/^/gm, '  '));
      if (result.skipped.length) {
        console.log(c.yellow(`  ${result.skipped.length} edit(s) skipped; see the plan above.`));
      }
      console.log('');
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

  let code = exitCode(analysis, args['fail-on'], { newOnly: Boolean(baselineDoc) });
  if (args['fail-on-compliance'] && compliance.some((result) => result.status === 'fail')) code = 1;
  return code;
}

/** `--compliance` with no value means every standard. */
function selectionValue(value) {
  if (!value || value === true) return undefined;
  return String(value);
}

/** Terminal compliance table. */
function printCompliance(results) {
  if (!results.length) return;
  console.log(c.bold('  COMPLIANCE') + '\n');
  for (const result of results) {
    const verdict = result.status === 'pass' ? c.green('PASS') : result.status === 'partial' ? c.yellow('PARTIAL') : c.red('FAIL');
    console.log(`  ${c.bold(result.label.padEnd(22))} ${verdict}  ${c.gray(`score ${result.score} · ${result.violationCount} violation${result.violationCount === 1 ? '' : 's'}`)}`);
    for (const control of result.controls.filter((item) => item.status === 'fail').slice(0, 4)) {
      console.log(`      ${c.red('✕')} ${control.label} ${c.gray(`(${control.violationCount})`)}`);
    }
    if (result.controls.filter((item) => item.status === 'fail').length > 4) {
      console.log(c.gray(`      … ${result.controls.filter((item) => item.status === 'fail').length - 4} more failed controls`));
    }
  }
  console.log(c.gray(`  Standards: ${COMPLIANCE_IDS.join(', ')}\n`));
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
// starttls / quic / ikev2
// ---------------------------------------------------------------------------

async function runStarttls(args) {
  const targets = args._.slice(1);
  if (!targets.length) {
    console.error(c.red('  Usage: mosca starttls <smtp://host:587 | imap://host:993 | pop3://host:995 | postgres://host:5432 | ldap://host:389>'));
    return 2;
  }
  printBanner(VERSION);
  const results = await Promise.all(targets.map((target) => inspectStarttls(target, { timeout: 10000 })));

  console.log(c.bold('  STARTTLS POSTURE') + '\n');
  for (const ep of results) {
    const label = `${ep.protocol}://${ep.host}${ep.port ? `:${ep.port}` : ''}`;
    if (!ep.reachable) {
      console.log(`  ${c.red('✕')} ${c.bold(label)}  ${c.gray(ep.error || 'unreachable')}`);
      continue;
    }
    const kex = ep.hybrid ? c.green(`● ${ep.groupLabel}`) : c.red(`○ ${ep.groupLabel || ep.group || 'unknown'}`);
    console.log(`  ${c.green('✓')} ${c.bold(label)}`);
    console.log(`      protocol   ${c.cyan(ep.versionName || '?')}`);
    console.log(`      key xchg   ${kex}${ep.hybrid ? c.gray('  (post-quantum hybrid)') : c.gray('  (breaks under Shor)')}`);
    if (ep.cipherName) console.log(`      cipher     ${ep.cipherName}`);
    const chain = ep.chainAnalysis;
    if (chain?.entries?.length) {
      const leaf = chain.entries[0];
      console.log(`      cert       ${leaf.keyLabel}${leaf.keyBits ? ` ${leaf.keyBits}` : ''} · ${chain.length} certificate${chain.length === 1 ? '' : 's'}`);
    }
    for (const finding of ep.findings.filter((f) => !f.positive)) {
      console.log(`      ${c.yellow('!')} ${finding.title}`);
    }
    console.log('');
  }
  const hybrid = results.filter((result) => result.hybrid).length;
  console.log(c.gray(`  ${hybrid} of ${results.length} STARTTLS endpoint${results.length === 1 ? '' : 's'} negotiate post-quantum hybrid key exchange.`));
  console.log('');
  return 0;
}

async function runQuic(args) {
  const hosts = args._.slice(1);
  if (!hosts.length) {
    console.error(c.red('  Usage: mosca quic <host...> [--port 443]'));
    return 2;
  }
  printBanner(VERSION);
  const port = args.port ? Number(args.port) : null;
  const targets = hosts.map((host) => (port && !host.includes(':') ? `${host}:${port}` : host));
  const results = await Promise.all(targets.map((target) => inspectQuic(target, { timeout: 10000 })));

  console.log(c.bold('  QUIC POSTURE') + '\n');
  for (const ep of results) {
    const label = `${ep.host}${ep.port !== 443 ? `:${ep.port}` : ''}`;
    if (!ep.reachable) {
      console.log(`  ${c.red('✕')} ${c.bold(label)}  ${c.gray(ep.error || 'unreachable')}`);
      continue;
    }
    const kex = ep.hybrid ? c.green(`● ${ep.groupLabel}`) : c.red(`○ ${ep.groupLabel || ep.group || 'unknown'}`);
    console.log(`  ${c.green('✓')} ${c.bold(label)}`);
    console.log(`      version    ${c.cyan(ep.versionName || '?')}${ep.versionNegotiation ? c.gray('  (version negotiation)') : ''}`);
    console.log(`      key xchg   ${kex}${ep.hybrid ? c.gray('  (post-quantum hybrid)') : c.gray('  (breaks under Shor)')}`);
    if (ep.cipherName) console.log(`      cipher     ${ep.cipherName}`);
    if (ep.datagramBytes) console.log(`      response   ${ep.datagramBytes} bytes`);
    for (const finding of ep.findings.filter((f) => !f.positive)) {
      console.log(`      ${c.yellow('!')} ${finding.title}`);
    }
    console.log('');
  }
  const hybrid = results.filter((result) => result.hybrid).length;
  console.log(c.gray(`  ${hybrid} of ${results.length} QUIC endpoint${results.length === 1 ? '' : 's'} negotiate post-quantum hybrid key exchange.`));
  console.log('');
  return 0;
}

async function runIkev2(args) {
  const hosts = args._.slice(1);
  if (!hosts.length) {
    console.error(c.red('  Usage: mosca ikev2 <host...> [--port 500] [--addke 35,36]'));
    return 2;
  }
  printBanner(VERSION);
  const port = args.port ? Number(args.port) : null;
  const targets = hosts.map((host) => (port && !host.includes(':') ? `${host}:${port}` : host));
  const addkeIds = args.addke
    ? splitList(args.addke).map(Number).filter((id) => Number.isFinite(id))
    : undefined;
  const results = await Promise.all(targets.map((target) => inspectIkev2(target, { timeout: 4000, addkeIds })));

  console.log(c.bold('  IKEv2 POSTURE') + '\n');
  for (const ep of results) {
    const label = `${ep.host}${ep.port !== 500 ? `:${ep.port}` : ''}`;
    if (!ep.reachable) {
      console.log(`  ${c.red('✕')} ${c.bold(label)}  ${c.gray(ep.error || 'unreachable')}`);
      continue;
    }
    const hybrid = ep.addke?.supported;
    console.log(`  ${c.green('✓')} ${c.bold(label)}`);
    console.log(`      hybrid     ${hybrid ? c.green(`● ADDKE transform ${ep.addke.transformId}`) : c.red('○ no RFC 9370 additional key exchange')}`);
    if (ep.classic?.notify) console.log(`      notify     ${ep.classic.notify}`);
    for (const finding of ep.findings.filter((f) => !f.positive)) {
      console.log(`      ${c.yellow('!')} ${finding.title}`);
    }
    console.log('');
  }
  const hybrid = results.filter((result) => result.addke?.supported).length;
  console.log(c.gray(`  ${hybrid} of ${results.length} IKEv2 gateway${results.length === 1 ? '' : 's'} accept hybrid additional key exchange.`));
  console.log('');
  return 0;
}

// ---------------------------------------------------------------------------
// pcap
// ---------------------------------------------------------------------------

async function runPcap(args) {
  const files = args._.slice(1).length ? args._.slice(1) : splitList(args.pcap) || [];
  if (!files.length) {
    console.error(c.red('  Usage: mosca pcap <file.pcap> [--out dir] [--format html,cbom,sarif,json,term]'));
    return 2;
  }
  for (const file of files) {
    if (!fs.existsSync(file)) {
      console.error(c.red(`  Capture not found: ${file}`));
      return 2;
    }
  }

  printBanner(VERSION);
  const overrides = buildOverrides(args);
  const { config: baseConfig } = loadConfig(args.config ? path.resolve(args.config) : path.join(process.cwd(), 'mosca.json'));
  const mergedConfig = mergeConfig(baseConfig, overrides);
  const formats = args.json ? ['json'] : splitList(args.format) || ['html', 'term'];

  const results = files.map((file) => analysePcapFile(file, { config: mergedConfig }));
  const capturedSessions = results.flatMap((result) => result.sessions);
  const findings = results.flatMap((result) => result.findings);
  const analysis = analyse({ findings, endpoints: [], sshEndpoints: [], capturedSessions, config: mergedConfig });
  analysis.capturedSessions = capturedSessions;
  analysis.captures = results;
  analysis.capture = summariseCaptures(results);
  analysis.endpoints = [];
  analysis.sshEndpoints = [];
  analysis.compliance = evaluateAllCompliance(analysis, selectionValue(args.compliance || args['fail-on-compliance']));

  if (!args.quiet && (formats.includes('term') || formats.length === 0)) {
    printCaptureSummary(analysis.capture, capturedSessions);
    printFindings(analysis.items, { limit: Number(args.top) || 20 });
    printRoadmap(analysis.roadmap);
    printCompliance(analysis.compliance);
  }

  const outDir = path.resolve(args.out || 'mosca-pcap-report');
  const written = [];
  if (formats.includes('html')) {
    fs.mkdirSync(outDir, { recursive: true });
    const html = buildHtmlReport({
      analysis,
      meta: { durationMs: 0, captureStats: analysis.capture },
      endpoints: [],
      projectName: results.length === 1 ? path.basename(results[0].file) : 'packet captures',
      toolVersion: VERSION,
    });
    const file = path.join(outDir, 'mosca-report.html');
    fs.writeFileSync(file, html, 'utf8');
    written.push(file);
  }
  if (formats.includes('cbom')) {
    fs.mkdirSync(outDir, { recursive: true });
    const cbom = buildCbom({ analysis, projectName: 'packet-captures', toolVersion: VERSION });
    const file = path.join(outDir, 'bom.cdx.json');
    fs.writeFileSync(file, JSON.stringify(cbom, null, 2), 'utf8');
    written.push(file);
  }
  if (formats.includes('sarif')) {
    fs.mkdirSync(outDir, { recursive: true });
    const sarif = buildSarif({ analysis, root: process.cwd(), toolVersion: VERSION });
    const file = path.join(outDir, 'mosca.sarif');
    fs.writeFileSync(file, JSON.stringify(sarif, null, 2), 'utf8');
    written.push(file);
  }
  if (formats.includes('mermaid')) {
    fs.mkdirSync(outDir, { recursive: true });
    const mmd = path.join(outDir, 'mosca.mmd');
    fs.writeFileSync(mmd, buildMermaid(analysis) + '\n', 'utf8');
    written.push(mmd);
  }
  if (formats.includes('json')) {
    const payload = { analysis, meta: { captureStats: analysis.capture }, captures: results, capturedSessions };
    if (args.json && !args.out) {
      console.log(JSON.stringify(payload, null, 2));
    } else {
      fs.mkdirSync(outDir, { recursive: true });
      const file = path.join(outDir, 'mosca.json');
      fs.writeFileSync(file, JSON.stringify(payload, null, 2), 'utf8');
      written.push(file);
    }
  }
  if (args.badge) {
    const badge = writeBadges({ dir: typeof args.badge === 'string' ? args.badge : path.join(outDir, 'badges'), analysis });
    written.push(badge.qri, badge.hndl);
  }

  if (!args.quiet && written.length) {
    console.log(c.gray('  Artefacts written:'));
    for (const file of written) console.log(`    ${c.cyan('•')} ${file}`);
    console.log('');
  }

  let code = exitCode(analysis, args['fail-on']);
  if (args['fail-on-compliance'] && analysis.compliance.some((result) => result.status === 'fail')) code = 1;
  return code;
}

// ---------------------------------------------------------------------------
// benchmark
// ---------------------------------------------------------------------------

/** Terminal leaderboard for `mosca benchmark`. */
function printBenchmarkSummary(result) {
  const overall = result.overall;
  const verdict = overall.qri >= 70 ? c.green(overall.grade) : overall.qri >= 50 ? c.yellow(overall.grade) : c.red(overall.grade);
  console.log(c.bold('  GLOBAL PQC READINESS') + '\n');
  console.log(`  ${c.bold(String(overall.qri))}${c.gray('/100')}  ${verdict}  ${c.gray(overall.gradeLabel)}`);
  console.log(
    `  ${c.gray('hybrid adoption')} ${c.cyan(`${overall.pqcHybridAdoption}%`)}  ` +
      `${c.gray('· HNDL exposure')} ${overall.hndlExposure > 0 ? c.red(`${overall.hndlExposure}%`) : c.green('0%')}  ` +
      `${c.gray('· observed')} ${overall.observed}/${overall.total}  ` +
      `${c.gray('· CRQC')} ${result.crqcYear}\n`,
  );
  console.log(
    `  ${padEnd(c.gray('SECTOR'), 24)}${padEnd(c.gray('QRI'), 8)}${padEnd(c.gray('GRADE'), 7)}${padEnd(c.gray('HYBRID'), 9)}${padEnd(c.gray('HNDL'), 8)}${c.gray('DATA LIFETIME')}`,
  );
  console.log('  ' + c.gray('─'.repeat(78)));
  for (const sector of result.sectors) {
    const grade = sector.qri >= 70 ? c.green(sector.grade) : sector.qri >= 50 ? c.yellow(sector.grade) : c.red(sector.grade);
    console.log(
      `  ${padEnd(sector.name || sector.id, 24)}` +
        `${padEnd(String(sector.qri), 8)}` +
        `${padEnd(grade, 7)}` +
        `${padEnd(`${sector.pqcHybridAdoption}%`, 9)}` +
        `${padEnd(sector.hndlExposure > 0 ? c.red(`${sector.hndlExposure}%`) : c.green('0%'), 8)}` +
        `${sector.dataLifetimeYears}y`,
    );
  }
  console.log('');
}

async function runBenchmarkCommand(args) {
  const targetsFile = path.resolve(typeof args.targets === 'string' ? args.targets : path.join(PROJECT_ROOT, 'benchmarks', 'targets.json'));
  if (!fs.existsSync(targetsFile)) {
    console.error(c.red(`  Benchmark targets not found: ${targetsFile}`));
    return 2;
  }
  const document = JSON.parse(fs.readFileSync(targetsFile, 'utf8').replace(/^\uFEFF/, ''));
  const quiet = Boolean(args.quiet);
  if (!quiet) printBanner(VERSION);

  let result;
  if (args.snapshot && args.snapshot !== true) {
    const snapshotFile = path.resolve(args.snapshot);
    const snapshot = JSON.parse(fs.readFileSync(snapshotFile, 'utf8').replace(/^\uFEFF/, ''));
    if (!quiet) console.log(c.gray(`  Replaying ${snapshotFile} (${snapshot.targets?.length || 0} targets)`));
    result = await replayBenchmark(snapshot);
  } else {
    if (!quiet) {
      console.log(c.gray(`  Probing ${document.targets?.length || 0} targets · concurrency ${Number(args.concurrency) || 10} · timeout ${Number(args.timeout) || 5000}ms`));
    }
    const { probeTls, probeSsh } = liveProbes();
    result = await runBenchmark({
      targets: expandTargets(document),
      probeTls,
      probeSsh,
      concurrency: Number(args.concurrency) || 10,
      timeout: Number(args.timeout) || 5000,
      crqcYear: Number(args['crqc-year']) || document.crqcYear || 2033,
      toolVersion: VERSION,
    });
  }

  if (!quiet) printBenchmarkSummary(result);

  const formats = args.json ? ['json'] : splitList(args.format) || ['html', 'term'];
  const outDir = path.resolve(args.out || 'mosca-benchmark');
  const written = [];
  if (formats.includes('html')) {
    fs.mkdirSync(outDir, { recursive: true });
    const file = path.join(outDir, 'state-of-pqc.html');
    fs.writeFileSync(
      file,
      buildBenchmarkHtml({
        benchmark: result,
        title: document.title || 'The State of Post-Quantum Readiness',
        subtitle: document.subtitle || '',
        toolVersion: VERSION,
      }),
      'utf8',
    );
    written.push(file);
  }
  if (formats.includes('json')) {
    const payload = { ...result, source: path.basename(targetsFile) };
    if (args.json && !args.out) {
      console.log(JSON.stringify(payload, null, 2));
    } else {
      fs.mkdirSync(outDir, { recursive: true });
      const file = path.join(outDir, 'benchmark.json');
      fs.writeFileSync(file, JSON.stringify(payload, null, 2), 'utf8');
      written.push(file);
    }
  }
  if (args.badge) {
    const badge = writeBadges({ dir: typeof args.badge === 'string' ? args.badge : path.join(outDir, 'badges'), analysis: { summary: { quantumReadinessIndex: result.overall.qri, hndlApplicable: false, capturedHndlApplicable: false } } });
    written.push(badge.qri, badge.hndl);
  }

  if (!quiet && written.length) {
    console.log(c.gray('  Artefacts written:'));
    for (const file of written) console.log(`    ${c.cyan('•')} ${file}`);
    console.log('');
  }
  return 0;
}

// ---------------------------------------------------------------------------
// fix
// ---------------------------------------------------------------------------

async function runFix(args, target) {
  const root = path.resolve(target);
  if (!fs.existsSync(root)) {
    console.error(c.red(`  Path does not exist: ${root}`));
    return 2;
  }
  printBanner(VERSION);

  const { analysis } = await scan({
    root,
    config: buildOverrides(args),
    endpoints: splitList(args.tls) || [],
    ssh: splitList(args.ssh) || [],
    starttls: splitList(args.starttls) || [],
    quic: splitList(args.quic) || [],
    ikev2: splitList(args.ikev2) || [],
    quiet: true,
  });
  const plan = buildFixPlan(analysis);
  const result = buildPatch(plan, { root });

  console.log(renderFixReport(plan).replace(/^/gm, '  '));
  console.log('');

  const outDir = path.resolve(args.out || path.join(root, 'mosca-report'));
  const patchFile = path.resolve(args['fix-out'] || path.join(outDir, 'mosca-fix.patch'));
  if (result.patch) {
    fs.mkdirSync(path.dirname(patchFile), { recursive: true });
    fs.writeFileSync(patchFile, result.patch, 'utf8');
    console.log(c.gray(`  Patch written to ${patchFile} (${result.applied.reduce((sum, item) => sum + item.edits, 0)} edit(s)).`));
    console.log(c.gray('  Apply deliberately: git apply --check <patch> && git apply <patch>'));
  } else {
    console.log(c.gray('  No automatic edits were generated; work through the advisories above.'));
  }
  if (result.skipped.length) {
    console.log(c.yellow(`  ${result.skipped.length} edit(s) skipped because the literal moved or the file was unreadable.`));
  }
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
  console.log(`  Protocols       ${c.bold('TLS 1.0–1.3, SSH 2.0, QUIC v1, IKEv2, STARTTLS')}`);
  console.log(`  Artefacts       ${c.bold('PEM, DER, JWK/JWKS, OpenSSH, authorized_keys, known_hosts')}`);
  console.log(`  Lockfiles       ${c.bold('npm, yarn, pnpm, Cargo, Go, Poetry, requirements.txt, Maven')}`);
  console.log(`  Compliance      ${c.bold(COMPLIANCE_IDS.join(', '))}`);
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
