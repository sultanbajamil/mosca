#!/usr/bin/env node
/**
 * MOSCA — world benchmark runner
 * ==============================
 *
 * Turns `benchmarks/targets.json` into a reproducible artefact:
 *
 *   node scripts/benchmark-world.js --live --write-snapshot benchmarks/snapshot.json
 *   node scripts/benchmark-world.js --snapshot benchmarks/snapshot.json
 *
 * The second form is what CI and the published page use. Replaying a snapshot
 * keeps the numbers stable: `docs/state-of-pqc.html` changes when the snapshot
 * changes, not when a target's TLS terminator happens to rotate a key share.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  runBenchmark,
  replayBenchmark,
  expandTargets,
  liveProbes,
  DEFAULT_CONCURRENCY,
  DEFAULT_TIMEOUT,
} from '../src/benchmark.js';
import { buildBenchmarkHtml, buildBenchmarkCardSvg } from '../src/report/benchmark-html.js';
import { c, padEnd } from '../src/util/log.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const VERSION = '3.1.0';

function parseArgs(argv) {
  const out = { _: [] };
  const takesValue = new Set(['targets', 'snapshot', 'out', 'json', 'crqc', 'concurrency', 'timeout', 'write-snapshot']);
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token.startsWith('--')) {
      const [rawKey, inline] = token.slice(2).split('=');
      const key = rawKey;
      if (takesValue.has(key)) {
        if (inline !== undefined) out[key] = inline;
        else if (argv[i + 1] && !argv[i + 1].startsWith('--')) out[key] = argv[++i];
        else out[key] = true;
      } else {
        out[key] = true;
      }
    } else {
      out._.push(token);
    }
  }
  return out;
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(path.resolve(file), 'utf8').replace(/^\uFEFF/, ''));
}

/** Persist the raw probe results so the benchmark can be replayed exactly. */
export function snapshotFrom(result, document) {
  return {
    title: document.title || result.title,
    subtitle: document.subtitle || '',
    generatedAt: result.generatedAt,
    currentYear: result.currentYear,
    crqcYear: result.crqcYear,
    toolVersion: result.toolVersion,
    targets: result.targets.map((target) => ({
      name: target.name,
      host: target.host,
      sector: target.sector,
      sectorName: target.sectorName,
      dataLifetimeYears: target.dataLifetimeYears,
      sshProbe: Boolean(target.sshProbe),
      tls: target.tls,
      ssh: target.ssh,
    })),
  };
}

function printSummary(result) {
  const overall = result.overall;
  console.log('');
  console.log(`  ${c.bold('GLOBAL')}  ${c.bold(String(overall.qri))}${c.gray('/100')}  ${c.bold(overall.grade)} ${c.gray(`(${overall.gradeLabel})`)}`);
  console.log(
    `  ${c.gray('hybrid adoption')} ${c.cyan(`${overall.pqcHybridAdoption}%`)}  ` +
      `${c.gray('· HNDL exposure')} ${overall.hndlExposure > 0 ? c.red(`${overall.hndlExposure}%`) : c.green('0%')}  ` +
      `${c.gray('· observed')} ${overall.observed}/${overall.total}`,
  );
  console.log('');
  console.log(
    `  ${padEnd(c.gray('SECTOR'), 24)}${padEnd(c.gray('QRI'), 8)}${padEnd(c.gray('GRADE'), 7)}${padEnd(c.gray('HYBRID'), 9)}${padEnd(c.gray('HNDL'), 8)}${c.gray('DATA')}`,
  );
  console.log('  ' + c.gray('─'.repeat(74)));
  for (const sector of result.sectors) {
    console.log(
      `  ${padEnd(sector.name || sector.id, 24)}` +
        `${padEnd(`${sector.qri}`, 8)}` +
        `${padEnd(sector.grade, 7)}` +
        `${padEnd(`${sector.pqcHybridAdoption}%`, 9)}` +
        `${padEnd(`${sector.hndlExposure}%`, 8)}` +
        `${sector.dataLifetimeYears}y`,
    );
  }
  console.log('');
}

async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const targetsFile = path.resolve(args.targets || path.join(ROOT, 'benchmarks', 'targets.json'));
  const document = readJson(targetsFile);
  const crqcYear = Number(args.crqc) || document.crqcYear || 2033;
  const concurrency = Math.max(1, Math.min(10, Number(args.concurrency) || DEFAULT_CONCURRENCY));
  const timeout = Math.max(250, Number(args.timeout) || DEFAULT_TIMEOUT);

  let result;
  if (args.snapshot) {
    const snapshot = readJson(args.snapshot);
    if (!args.quiet) console.log(c.gray(`  replaying ${args.snapshot} (${snapshot.targets?.length || 0} targets)`));
    result = await replayBenchmark(snapshot);
  } else {
    if (!args.quiet) {
      console.log(c.gray(`  probing ${document.targets?.length || 0} targets · concurrency ${concurrency} · timeout ${timeout}ms · CRQC ${crqcYear}`));
    }
    const { probeTls, probeSsh } = liveProbes();
    result = await runBenchmark({
      targets: expandTargets(document),
      probeTls,
      probeSsh,
      concurrency,
      timeout,
      crqcYear,
      toolVersion: VERSION,
    });
  }

  if (!args.quiet) printSummary(result);

  if (args['write-snapshot']) {
    const file = path.resolve(args['write-snapshot']);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(snapshotFrom(result, document), null, 2) + '\n', 'utf8');
    if (!args.quiet) console.log(c.gray(`  snapshot  ${file}`));
  }

  const outFile = path.resolve(args.out || path.join(ROOT, 'docs', 'state-of-pqc.html'));
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(
    outFile,
    buildBenchmarkHtml({
      benchmark: result,
      title: document.title || 'The State of Post-Quantum Readiness',
      subtitle: document.subtitle || '',
      toolVersion: VERSION,
    }),
    'utf8',
  );
  if (!args.quiet) console.log(c.gray(`  report    ${outFile}`));

  const svgFile = path.resolve(args.svg || path.join(path.dirname(outFile), 'state-of-pqc.svg'));
  fs.writeFileSync(
    svgFile,
    buildBenchmarkCardSvg({
      benchmark: result,
      title: document.title || 'The State of Post-Quantum Readiness',
    }),
    'utf8',
  );
  if (!args.quiet) console.log(c.gray(`  card      ${svgFile}`));

  if (args.json) {
    const jsonFile = args.json === true ? path.join(path.dirname(outFile), 'state-of-pqc.json') : path.resolve(args.json);
    fs.mkdirSync(path.dirname(jsonFile), { recursive: true });
    fs.writeFileSync(jsonFile, JSON.stringify(result, null, 2) + '\n', 'utf8');
    if (!args.quiet) console.log(c.gray(`  data      ${jsonFile}`));
  }
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(c.red(`  benchmark failed: ${error.message}`));
    process.exitCode = 1;
  });
}

export { main };
