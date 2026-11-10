/**
 * MOSCA — terminal report
 * =======================
 * Human-first output: a score, a ranked table, and the one thing to do next.
 */

import { c, severityColor, quantumColor, padEnd, padStart, scoreBar, rule } from '../util/log.js';
import { lookup } from '../rules/algorithms.js';

const WORDMARK = `
  ███╗   ███╗ ██████╗ ███████╗ ██████╗ █████╗
  ████╗ ████║██╔═══██╗██╔════╝██╔════╝██╔══██╗
  ██╔████╔██║██║   ██║███████╗██║     ███████║
  ██║╚██╔╝██║██║   ██║╚════██║██║     ██╔══██║
  ██║ ╚═╝ ██║╚██████╔╝███████║╚██████╗██║  ██║
  ╚═╝     ╚═╝ ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝`;

export function printBanner(version = '3.1.0') {
  const lines = WORDMARK.split('\n');
  for (const line of lines) {
    // Vertical gradient from cyan to magenta.
    process.stdout.write(c.brightCyan(line) + '\n');
  }
  process.stdout.write(c.gray('  post-quantum exposure scanner') + c.gray('  ·  ') + c.gray(`v${version}`) + '\n\n');
}

/**
 * @param {object} analysis
 * @param {{targets:string[], sourceStats:object, configStats:object, durationMs:number}} meta
 */
export function printSummary(analysis, meta) {
  const s = analysis.summary;
  const width = Math.min(process.stdout.columns || 88, 92);

  process.stdout.write(rule(width) + '\n');
  process.stdout.write(`${c.bold('  QUANTUM READINESS INDEX')}\n\n`);
  const scoreColor = s.quantumReadinessIndex >= 75 ? c.green : s.quantumReadinessIndex >= 50 ? c.yellow : c.red;
  process.stdout.write(`  ${scoreColor(c.bold(String(s.quantumReadinessIndex.toFixed(1))))} ${c.gray('/ 100')}   ${scoreBar(s.quantumReadinessIndex, 32)}\n\n`);

  const hndlLine = s.hndlApplicable
    ? `${s.hndlExposure > 0 ? c.red(`${s.hndlExposure}%`) : c.green('0%')} of internet-facing key exchange is classical-only`
    : c.gray('n/a — no endpoints inspected (add --tls <host>)');
  const suppressed = meta.sourceStats?.suppressed || 0;
  const surface = `${s.tlsEndpoints ?? s.endpointsInspected} TLS · ${s.sshEndpoints ?? 0} SSH`;
  const baselineLine = s.baseline?.supplied
    ? `  ${c.gray('Baseline')}       ${c.bold(String(s.baseline.newFindings))} new · ${s.baseline.existingFindings} existing · ${s.baseline.resolvedFindings} resolved${s.baseline.newFindings > 0 ? c.yellow('  ← regressions') : c.green('  ← no regressions')}\n`
    : '';
  process.stdout.write(
    `  ${c.gray('Mosca window')}   ${c.bold(String(s.yearsToCRQC))} years to a CRQC (${s.crqcYear})\n` +
      `  ${c.gray('HNDL exposure')}   ${hndlLine}\n` +
      `  ${c.gray('Findings')}        ${c.bold(String(s.totalFindings))} total · ${s.actionable} actionable · ${s.exposedItems} inside the Mosca window\n` +
      `  ${c.gray('Surface')}         ${meta.sourceStats?.filesScanned || 0} source files · ${meta.configStats?.filesScanned || 0} config files · ${surface}${suppressed ? ` · ${suppressed} suppressed` : ''}\n` +
      `  ${c.gray('Estimated effort')} ${c.bold(String(s.effortDays))} engineer-days across the roadmap\n` +
      baselineLine,
  );
  process.stdout.write('\n' + rule(width) + '\n\n');

  const rows = [
    ['critical', s.bySeverity.critical],
    ['high', s.bySeverity.high],
    ['medium', s.bySeverity.medium],
    ['low', s.bySeverity.low],
  ];
  process.stdout.write('  ');
  for (const [sev, count] of rows) {
    process.stdout.write(`${severityColor(sev)} ${c.bold(String(count))}   `);
  }
  process.stdout.write('\n');

  if (Array.isArray(s.sensitivity) && s.sensitivity.length) {
    process.stdout.write(`\n  ${c.gray('CRQC sensitivity')}  `);
    process.stdout.write(
      s.sensitivity
        .map((row) => `${c.bold(String(row.year))}: ${row.exposedItems > 0 ? c.yellow(String(row.exposedItems)) : c.green('0')}`)
        .join(c.gray('  ·  ')),
    );
    process.stdout.write(c.gray('  exposed findings\n'));
  }
  process.stdout.write('\n');
}

/**
 * Print the ranked findings table.
 */
export function printFindings(items, { limit = 20 } = {}) {
  const shown = items.filter((i) => !i.positive).slice(0, limit);
  if (shown.length === 0) {
    process.stdout.write(c.green('  No actionable findings. Nice.\n\n'));
    return;
  }
  process.stdout.write(c.bold('  TOP FINDINGS') + c.gray(`  (${Math.min(limit, items.filter((i) => !i.positive).length)} of ${items.filter((i) => !i.positive).length})`) + '\n\n');

  process.stdout.write(
    `  ${padEnd(c.gray('SEV'), 12)}${padEnd(c.gray('PRI'), 5)}${padEnd(c.gray('NEW'), 5)}${padEnd(c.gray('ALGORITHM'), 22)}${padEnd(c.gray('LOCATION'), 34)}${c.gray('REPLACE WITH')}\n`,
  );
  process.stdout.write('  ' + c.gray('─'.repeat(101)) + '\n');

  for (const item of shown) {
    const loc = item.location?.file
      ? `${item.location.file}:${item.location.line}`
      : `${item.location?.host}:${item.location?.port}`;
    const repl = item.replacement ? lookup(item.replacement).label : '—';
    process.stdout.write(
      `  ${padEnd(severityColor(item.severity), 12)}${padEnd(c.gray(item.priority), 5)}${padEnd(item.baselineStatus === 'new' ? c.magenta('NEW') : '', 5)}${padEnd(item.algorithmLabel || item.algorithm, 22)}${padEnd(truncate(loc, 32), 34)}${c.green(repl)}\n`,
    );
  }
  process.stdout.write('\n');
}

/** Print the endpoint matrix. */
export function printEndpoints(endpoints) {
  if (!endpoints.length) return;
  process.stdout.write(c.bold('  TLS ENDPOINTS') + '\n\n');
  process.stdout.write(
    `  ${padEnd(c.gray('HOST'), 30)}${padEnd(c.gray('PROTOCOL'), 10)}${padEnd(c.gray('KEY EXCHANGE'), 24)}${padEnd(c.gray('CERT SIG'), 24)}${c.gray('POSTURE')}\n`,
  );
  process.stdout.write('  ' + c.gray('─'.repeat(96)) + '\n');
  for (const ep of endpoints) {
    const host = `${ep.host}${ep.port !== 443 ? `:${ep.port}` : ''}`;
    if (!ep.reachable) {
      process.stdout.write(`  ${padEnd(host, 30)}${c.red('unreachable')} ${c.gray(truncate(ep.error || '', 50))}\n`);
      continue;
    }
    const posture = ep.hybrid ? c.green('● hybrid PQC') : c.red('○ classical');
    process.stdout.write(
      `  ${padEnd(host, 30)}${padEnd(ep.protocol || '?', 10)}${padEnd(ep.groupLabel || '—', 24)}${padEnd(ep.certificate?.signature?.name || '—', 24)}${posture}\n`,
    );
  }
  process.stdout.write('\n');
}

/** Print the passive PCAP harvest matrix. */
export function printCaptureSummary(capture, sessions = []) {
  if (!capture || (!capture.sessionCount && !capture.files?.length)) return;
  process.stdout.write(c.bold('  CAPTURED SESSIONS') + c.gray(`  ·  ${capture.sessionCount} session${capture.sessionCount === 1 ? '' : 's'} from ${capture.files?.length || 0} file${capture.files?.length === 1 ? '' : 's'}`) + '\n\n');
  if (capture.sessionCount === 0) {
    process.stdout.write(c.gray('  No TLS or SSH handshakes were found in the capture.') + '\n\n');
    return;
  }
  const ratio = capture.hndlCapturedRatio;
  process.stdout.write(
    `  ${c.gray('HNDL Captured Ratio')}  ${ratio > 0 ? c.red(`${ratio}%`) : c.green('0%')} ${c.gray('of recorded sessions are classical-only')}\n` +
      `  ${c.gray('Servers recorded')}    ${c.bold(String(capture.servers?.length || 0))} ${c.gray('·')} ${capture.tlsSessions} TLS · ${capture.sshSessions} SSH\n` +
      `  ${c.gray('Capture window')}     ${capture.firstCapture ? `${capture.firstCapture} → ${capture.lastCapture}` : 'unknown'}\n\n`,
  );
  process.stdout.write(
    `  ${padEnd(c.gray('CAPTURED'), 22)}${padEnd(c.gray('PROTO'), 7)}${padEnd(c.gray('SERVER'), 30)}${padEnd(c.gray('NEGOTIATED'), 30)}${c.gray('HNDL')}\n`,
  );
  process.stdout.write('  ' + c.gray('─'.repeat(102)) + '\n');
  for (const session of sessions.slice(0, 24)) {
    const when = session.captureTime ? session.captureTime.replace('T', ' ').slice(0, 19) : 'unknown';
    const proto = session.protocol.toUpperCase();
    const server = `${session.server?.name || session.server?.ip || 'unknown'}${session.server?.port ? `:${session.server.port}` : ''}`;
    const negotiated = session.protocol === 'tls'
      ? session.tls?.groupLabel || session.tls?.protocol || 'unknown'
      : session.ssh?.agreedKex || session.ssh?.software || 'unknown';
    const posture = session.hybrid ? c.green('● SAFE') : c.red(`○ ${session.hndl?.exposed ? 'EXPOSED' : 'LEGACY'}`);
    process.stdout.write(
      `  ${padEnd(when, 22)}${padEnd(proto, 7)}${padEnd(truncate(server, 28), 30)}${padEnd(truncate(negotiated, 28), 30)}${posture}\n`,
    );
  }
  if (sessions.length > 24) process.stdout.write(c.gray(`  … ${sessions.length - 24} more session(s) in the report`) + '\n');
  process.stdout.write('\n');
}

/** Print the SSH endpoint matrix. */
export function printSshEndpoints(endpoints) {
  if (!endpoints?.length) return;
  process.stdout.write(c.bold('  SSH ENDPOINTS') + '\n\n');
  process.stdout.write(
    `  ${padEnd(c.gray('HOST'), 30)}${padEnd(c.gray('BANNER'), 30)}${padEnd(c.gray('KEY EXCHANGE'), 32)}${c.gray('HOST KEY')}\n`,
  );
  process.stdout.write('  ' + c.gray('─'.repeat(110)) + '\n');
  for (const ep of endpoints) {
    const host = `${ep.host}${ep.port !== 22 ? `:${ep.port}` : ''}`;
    if (!ep.reachable) {
      process.stdout.write(`  ${padEnd(host, 30)}${c.red('unreachable')} ${c.gray(truncate(ep.error || '', 60))}\n`);
      continue;
    }
    const posture = ep.hybrid ? c.green(`● ${ep.hybridAlgorithm || 'hybrid'}`) : c.red(`○ ${ep.kexAlgorithms?.[0] || 'classical'}`);
    process.stdout.write(
      `  ${padEnd(host, 30)}${padEnd(truncate(ep.software || '—', 28), 30)}${padEnd(posture, 32)}${c.gray(ep.serverHostKeyAlgorithms?.[0] || '—')}\n`,
    );
  }
  process.stdout.write('\n');
}

/** Print the roadmap. */
export function printRoadmap(roadmap) {
  const active = roadmap.filter((p) => p.count > 0);
  if (!active.length) return;
  process.stdout.write(c.bold('  MIGRATION ROADMAP') + '\n\n');
  for (const phase of active) {
    process.stdout.write(`  ${c.brightCyan('▸')} ${c.bold(phase.name)} ${c.gray(`· ${phase.window} · ${phase.count} item${phase.count === 1 ? '' : 's'} · ~${phase.effortDays}d`)}\n`);
    process.stdout.write(`    ${c.gray(phase.goal)}\n`);
    process.stdout.write(`    ${c.gray('Standards: ' + phase.standards.join(', '))}\n\n`);
  }
}

/** Print the top three recommendations. */
export function printNextSteps(analysis) {
  const actionable = analysis.items.filter((i) => !i.positive && i.severity !== 'info');
  if (!actionable.length) return;
  process.stdout.write(c.bold('  DO THIS NEXT') + '\n\n');
  const seen = new Set();
  let n = 0;
  for (const item of actionable) {
    const key = item.replacement || item.algorithm;
    if (seen.has(key)) continue;
    seen.add(key);
    n++;
    const repl = item.replacement ? lookup(item.replacement) : null;
    process.stdout.write(
      `  ${c.brightCyan(`${n}.`)} ${item.title}\n     ${c.gray('→')} ${repl ? `Migrate to ${c.green(repl.label)}${repl.standard ? c.gray(` (${repl.standard})`) : ''}` : 'Review and remove'}\n`,
    );
    if (n >= 3) break;
  }
  process.stdout.write('\n');
}

function truncate(s, n) {
  const str = String(s);
  return str.length <= n ? str : `${str.slice(0, n - 1)}…`;
}
