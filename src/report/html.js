/**
 * MOSCA — interactive HTML report
 * ===============================
 *
 * A single self-contained file: no fonts, no scripts, no images fetched
 * from the network. It can be attached to an email, opened from a USB
 * stick, or published to GitHub Pages.
 *
 * The interesting part is the timeline: it renders Mosca's inequality for
 * the organisation's top algorithms and lets the reader move the CRQC
 * assumption to see which assets fall inside the exposure window.
 */

import { buildCbom } from './cbom.js';

const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));

const fmtPct = (n) => `${Number(n).toFixed(1)}%`;

function verdict(score) {
  if (score >= 80) return { label: 'Quantum-ready', tone: 'good', text: 'The estate is largely migrated. Keep it that way with continuous scanning.' };
  if (score >= 60) return { label: 'Migrating', tone: 'ok', text: 'Migration is under way. Close the remaining key-exchange gaps first.' };
  if (score >= 35) return { label: 'Exposed', tone: 'warn', text: 'A material share of the estate is still classical-only. Harvest-now-decrypt-later applies today.' };
  return { label: 'Critically exposed', tone: 'bad', text: 'Most of the cryptographic estate falls to a quantum computer, and some of it is already broken.' };
}

function sevClass(sev) {
  return `sev-${sev || 'info'}`;
}

// ---------------------------------------------------------------------------
// Fragments
// ---------------------------------------------------------------------------

function renderGauge(score) {
  const r = 84;
  const circumference = 2 * Math.PI * r;
  const offset = circumference * (1 - Math.min(100, Math.max(0, score)) / 100);
  const v = verdict(score);
  return `
  <div class="gauge-wrap tone-${v.tone}">
    <svg class="gauge" viewBox="0 0 200 200" role="img" aria-label="Quantum readiness index ${score} out of 100">
      <defs>
        <linearGradient id="gaugeGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="var(--accent)"/>
          <stop offset="100%" stop-color="var(--accent-2)"/>
        </linearGradient>
      </defs>
      <circle class="gauge-track" cx="100" cy="100" r="${r}"/>
      <circle class="gauge-value" cx="100" cy="100" r="${r}"
        stroke-dasharray="${circumference.toFixed(2)}"
        stroke-dashoffset="${offset.toFixed(2)}"/>
    </svg>
    <div class="gauge-center">
      <div class="gauge-score">${score.toFixed(1)}</div>
      <div class="gauge-unit">/ 100</div>
    </div>
    <div class="gauge-label">${esc(v.label)}</div>
  </div>`;
}

function renderKpi(label, value, sub, tone = '') {
  return `
  <div class="kpi ${tone}">
    <div class="kpi-value">${value}</div>
    <div class="kpi-label">${label}</div>
    <div class="kpi-sub">${sub}</div>
  </div>`;
}

function renderTimeline(items, summary) {
  const top = items
    .filter((i) => !i.positive && i.quantum !== 'safe')
    .reduce((acc, i) => {
      const key = i.algorithm;
      const existing = acc.find((x) => x.key === key);
      if (existing) {
        existing.count += 1;
        existing.score = Math.max(existing.score, i.score);
      } else {
        acc.push({
          key,
          label: i.algorithmLabel || i.algorithm,
          shelf: i.shelfLife,
          lead: i.leadTime,
          quantum: i.quantum,
          severity: i.severity,
          score: i.score,
          count: 1,
        });
      }
      return acc;
    }, [])
    .sort((a, b) => b.score - a.score)
    .slice(0, 9);

  if (!top.length) {
    return `<div class="empty">No quantum-vulnerable algorithms found.</div>`;
  }

  const maxYear = Math.max(20, ...top.map((t) => t.shelf + t.lead + 4));
  const rows = top
    .map((t) => {
      const shelfPct = (t.shelf / maxYear) * 100;
      const leadPct = (t.lead / maxYear) * 100;
      return `
      <div class="tl-row" data-shelf="${t.shelf}" data-lead="${t.lead}">
        <div class="tl-label">
          <span class="tl-name">${esc(t.label)}</span>
          <span class="tl-meta">${t.shelf}y data · ${t.lead}y migration</span>
        </div>
        <div class="tl-track">
          <div class="tl-bar">
            <div class="tl-seg tl-data" style="width:${shelfPct.toFixed(2)}%"></div>
            <div class="tl-seg tl-migrate" style="width:${leadPct.toFixed(2)}%"></div>
          </div>
          <div class="tl-crqc" style="left:0%"></div>
          <span class="tl-verdict"></span>
        </div>
      </div>`;
    })
    .join('');

  return `
  <div class="timeline-controls">
    <div class="scenario-buttons">
      <button class="scenario" data-year="2029">Aggressive <span>2029</span></button>
      <button class="scenario active" data-year="2033">Moderate <span>2033</span></button>
      <button class="scenario" data-year="2038">Conservative <span>2038</span></button>
    </div>
    <div class="slider-wrap">
      <label for="crqc">CRQC assumption: <strong id="crqc-year">${summary.crqcYear}</strong></label>
      <input type="range" id="crqc" min="2027" max="2045" step="1" value="${summary.crqcYear}">
    </div>
  </div>
  <div class="timeline" data-maxyears="${maxYear}" data-nowyear="${summary.currentYear}">
    <div class="tl-axis">
      <span class="tl-axis-label">now</span>
      <span class="tl-axis-crqc" id="crqc-label">${summary.crqcYear}</span>
      <span class="tl-axis-end">+${maxYear}y</span>
    </div>
    ${rows}
  </div>
  <div class="timeline-legend">
    <span><i class="sw sw-data"></i> data must stay secret</span>
    <span><i class="sw sw-migrate"></i> migration lead time</span>
    <span><i class="sw sw-crqc"></i> cryptographically relevant quantum computer</span>
    <span class="tl-summary" id="tl-summary"></span>
  </div>`;
}

function renderFindings(items) {
  const actionable = items.filter((i) => !i.positive);
  if (!actionable.length) {
    return `<div class="empty">No findings. Either the estate is clean or the scan did not reach the code.</div>`;
  }
  const compared = actionable.some((i) => i.baselineStatus === 'new' || i.baselineStatus === 'existing');
  const newCount = actionable.filter((i) => i.baselineStatus === 'new').length;
  const rows = actionable
    .map((i) => {
      const loc = i.location?.file ? `${i.location.file}:${i.location.line}` : `${i.location?.host}:${i.location?.port}`;
      const replacement = i.replacement ? i.replacement : null;
      const search = `${i.title} ${i.algorithmLabel} ${loc} ${i.note || ''}`.toLowerCase();
      const isNew = i.baselineStatus === 'new';
      return `
      <tr class="finding ${sevClass(i.severity)}" data-sev="${i.severity}" data-new="${isNew ? '1' : '0'}" data-text="${esc(search)}">
        <td><span class="pill ${sevClass(i.severity)}">${esc(i.severity)}</span>${isNew ? ' <span class="pill new">new</span>' : ''}</td>
        <td class="mono prio">${esc(i.priority)}</td>
        <td>
          <div class="f-title">${esc(i.title)}</div>
          <div class="f-note">${esc(i.note || '')}</div>
        </td>
        <td class="mono loc">${esc(loc)}</td>
        <td class="mono">${replacement ? `<span class="repl">${esc(replacement)}</span>` : '<span class="muted">—</span>'}</td>
        <td class="num mono" title="Mosca inequality">${i.mosca ? esc(i.mosca.inequality) : '—'}</td>
      </tr>`;
    })
    .join('');

  const counts = actionable.reduce((acc, i) => {
    acc[i.severity] = (acc[i.severity] || 0) + 1;
    return acc;
  }, {});

  return `
  <div class="toolbar">
    <div class="filters">
      <button class="chip active" data-filter="all">All <span>${actionable.length}</span></button>
      ${compared ? `<button class="chip new" data-filter="new">New <span>${newCount}</span></button>` : ''}
      ${['critical', 'high', 'medium', 'low']
        .filter((s) => counts[s])
        .map((s) => `<button class="chip ${sevClass(s)}" data-filter="${s}">${s} <span>${counts[s]}</span></button>`)
        .join('')}
    </div>
    <input class="search" id="search" type="search" placeholder="Filter by file, algorithm, note…" aria-label="Search findings">
  </div>
  <div class="table-wrap">
    <table class="findings">
      <thead>
        <tr>
          <th>Severity</th><th>Pri</th><th>Finding</th><th>Location</th><th>Migrate to</th><th class="num">Mosca</th>
        </tr>
      </thead>
      <tbody id="finding-body">${rows}</tbody>
    </table>
  </div>
  <div class="empty hidden" id="no-results">No findings match the current filter.</div>`;
}

function renderEndpoints(endpoints) {
  if (!endpoints.length) {
    return `<div class="empty">No live endpoints were inspected. Add hosts with <code>--tls</code> or in <code>mosca.json</code>.</div>`;
  }
  const cards = endpoints
    .map((ep) => {
      if (!ep.reachable) {
        return `
        <article class="ep-card down">
          <header>
            <span class="ep-host mono">${esc(ep.host)}${ep.port !== 443 ? `:${ep.port}` : ''}</span>
            <span class="pill sev-critical">unreachable</span>
          </header>
          <p class="muted">${esc(ep.error || 'connection failed')}</p>
        </article>`;
      }
      const cert = ep.certificate;
      const kexBadge = ep.hybrid
        ? `<span class="pill sev-safe">hybrid PQC · ${esc(ep.groupLabel || ep.group)}</span>`
        : `<span class="pill sev-high">classical · ${esc(ep.groupLabel || ep.group || 'unknown')}</span>`;
      return `
      <article class="ep-card">
        <header>
          <span class="ep-host mono">${esc(ep.host)}${ep.port !== 443 ? `:${ep.port}` : ''}</span>
          ${kexBadge}
        </header>
        <dl>
          <div><dt>Protocol</dt><dd class="mono">${esc(ep.protocol || '—')}</dd></div>
          <div><dt>Cipher</dt><dd class="mono">${esc(ep.cipher || '—')}</dd></div>
          <div><dt>ALPN</dt><dd class="mono">${esc(ep.alpn || '—')}</dd></div>
          <div><dt>Server prefers</dt><dd class="mono">${esc(ep.groupLabel || ep.group || '—')}</dd></div>
          ${cert ? `<div><dt>Cert signature</dt><dd class="mono">${esc(cert.signature.name)}</dd></div>` : ''}
          ${cert ? `<div><dt>Cert key</dt><dd class="mono">${esc(cert.publicKey.label)}${cert.publicKey.bits ? ` · ${cert.publicKey.bits}b` : ''}</dd></div>` : ''}
          ${cert ? `<div><dt>Expires</dt><dd class="mono">${cert.daysRemaining != null ? `${cert.daysRemaining} days` : '—'}</dd></div>` : ''}
        </dl>
        <div class="ep-verdict">${ep.hybrid ? 'Recorded traffic is protected against a future quantum computer.' : 'Recorded traffic can be decrypted once a CRQC exists. Enable X25519MLKEM768.'}</div>
      </article>`;
    })
    .join('');
  return `<div class="ep-grid">${cards}</div>`;
}

function renderCapturedSessions(sessions = []) {
  if (!sessions.length) return '';
  const cards = sessions.map((session) => {
    const server = `${session.server?.name || session.server?.ip || 'unknown'}${session.server?.port ? `:${session.server.port}` : ''}`;
    const when = session.captureTime ? session.captureTime.replace('T', ' ').slice(0, 19) : 'unknown';
    const kind = session.protocol === 'tls' ? 'TLS' : 'SSH';
    const negotiated = session.protocol === 'tls'
      ? session.tls?.groupLabel || session.tls?.groupName || session.tls?.protocol || 'unknown'
      : session.ssh?.agreedKex || session.ssh?.software || 'unknown';
    const detail = session.protocol === 'tls'
      ? `${session.tls?.protocol || 'TLS'} · ${session.tls?.cipherName || 'cipher unknown'}`
      : `${session.ssh?.software || 'SSH'} · host key ${session.ssh?.hostKeyAlgorithms?.[0] || 'unknown'}`;
    const status = session.hybrid ? 'safe' : session.hndl?.exposed ? 'exposed' : 'legacy';
    const statusLabel = session.hybrid ? 'Hybrid KEX · protected' : session.hndl?.exposed ? 'Inside the Mosca window' : 'Classical · recorded';
    return `<article class="ep-card capture-card ${status}">
      <header><span class="ep-host mono">${esc(server)}</span><span class="pill sev-${status === 'exposed' ? 'critical' : status === 'safe' ? 'safe' : 'high'}">${kind}</span></header>
      <dl>
        <div><dt>Captured</dt><dd>${esc(when)} UTC</dd></div>
        <div><dt>Negotiated</dt><dd>${esc(negotiated)}</dd></div>
        <div><dt>Detail</dt><dd>${esc(detail)}</dd></div>
        <div><dt>Mosca</dt><dd>${esc(session.hndl?.inequality || 'n/a')}</dd></div>
      </dl>
      <div class="ep-verdict">${session.hybrid ? `<span class="repl">● ${esc(statusLabel)}</span>` : `<span class="cap-exposed">○ ${esc(statusLabel)}</span>`}</div>
    </article>`;
  }).join('');
  return `<div class="ep-grid">${cards}</div>`;
}

function renderSshEndpoints(endpoints) {
  if (!endpoints?.length) return '';
  const cards = endpoints
    .map((ep) => {
      if (!ep.reachable) {
        return `
        <article class="ep-card down">
          <header>
            <span class="ep-host mono">${esc(ep.host)}${ep.port !== 22 ? `:${ep.port}` : ''}</span>
            <span class="pill sev-critical">unreachable</span>
          </header>
          <p class="muted">${esc(ep.error || 'connection failed')}</p>
        </article>`;
      }
      const kexBadge = ep.hybrid
        ? `<span class="pill sev-safe">hybrid KEX · ${esc(ep.hybridAlgorithm)}</span>`
        : `<span class="pill sev-high">classical · ${esc(ep.kexAlgorithms?.[0] || 'unknown')}</span>`;
      return `
      <article class="ep-card">
        <header>
          <span class="ep-host mono">${esc(ep.host)}${ep.port !== 22 ? `:${ep.port}` : ''}</span>
          ${kexBadge}
        </header>
        <dl>
          <div><dt>Banner</dt><dd class="mono">${esc(ep.banner || '—')}</dd></div>
          <div><dt>Host key</dt><dd class="mono">${esc(ep.serverHostKeyAlgorithms?.[0] || '—')}</dd></div>
          <div><dt>Ciphers</dt><dd class="mono">${esc((ep.encryption || []).slice(0, 3).join(', ') || '—')}</dd></div>
          <div><dt>MACs</dt><dd class="mono">${esc((ep.macs || []).slice(0, 3).join(', ') || '—')}</dd></div>
        </dl>
        <div class="ep-verdict">${ep.hybrid ? 'The server advertises a hybrid KEM for SSH sessions.' : 'No hybrid KEM advertised. Enable mlkem768x25519-sha256 or sntrup761x25519-sha512@openssh.com.'}</div>
      </article>`;
    })
    .join('');
  return `<div class="ep-grid">${cards}</div>`;
}

function renderSensitivity(rows) {
  if (!Array.isArray(rows) || rows.length === 0) return '';
  const cells = rows
    .map(
      (r) => `<div class="sens-cell">
        <div class="sens-year mono">${r.year}</div>
        <div class="sens-value mono ${r.exposedItems > 0 ? 'sev-high' : 'sev-safe'}">${r.exposedItems}</div>
        <div class="sens-sub">${r.yearsToCRQC} years · ${r.exposedShare.toFixed(1)}%</div>
      </div>`,
    )
    .join('');
  return `<div class="sens">${cells}<div class="sens-note">Findings inside the Mosca window under each CRQC assumption.</div></div>`;
}

function renderAlgorithms(algorithms) {
  if (!algorithms.length) return '';
  const max = Math.max(...algorithms.map((a) => a.count), 1);
  const rows = algorithms
    .map(
      (a) => `
    <div class="algo-row">
      <div class="algo-name mono">${esc(a.label)}</div>
      <div class="algo-bar"><span class="${sevClass(a.maxSeverity)}" style="width:${((a.count / max) * 100).toFixed(1)}%"></span></div>
      <div class="algo-count mono">${a.count}</div>
      <div class="algo-repl mono">${a.replacement ? esc(a.replacement) : '<span class="muted">—</span>'}</div>
    </div>`,
    )
    .join('');
  return `
  <div class="algo-head">
    <span>Algorithm</span><span>Occurrences</span><span>Count</span><span>Replace with</span>
  </div>${rows}`;
}

function renderRoadmap(roadmap) {
  const active = roadmap.filter((p) => p.count > 0);
  if (!active.length) return `<div class="empty">Nothing to migrate.</div>`;
  return active
    .map(
      (p, idx) => `
    <article class="phase">
      <div class="phase-num">${String(idx + 1).padStart(2, '0')}</div>
      <div class="phase-body">
        <header>
          <h3>${esc(p.name)}</h3>
          <span class="phase-window mono">${esc(p.window)}</span>
        </header>
        <p>${esc(p.goal)}</p>
        <div class="phase-meta">
          <span class="mono">${p.count} item${p.count === 1 ? '' : 's'}</span>
          <span class="mono">~${p.effortDays} engineer-days</span>
          ${p.standards.map((s) => `<span class="tag">${esc(s)}</span>`).join('')}
        </div>
      </div>
    </article>`,
    )
    .join('');
}

// ---------------------------------------------------------------------------
// v3: compliance, certificate chains, simulator, supply chain
// ---------------------------------------------------------------------------

const STATUS_CLASS = { pass: 'good', partial: 'warn', fail: 'bad' };

function renderCompliance(results) {
  if (!Array.isArray(results) || results.length === 0) {
    return '<div class="empty">No compliance standard was evaluated.</div>';
  }
  const cards = results
    .map((result) => {
      const tone = STATUS_CLASS[result.status] || '';
      const controls = result.controls
        .map(
          (control) => `<li class="ctl ${control.status}">
            <span class="ctl-mark">${control.status === 'pass' ? '✓' : '✕'}</span>
            <span><b>${esc(control.label)}</b>${control.status === 'fail' ? `<span class="ctl-count mono">${control.violationCount}</span><br><span class="muted">${esc(control.remediation)}</span>` : ''}</span>
          </li>`,
        )
        .join('');
      return `<article class="comp-card ${tone}">
        <header>
          <div><h3>${esc(result.label)}</h3><span class="muted">${esc(result.authority)}</span></div>
          <span class="pill sev-${result.status === 'pass' ? 'safe' : result.status === 'partial' ? 'medium' : 'critical'}">${esc(result.status.toUpperCase())}</span>
        </header>
        <div class="comp-score mono">${result.score}<span>/100</span> · ${result.violationCount} violation${result.violationCount === 1 ? '' : 's'}</div>
        <p class="muted">${esc(result.deadline)}</p>
        <ul class="ctl-list">${controls}</ul>
      </article>`;
    })
    .join('');
  return `<div class="comp-grid">${cards}</div>`;
}

function renderChainTree(endpoints = []) {
  const withChains = endpoints.filter((ep) => ep.chainAnalysis?.entries?.length);
  if (!withChains.length) {
    return '<div class="empty">No certificate chains were captured. Add TLS hosts with <code>--tls</code>.</div>';
  }
  return withChains
    .map((ep) => {
      const entries = ep.chainAnalysis.entries
        .map(
          (entry) => `<li class="chain-node ${entry.quantum}">
            <span class="chain-role mono">${esc(entry.role)}</span>
            <span class="chain-subject">${esc(entry.subject)}</span>
            <span class="chain-meta mono">${esc(entry.keyLabel)}${entry.keyBits ? ` ${entry.keyBits}b` : ''} · ${esc(entry.signatureAlgorithm || 'unknown')} · ${entry.daysRemaining == null ? '?' : `${entry.daysRemaining}d`}</span>
          </li>`,
        )
        .join('');
      const pqc = ep.pqcHandshake?.worst;
      const projection = pqc
        ? `<div class="chain-pqc ${pqc.exceeds ? 'bad' : 'good'}">
            <b>${esc(pqc.label)} projection</b>
            <span class="mono">${pqc.totalBytes} bytes · ${pqc.exceeds ? 'exceeds' : 'fits'} the 14 KB initial window</span>
          </div>`
        : '';
      return `<article class="chain-card">
        <header><span class="mono">${esc(ep.host)}:${ep.port}</span><span class="muted">${ep.chainAnalysis.length} certificate${ep.chainAnalysis.length === 1 ? '' : 's'}</span></header>
        <ol class="chain-list">${entries}</ol>
        ${projection}
      </article>`;
    })
    .join('');
}

function renderSimulator(analysis) {
  const s = analysis.summary;
  const actionable = analysis.items.filter((item) => !item.positive).length;
  return `<div class="sim" id="sim">
    <div class="sim-controls">
      <label>CRQC year <output class="mono" id="sim-year">${s.crqcYear}</output>
        <input type="range" id="sim-crqc" min="2029" max="2045" step="1" value="${s.crqcYear}">
      </label>
      <label>Migration speed <output class="mono" id="sim-speed">1.0×</output>
        <input type="range" id="sim-lead" min="50" max="200" step="10" value="100">
      </label>
      <label class="sim-check"><input type="checkbox" id="sim-hybrid"> Assume hybrid key exchange lands this quarter</label>
    </div>
    <div class="sim-output">
      <div class="sim-number mono" id="sim-exposed">${s.exposedItems}</div>
      <div class="muted">of ${actionable} actionable findings still inside the Mosca window</div>
      <div class="sim-bar"><span id="sim-bar-fill" style="width:${actionable ? (s.exposedItems / actionable) * 100 : 0}%"></span></div>
    </div>
  </div>`;
}

function renderDependencies(packages = []) {
  if (!packages.length) return '<div class="empty">No cryptographic lockfile packages matched.</div>';
  const rows = packages
    .map((pkg) => {
      const tone = pkg.status === 'quantum-safe' ? 'safe' : pkg.status === 'classically-broken' ? 'critical' : pkg.status === 'deprecated' ? 'medium' : 'high';
      return `<tr>
        <td class="mono">${esc(pkg.name)}</td>
        <td class="mono">${esc(pkg.version || '')}</td>
        <td>${esc(pkg.ecosystem || '')}</td>
        <td><span class="pill sev-${tone}">${esc(pkg.status || 'unknown')}</span></td>
        <td class="mono muted">${esc(pkg.file || pkg.rel || '')}</td>
      </tr>`;
    })
    .join('');
  return `<table class="data-table"><thead><tr><th>Package</th><th>Version</th><th>Ecosystem</th><th>Status</th><th>Lockfile</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function renderArtifacts(artifacts) {
  const findings = artifacts?.findings || [];
  if (!findings.length) return '<div class="empty">No on-disk key or certificate artifacts were found.</div>';
  const rows = findings
    .slice(0, 100)
    .map(
      (f) => `<tr>
        <td class="mono">${esc(f.location?.file || '')}</td>
        <td>${esc(f.algorithmLabel || f.algorithm || '')}</td>
        <td>${esc(f.artifact?.type || f.primitive || '')}</td>
        <td><span class="pill ${sevClass(f.severity)}">${esc(f.severity || '')}</span></td>
      </tr>`,
    )
    .join('');
  return `<table class="data-table"><thead><tr><th>File</th><th>Algorithm</th><th>Type</th><th>Severity</th></tr></thead><tbody>${rows}</tbody></table>`;
}

// ---------------------------------------------------------------------------
// Document
// ---------------------------------------------------------------------------

/**
 * @param {{analysis:object, meta:object, endpoints?:object[], projectName?:string, toolVersion?:string, cbom?:object}} input
 */
export function buildHtmlReport({ analysis, meta, endpoints = [], projectName = 'project', toolVersion = '1.0.0', cbom = null }) {
  const s = analysis.summary;
  const sshEndpoints = analysis.sshEndpoints || [];
  const capturedSessions = analysis.capturedSessions || [];
  const v = verdict(s.quantumReadinessIndex);
  const generated = new Date(s.generatedAt);
  // The footer offers the CBOM as a download. Embed the same document the CLI
  // writes, so a report shared on its own still carries a machine-readable
  // bill of materials instead of an empty object.
  const cbomDoc =
    cbom ||
    buildCbom({
      analysis: analysis.endpoints?.length || !endpoints.length ? analysis : { ...analysis, endpoints },
      projectName,
      toolVersion,
    });
  const data = {
    summary: s,
    items: analysis.items.map((i) => ({
      algorithm: i.algorithm,
      algorithmLabel: i.algorithmLabel,
      quantum: i.quantum,
      classical: i.classical,
      severity: i.severity,
      score: i.score,
      shelfLife: i.shelfLife,
      leadTime: i.leadTime,
      priority: i.priority,
      primitive: i.primitive,
      kind: i.kind,
      location: i.location,
      fingerprint: i.fingerprint,
      baselineStatus: i.baselineStatus || null,
      isNew: Boolean(i.isNew),
    })),
  };

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MOSCA — Post-Quantum Exposure Report · ${esc(projectName)}</title>
<meta name="description" content="Post-quantum cryptography exposure report generated by MOSCA.">
<style>
:root{
  --bg:#060911; --bg-2:#0a1020; --panel:rgba(255,255,255,.028); --panel-2:rgba(255,255,255,.05);
  --border:rgba(255,255,255,.085); --border-2:rgba(255,255,255,.14);
  --text:#e8eefb; --muted:#8b9ab5; --faint:#5d6a82;
  --accent:#22d3ee; --accent-2:#a78bfa;
  --green:#34d399; --yellow:#fbbf24; --orange:#fb923c; --red:#f87171;
  --mono:ui-monospace,"Cascadia Code","JetBrains Mono",Menlo,Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,system-ui,sans-serif;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{
  margin:0; background:var(--bg); color:var(--text); font-family:var(--sans);
  -webkit-font-smoothing:antialiased; line-height:1.55;
  background-image:
    radial-gradient(1200px 600px at 10% -10%, rgba(34,211,238,.10), transparent 60%),
    radial-gradient(900px 500px at 100% 0%, rgba(167,139,250,.10), transparent 55%),
    radial-gradient(800px 800px at 50% 120%, rgba(52,211,153,.05), transparent 60%);
  background-attachment:fixed;
}
.mono{font-family:var(--mono);font-variant-numeric:tabular-nums}
.muted{color:var(--muted)}
.hidden{display:none!important}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
code{font-family:var(--mono);font-size:.88em;background:rgba(255,255,255,.06);padding:.15em .4em;border-radius:4px}

.wrap{max-width:1180px;margin:0 auto;padding:0 28px 96px}

/* ---------- top bar ---------- */
.topbar{
  position:sticky;top:0;z-index:20;backdrop-filter:blur(14px);
  background:rgba(6,9,17,.72);border-bottom:1px solid var(--border);
}
.topbar-inner{max-width:1180px;margin:0 auto;padding:14px 28px;display:flex;align-items:center;gap:16px}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;letter-spacing:.14em;font-size:13px}
.brand-mark{width:22px;height:22px;border-radius:6px;background:linear-gradient(135deg,var(--accent),var(--accent-2));box-shadow:0 0 20px rgba(34,211,238,.45)}
.brand small{color:var(--faint);font-weight:500;letter-spacing:.02em;text-transform:none;font-size:12px}
.topbar nav{margin-left:auto;display:flex;gap:18px;font-size:13px;color:var(--muted)}
.topbar nav a{color:var(--muted)}
.topbar nav a:hover{color:var(--text);text-decoration:none}

/* ---------- hero ---------- */
.hero{display:grid;grid-template-columns:1.5fr .9fr;gap:48px;align-items:center;padding:72px 0 40px}
.eyebrow{font-size:11px;letter-spacing:.22em;text-transform:uppercase;color:var(--accent);font-weight:600;margin-bottom:18px}
.eyebrow::before{content:"";display:inline-block;width:28px;height:1px;background:var(--accent);vertical-align:middle;margin-right:12px;opacity:.7}
h1{font-size:46px;line-height:1.08;margin:0 0 18px;letter-spacing:-.02em;font-weight:700}
h1 em{font-style:normal;background:linear-gradient(120deg,var(--accent),var(--accent-2));-webkit-background-clip:text;background-clip:text;color:transparent}
.lede{font-size:17px;color:var(--muted);max-width:56ch;margin:0 0 26px}
.hero-meta{display:flex;flex-wrap:wrap;gap:24px;font-size:12.5px;color:var(--faint);font-family:var(--mono)}
.hero-meta b{color:var(--text);font-weight:600}

/* ---------- gauge ---------- */
.gauge-wrap{position:relative;display:flex;flex-direction:column;align-items:center;gap:14px}
.gauge{width:210px;height:210px;transform:rotate(-90deg)}
.gauge-track{fill:none;stroke:rgba(255,255,255,.07);stroke-width:12}
.gauge-value{
  fill:none;stroke:url(#gaugeGrad);stroke-width:12;stroke-linecap:round;
  transition:stroke-dashoffset 1.4s cubic-bezier(.2,.8,.2,1);
  filter:drop-shadow(0 0 10px rgba(34,211,238,.45));
}
.gauge-center{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center;pointer-events:none}
.gauge-score{font-size:46px;font-weight:700;letter-spacing:-.03em;line-height:1}
.gauge-unit{font-size:12px;color:var(--faint);font-family:var(--mono);margin-top:4px}
.gauge-label{
  font-size:12px;letter-spacing:.16em;text-transform:uppercase;font-weight:600;
  padding:6px 14px;border-radius:999px;border:1px solid var(--border-2);
}
.tone-good .gauge-label{color:var(--green);border-color:rgba(52,211,153,.35);background:rgba(52,211,153,.08)}
.tone-ok .gauge-label{color:var(--accent);border-color:rgba(34,211,238,.35);background:rgba(34,211,238,.08)}
.tone-warn .gauge-label{color:var(--yellow);border-color:rgba(251,191,36,.35);background:rgba(251,191,36,.08)}
.tone-bad .gauge-label{color:var(--red);border-color:rgba(248,113,113,.35);background:rgba(248,113,113,.08)}

/* ---------- kpis ---------- */
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:8px 0 64px}
.kpi{
  background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:20px 20px 18px;
  position:relative;overflow:hidden;
}
.kpi::after{content:"";position:absolute;inset:0;background:linear-gradient(180deg,rgba(255,255,255,.03),transparent);pointer-events:none}
.kpi-value{font-size:30px;font-weight:700;letter-spacing:-.02em;line-height:1.1}
.kpi-label{font-size:12px;color:var(--text);margin-top:8px;font-weight:600}
.kpi-sub{font-size:11.5px;color:var(--faint);margin-top:3px}
.kpi.bad .kpi-value{color:var(--red)}
.kpi.warn .kpi-value{color:var(--yellow)}
.kpi.good .kpi-value{color:var(--green)}

/* ---------- sections ---------- */
section{padding:46px 0;border-top:1px solid var(--border)}
.sec-head{margin-bottom:26px}
.sec-head h2{font-size:24px;margin:0 0 8px;letter-spacing:-.01em}
.sec-head p{margin:0;color:var(--muted);max-width:78ch;font-size:14.5px}

/* ---------- timeline ---------- */
.timeline-controls{display:flex;flex-wrap:wrap;gap:24px;align-items:center;justify-content:space-between;margin-bottom:26px}
.scenario-buttons{display:flex;gap:6px;background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:4px}
.scenario{
  background:transparent;border:0;color:var(--muted);font:inherit;font-size:12.5px;
  padding:8px 14px;border-radius:7px;cursor:pointer;display:flex;gap:7px;align-items:center;transition:.15s;
}
.scenario span{font-family:var(--mono);font-size:11px;color:var(--faint)}
.scenario:hover{color:var(--text)}
.scenario.active{background:var(--panel-2);color:var(--text);box-shadow:0 1px 0 rgba(255,255,255,.06) inset}
.scenario.active span{color:var(--accent)}
.slider-wrap{display:flex;align-items:center;gap:14px;font-size:12.5px;color:var(--muted)}
.slider-wrap strong{color:var(--accent);font-family:var(--mono);font-size:14px}
input[type=range]{-webkit-appearance:none;appearance:none;height:4px;width:190px;border-radius:99px;background:linear-gradient(90deg,var(--accent),var(--accent-2));outline:none}
input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:16px;height:16px;border-radius:50%;background:var(--text);border:3px solid var(--bg);box-shadow:0 0 0 1px var(--border-2);cursor:pointer}
input[type=range]::-moz-range-thumb{width:12px;height:12px;border-radius:50%;background:var(--text);border:3px solid var(--bg);cursor:pointer}

.timeline{background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:22px 24px 10px}
.tl-axis{position:relative;height:22px;margin-bottom:6px;border-bottom:1px dashed var(--border-2)}
.tl-axis-label,.tl-axis-end{position:absolute;top:0;font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint);font-family:var(--mono)}
.tl-axis-label{left:0}
.tl-axis-end{right:0}
.tl-axis-crqc{position:absolute;top:0;transform:translateX(-50%);font-size:10px;font-family:var(--mono);color:var(--red);white-space:nowrap}
.tl-row{display:grid;grid-template-columns:220px 1fr;gap:18px;align-items:center;padding:11px 0;border-bottom:1px solid rgba(255,255,255,.04)}
.tl-row:last-child{border-bottom:0}
.tl-label{display:flex;flex-direction:column;min-width:0}
.tl-name{font-size:13px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tl-meta{font-size:10.5px;color:var(--faint);font-family:var(--mono)}
.tl-track{position:relative;height:26px;display:flex;align-items:center}
.tl-bar{display:flex;height:18px;width:100%;border-radius:5px;overflow:hidden;background:rgba(255,255,255,.035)}
.tl-seg{height:100%}
.tl-data{background:linear-gradient(90deg,rgba(34,211,238,.85),rgba(34,211,238,.45))}
.tl-migrate{background:repeating-linear-gradient(135deg,rgba(167,139,250,.55) 0 6px,rgba(167,139,250,.25) 6px 12px)}
.tl-crqc{position:absolute;top:-4px;bottom:-4px;width:2px;background:var(--red);box-shadow:0 0 8px rgba(248,113,113,.8);transition:left .25s ease}
.tl-verdict{position:absolute;right:0;top:50%;transform:translateY(-50%);font-size:9.5px;font-family:var(--mono);letter-spacing:.08em;padding:2px 7px;border-radius:4px;opacity:0;transition:.2s}
.tl-row.exposed .tl-verdict{opacity:1;background:rgba(248,113,113,.14);color:var(--red);border:1px solid rgba(248,113,113,.3)}
.tl-row.safe .tl-verdict{opacity:1;background:rgba(52,211,153,.12);color:var(--green);border:1px solid rgba(52,211,153,.3)}
.timeline-legend{display:flex;flex-wrap:wrap;gap:22px;align-items:center;margin-top:18px;font-size:11.5px;color:var(--muted)}
.timeline-legend .sw{display:inline-block;width:12px;height:12px;border-radius:3px;margin-right:7px;vertical-align:-2px}
.sw-data{background:linear-gradient(90deg,rgba(34,211,238,.85),rgba(34,211,238,.45))}
.sw-migrate{background:repeating-linear-gradient(135deg,rgba(167,139,250,.55) 0 4px,rgba(167,139,250,.25) 4px 8px)}
.sw-crqc{background:var(--red);border-radius:1px;width:3px}
.tl-summary{margin-left:auto;font-family:var(--mono);color:var(--text)}

/* ---------- findings ---------- */
.toolbar{display:flex;flex-wrap:wrap;gap:14px;align-items:center;justify-content:space-between;margin-bottom:16px}
.filters{display:flex;gap:6px;flex-wrap:wrap}
.chip{
  background:var(--panel);border:1px solid var(--border);color:var(--muted);font:inherit;font-size:12px;
  padding:7px 12px;border-radius:8px;cursor:pointer;display:flex;gap:7px;align-items:center;transition:.15s;
}
.chip span{font-family:var(--mono);font-size:10.5px;color:var(--faint)}
.chip:hover{color:var(--text);border-color:var(--border-2)}
.chip.active{background:rgba(34,211,238,.10);border-color:rgba(34,211,238,.4);color:var(--accent)}
.chip.active span{color:var(--accent)}
.search{
  background:var(--panel);border:1px solid var(--border);border-radius:9px;color:var(--text);
  font:inherit;font-size:12.5px;padding:9px 14px;min-width:280px;outline:none;transition:.15s;
}
.search:focus{border-color:rgba(34,211,238,.5);box-shadow:0 0 0 3px rgba(34,211,238,.10)}
.search::placeholder{color:var(--faint)}

.table-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:14px;background:var(--panel)}
table.findings{width:100%;border-collapse:collapse;font-size:12.5px}
table.findings th{
  text-align:left;font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--faint);
  font-weight:600;padding:13px 16px;border-bottom:1px solid var(--border);white-space:nowrap;
}
table.findings td{padding:13px 16px;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:top}
table.findings tr:last-child td{border-bottom:0}
table.findings tbody tr{transition:background .12s}
table.findings tbody tr:hover{background:rgba(255,255,255,.025)}
.f-title{font-weight:600;margin-bottom:2px}
.f-note{color:var(--faint);font-size:11px;max-width:60ch}
.prio{color:var(--faint);font-size:11px}
.loc{color:var(--muted);font-size:11.5px;word-break:break-all;max-width:260px}
.num{text-align:right}
.pill{display:inline-block;font-size:9.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;padding:3px 8px;border-radius:5px;white-space:nowrap}
.sev-critical{background:rgba(248,113,113,.16);color:#fca5a5;border:1px solid rgba(248,113,113,.3)}
.sev-high{background:rgba(251,146,60,.14);color:#fdba74;border:1px solid rgba(251,146,60,.3)}
.sev-medium{background:rgba(251,191,36,.12);color:#fcd34d;border:1px solid rgba(251,191,36,.28)}
.sev-low{background:rgba(34,211,238,.10);color:#67e8f9;border:1px solid rgba(34,211,238,.25)}
.sev-info{background:rgba(255,255,255,.06);color:var(--muted);border:1px solid var(--border)}
.sev-safe{background:rgba(52,211,153,.12);color:#6ee7b7;border:1px solid rgba(52,211,153,.3)}
.pill.new{background:rgba(167,139,250,.18);color:#d8b4fe;border:1px solid rgba(167,139,250,.45);margin-left:4px}
.baseline-note{margin:18px 0 0;padding:13px 16px;border-radius:12px;font-size:12.5px;border:1px solid var(--border);background:var(--panel);color:var(--muted)}
.baseline-note.good{border-color:rgba(52,211,153,.3);background:rgba(52,211,153,.06)}
.baseline-note.bad{border-color:rgba(251,191,36,.35);background:rgba(251,191,36,.06)}
.sens{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-top:20px}
.sens-cell{background:var(--panel);border:1px solid var(--border);border-radius:11px;padding:14px 16px;text-align:center}
.sens-year{font-size:11px;color:var(--faint);letter-spacing:.12em}
.sens-value{font-size:28px;font-weight:700;line-height:1.15;margin:4px 0}
.sens-sub{font-size:10.5px;color:var(--faint)}
.sens-note{grid-column:1/-1;font-size:11px;color:var(--faint);padding:2px 2px 0}
.repl{color:var(--green)}
.empty{padding:40px;text-align:center;color:var(--faint);border:1px dashed var(--border-2);border-radius:14px;font-size:13px}

/* ---------- endpoints ---------- */
.ep-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:16px}
.ep-card{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:18px 20px;transition:.2s}
.ep-card:hover{border-color:var(--border-2);transform:translateY(-2px)}
.ep-card.down{opacity:.65}
.ep-card.exposed{border-color:rgba(248,113,113,.35);background:rgba(248,113,113,.04)}
.ep-card.legacy{border-color:rgba(251,191,36,.28)}
.ep-card.safe{border-color:rgba(52,211,153,.3)}
.cap-exposed{color:var(--red)}
.ep-card header{display:flex;align-items:center;gap:10px;justify-content:space-between;margin-bottom:14px}
.ep-host{font-size:13px;font-weight:600}
.ep-card dl{margin:0;display:grid;grid-template-columns:1fr 1fr;gap:9px 14px}
.ep-card dl div{min-width:0}
.ep-card dt{font-size:9.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint)}
.ep-card dd{margin:1px 0 0;font-size:11.5px;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ep-verdict{margin-top:14px;padding-top:12px;border-top:1px solid rgba(255,255,255,.05);font-size:11.5px;color:var(--muted)}

/* ---------- algorithms ---------- */
.algo-head,.algo-row{display:grid;grid-template-columns:260px 1fr 70px 220px;gap:16px;align-items:center}
.algo-head{font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--faint);padding:0 0 12px;border-bottom:1px solid var(--border);margin-bottom:6px}
.algo-row{padding:9px 0;border-bottom:1px solid rgba(255,255,255,.04)}
.algo-row:last-child{border-bottom:0}
.algo-name{font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.algo-bar{height:8px;border-radius:99px;background:rgba(255,255,255,.05);overflow:hidden}
.algo-bar span{display:block;height:100%;border-radius:99px;background:var(--accent);opacity:.75}
.algo-bar span.sev-critical{background:var(--red)}
.algo-bar span.sev-high{background:var(--orange)}
.algo-bar span.sev-medium{background:var(--yellow)}
.algo-bar span.sev-low{background:var(--accent)}
.algo-count{font-size:11.5px;color:var(--muted);text-align:right}
.algo-repl{font-size:11.5px;color:var(--green);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* ---------- roadmap ---------- */
.phase{display:grid;grid-template-columns:64px 1fr;gap:22px;padding:22px 0;border-bottom:1px solid rgba(255,255,255,.05)}
.phase:last-child{border-bottom:0}
.phase-num{font-family:var(--mono);font-size:22px;color:var(--faint);font-weight:600;padding-top:2px}
.phase-body header{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap}
.phase-body h3{margin:0;font-size:17px;font-weight:650;letter-spacing:-.01em}
.phase-window{font-size:10.5px;color:var(--accent);letter-spacing:.08em;padding:3px 9px;border:1px solid rgba(34,211,238,.25);border-radius:6px;background:rgba(34,211,238,.06)}
.phase-body p{color:var(--muted);font-size:13px;margin:8px 0 12px;max-width:80ch}
.phase-meta{display:flex;flex-wrap:wrap;gap:8px;align-items:center;font-size:10.5px;color:var(--faint)}
.tag{font-family:var(--mono);font-size:10px;padding:2px 8px;border-radius:5px;background:rgba(255,255,255,.05);border:1px solid var(--border);color:var(--muted)}

/* ---------- methodology ---------- */
.meth{display:grid;grid-template-columns:1fr 1fr;gap:40px}
.meth h3{font-size:15px;margin:0 0 10px}
.meth p{color:var(--muted);font-size:13.5px;margin:0 0 12px}
.formula{
  font-family:var(--mono);font-size:12.5px;line-height:1.9;background:rgba(34,211,238,.04);
  border:1px solid rgba(34,211,238,.16);border-left:3px solid var(--accent);border-radius:10px;padding:16px 18px;color:var(--text);
  white-space:pre-wrap;overflow-x:auto;
}
.formula .cm{color:var(--faint)}
.refs{list-style:none;padding:0;margin:0;font-size:12.5px;color:var(--muted)}
.refs li{padding:7px 0;border-bottom:1px solid rgba(255,255,255,.04)}
.refs li:last-child{border-bottom:0}
.refs b{color:var(--text);font-weight:600}

footer{border-top:1px solid var(--border);margin-top:40px;padding:34px 0;color:var(--faint);font-size:12px;display:flex;flex-wrap:wrap;gap:20px;justify-content:space-between;align-items:center}
.footer-brand{display:flex;align-items:center;gap:10px;letter-spacing:.1em;font-weight:600;color:var(--text);font-size:11px}

/* ---------- v3: simulator, chains, compliance, tables ---------- */
.sim{display:grid;grid-template-columns:1.2fr .8fr;gap:28px;border:1px solid var(--border);background:var(--panel);border-radius:16px;padding:26px}
.sim-controls{display:flex;flex-direction:column;gap:18px}
.sim-controls label{display:flex;flex-direction:column;gap:8px;font-size:13px;color:var(--muted)}
.sim-controls output{color:var(--accent);font-size:15px}
.sim-controls input[type=range]{accent-color:var(--accent);width:100%}
.sim-check{flex-direction:row!important;align-items:center;gap:10px!important}
.sim-output{display:flex;flex-direction:column;justify-content:center;gap:8px;border-left:1px solid var(--border);padding-left:28px}
.sim-number{font-size:44px;font-weight:700;line-height:1;color:var(--text)}
.sim-bar{height:8px;border-radius:999px;background:rgba(255,255,255,.08);overflow:hidden;margin-top:8px}
.sim-bar span{display:block;height:100%;background:linear-gradient(90deg,var(--yellow),var(--red));border-radius:999px;transition:width .3s}
.chain-card{border:1px solid var(--border);border-radius:14px;background:var(--panel);padding:20px;margin-bottom:16px}
.chain-card header{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;font-size:13px}
.chain-list{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:10px}
.chain-node{display:grid;grid-template-columns:110px 1fr;gap:4px 14px;border-left:2px solid var(--border-2);padding:8px 0 8px 14px}
.chain-node.broken{border-left-color:var(--red)}
.chain-node.weakened{border-left-color:var(--yellow)}
.chain-node.safe{border-left-color:var(--green)}
.chain-role{font-size:10.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--faint);grid-row:span 2;align-self:center}
.chain-subject{font-weight:600;font-size:14px;word-break:break-word}
.chain-meta{font-size:11.5px;color:var(--muted);grid-column:2}
.chain-pqc{margin-top:14px;padding:10px 14px;border-radius:10px;font-size:12px;display:flex;gap:10px;flex-wrap:wrap;justify-content:space-between}
.chain-pqc.bad{background:rgba(248,113,113,.08);border:1px solid rgba(248,113,113,.3);color:#fecaca}
.chain-pqc.good{background:rgba(52,211,153,.08);border:1px solid rgba(52,211,153,.3);color:#a7f3d0}
.comp-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:18px}
.comp-card{border:1px solid var(--border);border-radius:14px;background:var(--panel);padding:20px}
.comp-card.good{border-color:rgba(52,211,153,.3)}
.comp-card.warn{border-color:rgba(251,191,36,.3)}
.comp-card.bad{border-color:rgba(248,113,113,.3)}
.comp-card header{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}
.comp-card h3{margin:0;font-size:15px}
.comp-score{font-size:24px;font-weight:700;margin:10px 0 2px}
.comp-score span{font-size:12px;color:var(--faint);font-weight:400}
.comp-card p{font-size:12px;margin:0 0 12px}
.ctl-list{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:8px;font-size:12.5px}
.ctl{display:flex;gap:8px;align-items:flex-start}
.ctl-mark{font-weight:700}
.ctl.pass .ctl-mark{color:var(--green)}
.ctl.fail .ctl-mark{color:var(--red)}
.ctl-count{color:var(--red);margin-left:6px;font-size:11px}
.ctl .muted{font-size:11.5px}
.data-table{width:100%;border-collapse:collapse;font-size:12.5px}
.data-table th{text-align:left;color:var(--faint);font-weight:600;font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;padding:0 12px 10px 0;border-bottom:1px solid var(--border)}
.data-table td{padding:9px 12px 9px 0;border-bottom:1px solid var(--border);vertical-align:top}

@media (max-width:900px){
  .hero{grid-template-columns:1fr;gap:28px;padding-top:44px}
  .sim{grid-template-columns:1fr}
  .sim-output{border-left:0;border-top:1px solid var(--border);padding:20px 0 0}
  .comp-grid{grid-template-columns:1fr}
  .kpis{grid-template-columns:repeat(2,1fr)}
  .meth{grid-template-columns:1fr}
  .tl-row{grid-template-columns:1fr;gap:6px}
  .algo-head{display:none}
  .algo-row{grid-template-columns:1fr 60px;row-gap:6px}
  .algo-bar{grid-column:1/-1;order:3}
  .algo-repl{grid-column:1/-1;order:4}
  h1{font-size:34px}
}
@media print{
  body{background:#fff;color:#111}
  .topbar,input,.scenario-buttons{display:none}
  section{page-break-inside:avoid}
}
</style>
</head>
<body>

<div class="topbar">
  <div class="topbar-inner">
    <div class="brand"><span class="brand-mark"></span> MOSCA <small>post-quantum exposure scanner</small></div>
    <nav>
      <a href="#timeline">Timeline</a>
      <a href="#simulator">Simulator</a>
      <a href="#findings">Findings</a>
      <a href="#endpoints">Endpoints</a>
      ${sshEndpoints.length ? '<a href="#ssh">SSH</a>' : ''}
      ${capturedSessions.length ? '<a href="#captures">Captures</a>' : ''}
      <a href="#chains">Chains</a>
      <a href="#compliance">Compliance</a>
      <a href="#roadmap">Roadmap</a>
      <a href="#methodology">Method</a>
    </nav>
  </div>
</div>

<main class="wrap">

  <section class="hero" style="border-top:0">
    <div>
      <div class="eyebrow">Post-quantum exposure report</div>
      <h1>${esc(projectName)} is <em>${esc(v.label.toLowerCase())}</em>.</h1>
      <p class="lede">${esc(v.text)}</p>
      <div class="hero-meta">
        <span>Generated <b>${generated.toISOString().replace('T', ' ').slice(0, 19)} UTC</b></span>
        <span>Scope <b>${s.byKind.source + s.byKind.config} code findings</b></span>
        <span>CRQC <b>${s.crqcYear}</b></span>
        <span>Actionable <b>${s.actionable}</b></span>
        ${s.capturedSessions ? `<span>Captured <b>${s.capturedSessions} session${s.capturedSessions === 1 ? '' : 's'}</b></span>` : ''}
      </div>
    </div>
    ${renderGauge(s.quantumReadinessIndex)}
  </section>

  ${s.baseline?.supplied ? `<div class="baseline-note ${s.baseline.newFindings > 0 ? 'bad' : 'good'}">
    <b>Baseline comparison.</b>
    ${s.baseline.newFindings} new finding${s.baseline.newFindings === 1 ? '' : 's'} since ${esc(s.baseline.createdAt || 'the recorded baseline')} ·
    ${s.baseline.existingFindings} existing ·
    ${s.baseline.resolvedFindings} resolved.
    ${s.baseline.newFindings > 0 ? 'Regressions are marked <span class="pill new">new</span>.' : 'No regressions.'}
  </div>` : ''}

  <div class="kpis">
    ${renderKpi('Harvest-now-decrypt-later', s.hndlApplicable ? `${s.hndlExposure}%` : 'n/a', s.hndlApplicable ? 'of internet-facing key exchange is classical-only' : 'no live endpoints inspected', s.hndlApplicable ? (s.hndlExposure > 50 ? 'bad' : s.hndlExposure > 0 ? 'warn' : 'good') : '')}
    ${renderKpi('Inside the Mosca window', String(s.exposedItems), `of ${s.totalFindings} findings are already exposed`, s.exposedItems > 0 ? 'warn' : 'good')}
    ${renderKpi('Critical findings', String(s.bySeverity.critical), `${s.bySeverity.high} high · ${s.bySeverity.medium} medium`, s.bySeverity.critical > 0 ? 'bad' : 'good')}
    ${renderKpi('Migration effort', `${s.effortDays}d`, 'estimated engineer-days', '')}
    ${s.capturedHndlApplicable ? renderKpi('HNDL Captured Ratio', `${s.hndlCapturedRatio}%`, `${s.capturedClassicalSessions} of ${s.capturedSessions} recorded sessions classical-only`, s.hndlCapturedRatio > 0 ? 'bad' : 'good') : ''}
  </div>

  <section id="timeline">
    <div class="sec-head">
      <h2>Mosca's inequality, on your estate</h2>
      <p>Each bar is an algorithm in use. The solid section is how long the data it protects must stay secret; the hatched section is the time a migration is expected to take. When the bar crosses the red line, the data is already exposed — an adversary who recorded it today can read it later. Move the line to test the assumption.</p>
    </div>
    ${renderTimeline(analysis.items, s)}
    ${renderSensitivity(s.sensitivity)}
  </section>

  <section id="simulator">
    <div class="sec-head">
      <h2>Crypto-agility simulator</h2>
      <p>The Mosca window is not a fixed fact; it is a set of assumptions about the adversary and about how fast you can migrate. Move the CRQC year and the migration speed to see which findings cross the line. This is scenario planning, not a prediction.</p>
    </div>
    ${renderSimulator(analysis)}
  </section>

  <section id="findings">
    <div class="sec-head">
      <h2>Findings</h2>
      <p>Ranked by severity and by the Mosca score. The <span class="mono">Mosca</span> column shows the inequality behind each item: <span class="mono">shelf life + lead time vs. years to CRQC</span>.</p>
    </div>
    ${renderFindings(analysis.items)}
  </section>

  <section id="endpoints">
    <div class="sec-head">
      <h2>Live TLS endpoints</h2>
      <p>Each endpoint was probed with a hand-built ClientHello that offers the post-quantum hybrid group <span class="mono">X25519MLKEM768</span> (0x11EC). The reported key exchange is what the server <em>chose</em>, not what the local runtime supports.</p>
    </div>
    ${renderEndpoints(endpoints)}
  </section>

  <section id="chains">
    <div class="sec-head">
      <h2>Certificate chains</h2>
      <p>Every certificate in the peer chain, not just the leaf. A modern leaf signed by a long-lived RSA intermediate is a chain problem: rotating the leaf does not remove the exposure.</p>
    </div>
    ${renderChainTree(analysis.endpoints || endpoints)}
  </section>

  ${sshEndpoints.length ? `<section id="ssh">
    <div class="sec-head">
      <h2>Live SSH endpoints</h2>
      <p>Each server was asked for its <span class="mono">SSH_MSG_KEXINIT</span> with a minimal RFC 4253 exchange. The probe never authenticates and never completes key exchange; the advertised algorithm lists are the evidence.</p>
    </div>
    ${renderSshEndpoints(sshEndpoints)}
  </section>` : ''}

  ${capturedSessions.length ? `<section id="captures">
    <div class="sec-head">
      <h2>Captured sessions (passive PCAP harvest)</h2>
      <p>These sessions were already recorded in a PCAP/PCAPNG file. Nothing was sent to the servers. Each card shows what the recording actually negotiated and whether the capture date places it inside the Mosca window. HNDL Captured Ratio: <b>${s.hndlCapturedRatio}%</b> classical-only.</p>
    </div>
    ${renderCapturedSessions(capturedSessions)}
  </section>` : ''}

  <section id="algorithms">
    <div class="sec-head">
      <h2>Cryptographic inventory</h2>
      <p>Every primitive observed, with its occurrence count and the recommended replacement.</p>
    </div>
    ${renderAlgorithms(analysis.algorithms)}
  </section>

  <section id="compliance">
    <div class="sec-head">
      <h2>Compliance gates</h2>
      <p>A named standard is a better audit artefact than a score. Each control names the finding and the remediation an auditor will ask for.</p>
    </div>
    ${renderCompliance(analysis.compliance)}
  </section>

  <section id="supply-chain">
    <div class="sec-head">
      <h2>Cryptographic supply chain</h2>
      <p>Lockfile packages that fix an algorithm on your behalf. A quantum-vulnerable TLS library is a finding even when your own code calls the right API.</p>
    </div>
    ${renderDependencies(analysis.dependencies?.packages || [])}
  </section>

  <section id="artifacts">
    <div class="sec-head">
      <h2>On-disk key and certificate artefacts</h2>
      <p>PEM, DER, JWK and OpenSSH material found in the repository. Only metadata is read; private key bodies are never emitted.</p>
    </div>
    ${renderArtifacts(analysis.artifacts)}
  </section>

  <section id="roadmap">
    <div class="sec-head">
      <h2>Migration roadmap</h2>
      <p>Ordered by dependency, not just severity. Key exchange comes before signatures because harvest-now-decrypt-later is the only exposure that cannot be repaired after the fact.</p>
    </div>
    ${renderRoadmap(analysis.roadmap)}
  </section>

  <section id="methodology">
    <div class="sec-head">
      <h2>Method</h2>
      <p>Everything in this report is reproducible from the command line. The scoring model is documented, versioned, and has no hidden weights.</p>
    </div>
    <div class="meth">
      <div>
        <h3>The Mosca inequality</h3>
        <p>Mosca's theorem says a system is quantum-safe only when the sum of the time data must stay confidential and the time needed to migrate is shorter than the time until a cryptographically relevant quantum computer exists.</p>
        <div class="formula">exposed  ⇔  shelfLife + migrationLeadTime &gt; yearsToCRQC

<span class="cm"># shelfLife          years the data must stay secret</span>
<span class="cm"># migrationLeadTime  derived from how widely the primitive is used</span>
<span class="cm"># yearsToCRQC        configurable planning assumption (default 2033)</span></div>
        <h3 style="margin-top:22px">The score</h3>
        <p>Each finding is scored 0–100 as a weighted sum of quantum vulnerability (0.40), data durability (0.20), breadth of use (0.15), classical weakness (0.15) and exposure surface (0.10).</p>
      </div>
      <div>
        <h3>References</h3>
        <ul class="refs">
          <li><b>FIPS 203</b> — ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)</li>
          <li><b>FIPS 204</b> — ML-DSA (Module-Lattice-Based Digital Signature)</li>
          <li><b>FIPS 205</b> — SLH-DSA (Stateless Hash-Based Digital Signature)</li>
          <li><b>NIST IR 8547</b> (draft) — Transition to Post-Quantum Cryptography Standards</li>
          <li><b>RFC 8996</b> — Deprecating TLS 1.0 and TLS 1.1</li>
          <li><b>draft-ietf-tls-ecdhe-mlkem</b> — Hybrid ECDHE-MLKEM key agreement for TLS 1.3</li>
          <li><b>CycloneDX 1.6</b> — Cryptography Bill of Materials</li>
          <li><b>CNSA 2.0</b> — NSA Commercial National Security Algorithm Suite</li>
        </ul>
      </div>
    </div>
  </section>

  <footer>
    <div class="footer-brand"><span class="brand-mark" style="width:16px;height:16px"></span> MOSCA</div>
    <div>Generated by MOSCA v${esc(toolVersion)} · ${s.totalFindings} findings · scan completed in ${meta.durationMs ?? 0} ms</div>
    <div><a href="#" id="download-cbom">Download CBOM (CycloneDX 1.6)</a></div>
  </footer>
</main>

<script id="mosca-data" type="application/json">${JSON.stringify(data).replace(/</g, '\\u003c')}</script>
<script id="mosca-cbom" type="application/json">${JSON.stringify(cbomDoc).replace(/</g, '\\u003c')}</script>
<script>
(function(){
  var data = JSON.parse(document.getElementById('mosca-data').textContent);

  /* ---------------- Mosca timeline ---------------- */
  var timeline = document.querySelector('.timeline');
  if (timeline) {
    var maxYears = Number(timeline.dataset.maxyears);
    var nowYear = Number(timeline.dataset.nowyear);
    var rows = Array.prototype.slice.call(document.querySelectorAll('.tl-row'));
    var slider = document.getElementById('crqc');
    var yearLabel = document.getElementById('crqc-year');
    var axisLabel = document.getElementById('crqc-label');
    var summary = document.getElementById('tl-summary');

    function render(year) {
      var years = year - nowYear;
      var pct = Math.min(100, Math.max(0, (years / maxYears) * 100));
      document.querySelectorAll('.tl-crqc').forEach(function(el){ el.style.left = pct + '%'; });
      if (axisLabel) axisLabel.style.left = pct + '%';
      if (yearLabel) yearLabel.textContent = year;
      var exposed = 0;
      rows.forEach(function(row){
        var shelf = Number(row.dataset.shelf);
        var lead = Number(row.dataset.lead);
        var isExposed = (shelf + lead) > years;
        row.classList.toggle('exposed', isExposed);
        row.classList.toggle('safe', !isExposed);
        var v = row.querySelector('.tl-verdict');
        if (v) v.textContent = isExposed ? 'EXPOSED' : 'SAFE';
        if (isExposed) exposed++;
      });
      if (summary) summary.textContent = exposed + ' of ' + rows.length + ' algorithms exposed';
    }

    if (slider) {
      slider.addEventListener('input', function(){
        document.querySelectorAll('.scenario').forEach(function(b){ b.classList.remove('active'); });
        render(Number(slider.value));
      });
    }
    document.querySelectorAll('.scenario').forEach(function(btn){
      btn.addEventListener('click', function(){
        document.querySelectorAll('.scenario').forEach(function(b){ b.classList.remove('active'); });
        btn.classList.add('active');
        var y = Number(btn.dataset.year);
        if (slider) slider.value = String(y);
        render(y);
      });
    });
    render(Number(slider ? slider.value : (data.summary && data.summary.crqcYear) || 2033));
  }

  /* ---------------- findings filter ---------------- */
  var body = document.getElementById('finding-body');
  var search = document.getElementById('search');
  var noResults = document.getElementById('no-results');
  var activeFilter = 'all';

  function applyFilter() {
    if (!body) return;
    var q = (search && search.value || '').toLowerCase().trim();
    var visible = 0;
    Array.prototype.forEach.call(body.querySelectorAll('tr.finding'), function(row){
      var sevOk = activeFilter === 'all'
        || (activeFilter === 'new' ? row.dataset.new === '1' : row.dataset.sev === activeFilter);
      var textOk = !q || (row.dataset.text || '').indexOf(q) !== -1;
      var show = sevOk && textOk;
      row.style.display = show ? '' : 'none';
      if (show) visible++;
    });
    if (noResults) noResults.classList.toggle('hidden', visible !== 0);
  }

  document.querySelectorAll('.chip').forEach(function(chip){
    chip.addEventListener('click', function(){
      document.querySelectorAll('.chip').forEach(function(c){ c.classList.remove('active'); });
      chip.classList.add('active');
      activeFilter = chip.dataset.filter;
      applyFilter();
    });
  });
  if (search) search.addEventListener('input', applyFilter);
  applyFilter();

  /* ---------------- crypto-agility simulator ---------------- */
  (function(){
    var crqc = document.getElementById('sim-crqc');
    var lead = document.getElementById('sim-lead');
    if (!crqc || !lead) return;
    var hybrid = document.getElementById('sim-hybrid');
    var yearOut = document.getElementById('sim-year');
    var speedOut = document.getElementById('sim-speed');
    var exposedOut = document.getElementById('sim-exposed');
    var fill = document.getElementById('sim-bar-fill');
    var items = (data.items || []).filter(function(i){ return i.quantum !== 'safe'; });
    var currentYear = (data.summary && data.summary.currentYear) || new Date().getFullYear();

    function run() {
      var year = Number(crqc.value);
      var scale = Number(lead.value) / 100;
      if (yearOut) yearOut.textContent = String(year);
      if (speedOut) speedOut.textContent = scale.toFixed(1) + '\u00d7';
      var exposed = 0;
      items.forEach(function(item){
        if (hybrid && hybrid.checked && item.primitive === 'key-agreement') return;
        var shelf = Number(item.shelfLife) || 0;
        var leadTime = Number(item.leadTime) || 0;
        if (shelf + leadTime * scale > year - currentYear) exposed++;
      });
      if (exposedOut) exposedOut.textContent = String(exposed);
      if (fill) fill.style.width = (items.length ? (exposed / items.length) * 100 : 0) + '%';
    }

    crqc.addEventListener('input', run);
    lead.addEventListener('input', run);
    if (hybrid) hybrid.addEventListener('change', run);
    run();
  })();

  /* ---------------- CBOM download ---------------- */
  var dl = document.getElementById('download-cbom');
  if (dl) {
    dl.addEventListener('click', function(e){
      e.preventDefault();
      var el = document.getElementById('mosca-cbom');
      var doc = {};
      try { doc = el ? JSON.parse(el.textContent) : {}; } catch (err) { doc = {}; }
      var blob = new Blob([JSON.stringify(doc, null, 2)], { type: 'application/json' });
      var a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'bom.cdx.json';
      a.click();
      setTimeout(function(){ URL.revokeObjectURL(a.href); }, 2000);
    });
  }
})();
</script>
</body>
</html>`;
}
