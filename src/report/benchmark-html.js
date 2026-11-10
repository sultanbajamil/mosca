/**
 * MOSCA — State of PQC benchmark report
 * =====================================
 *
 * One self-contained HTML file. No CDN, no web font, no analytics: the page
 * must render identically on an air-gapped laptop and on GitHub Pages. All
 * interactivity is a few dozen lines of vanilla JavaScript over data that is
 * embedded in the document.
 *
 * The interactive controls are the argument: a leaderboard shows where the
 * sector stands today, and the CRQC slider shows when "today" stops being
 * good enough. An insight card is written to be screenshotted on its own.
 */

const DEFAULT_MIGRATION_LEAD = 1;

const esc = (value) =>
  String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

function jsonForScript(value) {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026');
}

function gradeFor(score) {
  if (score == null || !Number.isFinite(Number(score))) return { grade: '—', color: '#5d6a82' };
  const value = Number(score);
  if (value >= 90) return { grade: 'A+', color: '#22c55e' };
  if (value >= 80) return { grade: 'A', color: '#34d399' };
  if (value >= 70) return { grade: 'B', color: '#22d3ee' };
  if (value >= 60) return { grade: 'C', color: '#fbbf24' };
  if (value >= 50) return { grade: 'D', color: '#fb923c' };
  if (value >= 40) return { grade: 'E', color: '#f97316' };
  return { grade: 'F', color: '#ef4444' };
}

function pct(part, total) {
  return total === 0 ? 0 : Math.round((part / total) * 1000) / 10;
}

function fmtDate(iso) {
  if (!iso) return 'unknown';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return String(iso);
  return date.toISOString().slice(0, 10);
}

/** Build the complete standalone page. */
export function buildBenchmarkHtml({ benchmark, title = 'The State of Post-Quantum Readiness', subtitle = '', toolVersion = '3.1.0', repository = 'https://github.com/sultanbajamil/mosca' }) {  const data = {
    title,
    subtitle,
    generatedAt: benchmark.generatedAt,
    currentYear: benchmark.currentYear,
    crqcYear: benchmark.crqcYear,
    toolVersion: benchmark.toolVersion || toolVersion,
    migrationLead: DEFAULT_MIGRATION_LEAD,
    sectors: benchmark.sectors,
    overall: benchmark.overall,
    targets: benchmark.targets.map((target) => ({
      name: target.name,
      host: target.host,
      sector: target.sector,
      sectorName: target.sectorName,
      dataLifetimeYears: target.dataLifetimeYears,
      reachable: target.reachable,
      hybrid: target.hybrid,
      hasClassical: target.hasClassical,
      kex: target.kex,
      sshKex: target.sshKex,
      protocol: target.protocol,
      debt: target.debt,
      score: target.score,
      error: target.error,
    })),
  };

  const sectorChips = [
    '<button class="chip active" data-sector="all" type="button">All sectors</button>',
    ...benchmark.sectors.map(
      (sector) =>
        `<button class="chip" data-sector="${esc(sector.id)}" type="button">${esc(sector.name || sector.id)}</button>`,
    ),
  ].join('');

  const generated = fmtDate(benchmark.generatedAt);
  const observed = benchmark.overall.observed;
  const total = benchmark.overall.total;
  const hybridAdoption = benchmark.overall.pqcHybridAdoption;
  const grade = benchmark.overall.grade || gradeFor(benchmark.overall.qri).grade;
  const gradeColor = benchmark.overall.gradeColor || gradeFor(benchmark.overall.qri).color;
  const globalQri = Number.isInteger(benchmark.overall.qri) ? benchmark.overall.qri : Number(benchmark.overall.qri).toFixed(1);

  // The initial server-side values are rendered for no-JS readers; the inline
  // script recomputes the same figures whenever the slider moves.
  const initialHndl = benchmark.overall.hndlExposure;
  const best = benchmark.sectors.find((sector) => sector.observed > 0);
  const worst = [...benchmark.sectors].reverse().find((sector) => sector.observed > 0);
  const maxLifetime = benchmark.sectors.reduce((max, sector) => Math.max(max, sector.dataLifetimeYears || 0), 0);
  const classicalDebt = benchmark.targets.reduce((sum, target) => sum + (target.debt?.length || 0), 0);

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<meta name="description" content="${esc(title)} — ${esc(subtitle || 'A live benchmark of post-quantum readiness across sectors.')}">
<title>${esc(title)}</title>
<style>
:root{
  --bg:#05070c;--panel:#0a0f1a;--panel-2:#0c1320;--border:rgba(255,255,255,.07);
  --text:#e8eefb;--muted:#8b9ab5;--faint:#5d6a82;
  --cyan:#22d3ee;--violet:#a78bfa;--green:#34d399;--amber:#fbbf24;--red:#f87171;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:
  radial-gradient(900px 500px at 15% -10%,rgba(34,211,238,.11),transparent 60%),
  radial-gradient(800px 500px at 90% 0%,rgba(167,139,250,.11),transparent 55%),var(--bg);
  color:var(--text);font-family:var(--sans);line-height:1.55;-webkit-font-smoothing:antialiased}
a{color:var(--cyan);text-decoration:none}
a:hover{text-decoration:underline}
.wrap{max-width:1180px;margin:0 auto;padding:0 28px}
.mono{font-family:var(--mono)}
.top{border-bottom:1px solid var(--border);background:rgba(5,7,12,.72);backdrop-filter:blur(8px);position:sticky;top:0;z-index:20}
.top-in{display:flex;align-items:center;justify-content:space-between;gap:20px;height:62px}
.brand{display:flex;align-items:center;gap:12px;font-family:var(--mono);font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
.brand b{color:var(--text);letter-spacing:.18em}
.dot{width:9px;height:9px;border-radius:50%;background:var(--green);box-shadow:0 0 0 4px rgba(52,211,153,.12)}
.top-links{display:flex;gap:18px;font-size:12px;color:var(--muted);font-family:var(--mono)}
.top-links a{color:var(--muted)}
.top-links a:hover{color:var(--text)}
header.hero{padding:64px 0 34px}
.kicker{font-family:var(--mono);font-size:11px;letter-spacing:.24em;text-transform:uppercase;color:var(--cyan);margin-bottom:18px}
h1{font-size:clamp(36px,6vw,66px);line-height:1.02;letter-spacing:-.035em;margin:0 0 18px;font-weight:740}
h1 .grad{background:linear-gradient(100deg,var(--cyan),var(--violet));-webkit-background-clip:text;background-clip:text;color:transparent}
.lede{max-width:760px;color:var(--muted);font-size:17px;margin:0}
.hero-meta{display:flex;flex-wrap:wrap;gap:9px;margin-top:26px}
.pill{font-family:var(--mono);font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;padding:5px 10px;border-radius:99px;border:1px solid var(--border);color:var(--muted);background:rgba(255,255,255,.02)}
.pill.live{border-color:rgba(52,211,153,.3);color:var(--green)}
.pill.warn{border-color:rgba(251,191,36,.3);color:var(--amber)}
section{padding:34px 0}
.sec-head{display:flex;align-items:flex-end;justify-content:space-between;gap:20px;margin-bottom:20px;flex-wrap:wrap}
h2{font-size:13px;font-family:var(--mono);letter-spacing:.18em;text-transform:uppercase;color:var(--muted);margin:0;font-weight:600}
.sec-head p{margin:0;color:var(--faint);font-size:12.5px;max-width:640px}
.kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}
.kpi{background:linear-gradient(160deg,var(--panel-2),var(--panel));border:1px solid var(--border);border-radius:14px;padding:18px 18px 16px;position:relative;overflow:hidden}
.kpi:before{content:"";position:absolute;inset:0 auto auto 0;width:100%;height:2px;background:linear-gradient(90deg,var(--cyan),transparent);opacity:.55}
.kpi .label{font-family:var(--mono);font-size:9.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--faint)}
.kpi .value{font-size:32px;font-weight:730;letter-spacing:-.03em;margin-top:8px;line-height:1}
.kpi .sub{font-size:11.5px;color:var(--muted);margin-top:7px}
.kpi.good .value{color:var(--green)}.kpi.bad .value{color:var(--red)}.kpi.warn .value{color:var(--amber)}
.insights{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.insight{position:relative;border:1px solid var(--border);border-radius:16px;padding:22px;background:
  linear-gradient(150deg,rgba(34,211,238,.07),transparent 45%),linear-gradient(160deg,var(--panel-2),var(--panel));overflow:hidden}
.insight:after{content:"";position:absolute;inset:auto -30% -60% auto;width:220px;height:220px;border-radius:50%;background:radial-gradient(circle,rgba(167,139,250,.14),transparent 70%)}
.insight .tag{font-family:var(--mono);font-size:9.5px;letter-spacing:.18em;text-transform:uppercase;color:var(--cyan)}
.insight .big{font-size:30px;font-weight:740;letter-spacing:-.03em;line-height:1.1;margin:14px 0 8px}
.insight p{margin:0;color:var(--muted);font-size:12.5px}
.insight .copy{position:absolute;top:14px;right:14px;border:1px solid var(--border);background:rgba(255,255,255,.03);color:var(--faint);font-family:var(--mono);font-size:9px;letter-spacing:.1em;text-transform:uppercase;border-radius:7px;padding:5px 8px;cursor:pointer;z-index:2}
.insight .copy:hover{color:var(--text);border-color:rgba(34,211,238,.35)}
.controls{display:grid;grid-template-columns:1fr 340px;gap:18px;margin-top:6px}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:16px 18px}
.chips{display:flex;flex-wrap:wrap;gap:8px}
.chip{border:1px solid var(--border);background:rgba(255,255,255,.02);color:var(--muted);font-family:var(--mono);font-size:10.5px;letter-spacing:.06em;padding:7px 11px;border-radius:99px;cursor:pointer}
.chip:hover{color:var(--text);border-color:rgba(34,211,238,.3)}
.chip.active{background:rgba(34,211,238,.1);border-color:rgba(34,211,238,.45);color:var(--text)}
.slider-head{display:flex;align-items:baseline;justify-content:space-between;gap:10px;font-family:var(--mono);font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--faint)}
.slider-head b{font-size:15px;color:var(--text);letter-spacing:0}
input[type=range]{width:100%;margin:14px 0 6px;appearance:none;height:3px;border-radius:9px;background:linear-gradient(90deg,var(--cyan),var(--violet));outline:none}
input[type=range]::-webkit-slider-thumb{appearance:none;width:17px;height:17px;border-radius:50%;background:#0b1220;border:2px solid var(--cyan);box-shadow:0 0 0 4px rgba(34,211,238,.13);cursor:pointer}
input[type=range]::-moz-range-thumb{width:15px;height:15px;border-radius:50%;background:#0b1220;border:2px solid var(--cyan);cursor:pointer}
.slider-note{font-size:11px;color:var(--faint);margin:2px 0 0}
.table-wrap{background:var(--panel);border:1px solid var(--border);border-radius:16px;overflow:hidden}
table{width:100%;border-collapse:collapse;font-size:12.5px}
thead th{font-family:var(--mono);font-size:9.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--faint);text-align:left;font-weight:600;padding:13px 14px;border-bottom:1px solid var(--border);background:rgba(255,255,255,.015);cursor:pointer;white-space:nowrap;user-select:none}
thead th:hover{color:var(--text)}
tbody td{padding:11px 14px;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:middle}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover{background:rgba(34,211,238,.025)}
.rank{font-family:var(--mono);color:var(--faint);font-size:11px;width:44px}
.org{font-weight:600}
.org small{display:block;font-weight:400;color:var(--faint);font-size:10.5px;margin-top:1px}
.sector-pill{font-family:var(--mono);font-size:9.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);border:1px solid var(--border);border-radius:6px;padding:3px 7px;white-space:nowrap}
.proto{font-family:var(--mono);font-size:10.5px;color:var(--muted);white-space:nowrap}
.badge{display:inline-flex;align-items:center;justify-content:center;min-width:34px;font-family:var(--mono);font-size:10.5px;font-weight:700;letter-spacing:.04em;border-radius:7px;padding:4px 7px;border:1px solid currentColor}
.hybrid{font-family:var(--mono);font-size:10.5px;white-space:nowrap}
.hybrid.yes{color:var(--green)}
.hybrid.no{color:var(--red)}
.hybrid.na{color:var(--faint)}
.score-cell{display:flex;align-items:center;gap:10px;min-width:180px}
.bar{flex:1;height:6px;border-radius:99px;background:rgba(255,255,255,.06);overflow:hidden}
.bar span{display:block;height:100%;border-radius:99px}
.score-num{font-family:var(--mono);font-size:11px;color:var(--muted);width:34px;text-align:right}
.debt{font-family:var(--mono);font-size:10px;color:var(--faint)}
.empty{padding:34px;text-align:center;color:var(--faint);font-size:12.5px}
.two-col{display:grid;grid-template-columns:1.2fr .8fr;gap:18px}
.sector-row{display:grid;grid-template-columns:1fr 54px 110px 110px;gap:12px;align-items:center;padding:12px 16px;border-bottom:1px solid rgba(255,255,255,.04)}
.sector-row:last-child{border-bottom:0}
.sector-row .name{font-weight:600;font-size:12.5px}
.sector-row .name small{display:block;font-weight:400;color:var(--faint);font-size:10.5px}
.sector-row .num{font-family:var(--mono);font-size:11.5px;text-align:right;color:var(--muted)}
.method{color:var(--muted);font-size:12.5px;max-width:780px}
.method h3{font-family:var(--mono);font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:var(--faint);margin:20px 0 8px}
.method ul{margin:0;padding-left:18px}
.method li{margin-bottom:6px}
footer{border-top:1px solid var(--border);margin-top:40px;padding:26px 0 44px;color:var(--faint);font-size:11.5px;font-family:var(--mono)}
footer .row{display:flex;justify-content:space-between;gap:18px;flex-wrap:wrap}
@media(max-width:940px){
  .kpis{grid-template-columns:repeat(2,1fr)}
  .insights{grid-template-columns:1fr}
  .controls{grid-template-columns:1fr}
  .two-col{grid-template-columns:1fr}
  .hide-sm{display:none}
  .wrap{padding:0 18px}
}
@media(max-width:620px){
  .kpis{grid-template-columns:1fr 1fr}
  h1{font-size:38px}
  .sector-row{grid-template-columns:1fr 44px}
  .sector-row .num:nth-child(n+3){display:none}
}
</style>
</head>
<body>
<div class="top"><div class="wrap top-in">
  <div class="brand"><span class="dot"></span><b>MOSCA</b><span>state of PQC</span></div>
  <div class="top-links">
    <a href="#leaderboard">Leaderboard</a>
    <a href="#sectors">Sectors</a>
    <a href="#method">Method</a>
    <a href="${esc(repository)}">GitHub ↗</a>
  </div>
</div></div>

<header class="hero"><div class="wrap">
  <div class="kicker">Global benchmark · TLS &amp; SSH · ${esc(String(observed))} of ${esc(String(total))} endpoints observed</div>
  <h1>${esc(title.split(' ').slice(0, -2).join(' '))} <span class="grad">${esc(title.split(' ').slice(-2).join(' '))}</span></h1>
  <p class="lede">${esc(subtitle || 'Which sectors are ready for a cryptographically relevant quantum computer, which are still recording classical handshakes, and how long their data stays secret after the recording is made.')}</p>
  <div class="hero-meta">
    <span class="pill live">Generated ${esc(generated)}</span>
    <span class="pill">CRQC assumption <b class="mono">${esc(String(benchmark.crqcYear))}</b></span>
    <span class="pill">${esc(String(benchmark.sectors.length))} sectors</span>
    <span class="pill warn">${esc(String(classicalDebt))} classical debt signals</span>
    <span class="pill">MOSCA v${esc(data.toolVersion)}</span>
  </div>
</div></header>

<div class="wrap">
  <section id="overview">
    <div class="kpis">
      <div class="kpi good">
        <div class="label">Global QRI</div>
        <div class="value" style="color:${esc(gradeColor)}">${esc(String(globalQri))}<span style="font-size:14px;color:var(--faint)">/100</span></div>
        <div class="sub">Grade ${esc(grade)} · ${esc(benchmark.overall.gradeLabel || '')}</div>
      </div>
      <div class="kpi ${hybridAdoption >= 50 ? 'good' : 'bad'}">
        <div class="label">PQC hybrid adoption</div>
        <div class="value">${esc(String(hybridAdoption))}%</div>
        <div class="sub">of observed endpoints negotiate a hybrid KEM</div>
      </div>
      <div class="kpi bad">
        <div class="label" id="hndl-label">HNDL exposure</div>
        <div class="value" id="hndl-value">${esc(String(initialHndl))}%</div>
        <div class="sub" id="hndl-sub">classical endpoints already inside the Mosca window</div>
      </div>
      <div class="kpi warn">
        <div class="label">Longest data lifetime</div>
        <div class="value">${esc(String(maxLifetime))}<span style="font-size:14px;color:var(--faint)">y</span></div>
        <div class="sub">the secret outlives most migration plans</div>
      </div>
      <div class="kpi">
        <div class="label">Observed / targeted</div>
        <div class="value">${esc(String(observed))}<span style="font-size:14px;color:var(--faint)">/${esc(String(total))}</span></div>
        <div class="sub">${esc(String(benchmark.overall.unreachable))} did not answer safely</div>
      </div>
    </div>
  </section>

  <section id="insights">
    <div class="sec-head">
      <h2>Insight cards</h2>
      <p>Each card is a complete claim with its number. Copy one into a deck, a post, or a board memo.</p>
    </div>
    <div class="insights">
      <article class="insight">
        <button class="copy" data-copy="insight-1" type="button">copy</button>
        <div class="tag">Adoption</div>
        <div class="big" id="insight-1">${esc(String(hybridAdoption))}% hybrid</div>
        <p>of the observed global endpoints negotiate a post-quantum hybrid key exchange today. The rest still produce recordings that a future quantum computer can open.</p>
      </article>
      <article class="insight">
        <button class="copy" data-copy="insight-2" type="button">copy</button>
        <div class="tag">Harvest now, decrypt later</div>
        <div class="big" id="insight-2">${esc(String(initialHndl))}% exposed</div>
        <p id="insight-2-note">At a ${esc(String(benchmark.crqcYear))} CRQC, classical endpoints whose data must stay secret for the sector lifetime are already inside the Mosca window.</p>
      </article>
      <article class="insight">
        <button class="copy" data-copy="insight-3" type="button">copy</button>
        <div class="tag">Sector spread</div>
        <div class="big" id="insight-3">${esc(best?.grade || '—')} vs ${esc(worst?.grade || '—')}</div>
        <p id="insight-3-note">${esc(best?.name || 'The leading sector')} leads at ${esc(String(best?.qri ?? 0))}; ${esc(worst?.name || 'the trailing sector')} trails at ${esc(String(worst?.qri ?? 0))}. A global average hides a ${esc(String(Math.max(0, Math.round((best?.qri || 0) - (worst?.qri || 0)) * 10) / 10))}-point gap.</p>
      </article>
    </div>
  </section>

  <section>
    <div class="controls">
      <div class="panel">
        <div class="slider-head"><span>Filter by sector</span><span id="visible-count" class="mono">${esc(String(observed))} observed</span></div>
        <div class="chips" style="margin-top:12px">${sectorChips}</div>
      </div>
      <div class="panel">
        <div class="slider-head"><span>CRQC assumption</span><b id="crqc-year">${esc(String(benchmark.crqcYear))}</b></div>
        <input type="range" id="crqc" min="2027" max="2045" step="1" value="${esc(String(benchmark.crqcYear))}" aria-label="CRQC year">
        <p class="slider-note">Slide to change the planning horizon. The Mosca window recalculates live: <span class="mono">data lifetime + migration lead vs. years to CRQC</span>.</p>
      </div>
    </div>
  </section>

  <section id="leaderboard">
    <div class="sec-head">
      <h2>Leaderboard</h2>
      <p>Scored from the key exchange each endpoint actually negotiated, with deductions for legacy TLS, weak ciphers and classical debt. Click a column to sort.</p>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th data-sort="rank">#</th>
          <th data-sort="name">Organization</th>
          <th class="hide-sm" data-sort="sector">Sector</th>
          <th data-sort="kex">Negotiated KEX</th>
          <th class="hide-sm" data-sort="protocol">Protocol</th>
          <th data-sort="score">Score</th>
          <th data-sort="grade">Grade</th>
        </tr></thead>
        <tbody id="leaderboard-body"></tbody>
      </table>
      <div class="empty" id="empty" style="display:none">No observed endpoints in this filter.</div>
    </div>
  </section>

  <section id="sectors">
    <div class="sec-head">
      <h2>Sector readiness</h2>
      <p>HNDL exposure is computed per sector from its own data lifetime, which is why two sectors with the same QRI can carry very different legal risk.</p>
    </div>
    <div class="table-wrap" id="sector-table"></div>
  </section>

  <section id="method">
    <div class="sec-head"><h2>Method</h2></div>
    <div class="method">
      <p>Every target is probed twice: a raw TLS ClientHello offering <span class="mono">X25519MLKEM768</span> (0x11EC) and a minimal RFC 4253 SSH exchange that reads <span class="mono">SSH_MSG_KEXINIT</span> without authenticating. The score is the negotiated posture, not the vendor's roadmap.</p>
      <h3>Scoring</h3>
      <ul>
        <li>Start at 100. A TLS endpoint without hybrid key exchange costs 40 points; legacy TLS costs 20; a weak cipher costs 15.</li>
        <li>An SSH endpoint without hybrid KEX costs 15. Every additional classical-debt signal costs 5, capped at 20.</li>
        <li>Grades: A+ ≥ 90, A ≥ 80, B ≥ 70, C ≥ 60, D ≥ 50, E ≥ 40, F below 40.</li>
      </ul>
      <h3>Harvest-now-decrypt-later</h3>
      <p>A sector is exposed when <span class="mono">data lifetime + ${DEFAULT_MIGRATION_LEAD}-year migration lead &gt; years to CRQC</span>. The data lifetime is the sector's confidentiality obligation, not the certificate lifetime. This is why healthcare and government remain exposed long after their TLS stacks are upgraded.</p>
      <h3>Limits</h3>
      <ul>
        <li>Only publicly reachable endpoints are observed. A missing host is reported, never guessed.</li>
        <li>The benchmark measures the negotiated handshake, not configuration drift, certificate policy or internal estate coverage.</li>
        <li>No packets beyond the handshake are sent, and no authentication is attempted.</li>
      </ul>
    </div>
  </section>
</div>

<footer><div class="wrap row">
  <span>MOSCA v${esc(data.toolVersion)} · generated ${esc(generated)} · ${esc(String(observed))} observed endpoints · zero runtime dependencies</span>
  <span><a href="${esc(repository)}">${esc(repository.replace(/^https?:\/\//, ''))}</a></span>
</div></footer>

<script>
(function(){
  "use strict";
  var DATA = ${jsonForScript(data)};
  var MIGRATION_LEAD = DATA.migrationLead;
  var state = { sector: 'all', crqc: DATA.crqcYear, sort: 'score', dir: -1 };

  function gradeFor(score){
    if(score==null||!isFinite(score)) return {grade:'—',color:'#5d6a82'};
    if(score>=90) return {grade:'A+',color:'#22c55e'};
    if(score>=80) return {grade:'A',color:'#34d399'};
    if(score>=70) return {grade:'B',color:'#22d3ee'};
    if(score>=60) return {grade:'C',color:'#fbbf24'};
    if(score>=50) return {grade:'D',color:'#fb923c'};
    if(score>=40) return {grade:'E',color:'#f97316'};
    return {grade:'F',color:'#ef4444'};
  }
  function pct(part,total){return total===0?0:Math.round(part/total*1000)/10;}
  function esc(v){return String(v==null?'':v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
  function visible(){return DATA.targets.filter(function(t){return state.sector==='all'||t.sector===state.sector;});}
  function observed(list){return list.filter(function(t){return t.score!=null;});}
  function hndlExposed(list){
    var yearsToCRQC = Math.max(0, state.crqc - DATA.currentYear);
    return observed(list).filter(function(t){
      return t.hasClassical && (t.dataLifetimeYears + MIGRATION_LEAD > yearsToCRQC);
    }).length;
  }
  function hndlPct(list){var obs=observed(list).length;return pct(hndlExposed(list),obs);}

  function renderKpis(){
    var list=visible(), obs=observed(list), exposed=hndlExposed(list);
    var el=document.getElementById('hndl-value');
    if(el) el.textContent = hndlPct(list)+'%';
    var sub=document.getElementById('hndl-sub');
    if(sub) sub.textContent = exposed+' of '+obs.length+' observed endpoints inside the Mosca window at '+state.crqc+'.';
    var count=document.getElementById('visible-count');
    if(count) count.textContent=obs.length+' observed · '+(list.length-obs.length)+' unreachable';
    var note=document.getElementById('insight-2-note');
    if(note) note.textContent='At a '+state.crqc+' CRQC, '+hndlPct(list)+'% of observed endpoints in this filter carry data that stays secret longer than the machine takes to arrive.';
    var big=document.getElementById('insight-2');
    if(big) big.textContent=hndlPct(list)+'% exposed';
  }

  function renderLeaderboard(){
    var list=visible().slice();
    var key=state.sort;
    list.sort(function(a,b){
      var av=a[key], bv=b[key];
      if(key==='rank'){av=a.score==null?-1:a.score;bv=b.score==null?-1:b.score;}
      if(av==null) av=-1; if(bv==null) bv=-1;
      if(typeof av==='string') return av.localeCompare(bv)*state.dir;
      return (av-bv)*state.dir;
    });
    var rows=list.map(function(t,i){
      var g=gradeFor(t.score), color=g.color;
      var score=t.score==null?'—':t.score;
      var hybrid=t.score==null?'<span class="hybrid na">not observed</span>':t.hybrid?'<span class="hybrid yes">● hybrid</span>':'<span class="hybrid no">○ classical</span>';
      var kex=t.kex&&t.kex!=='unknown'?t.kex:(t.sshKex||'unknown');
      var debt=t.debt&&t.debt.length?'<div class="debt">'+t.debt.slice(0,2).map(esc).join(' · ')+'</div>':'';
      return '<tr>'+
        '<td class="rank">'+(state.sort==='score'&&state.dir===-1?(i+1):i+1)+'</td>'+
        '<td class="org">'+esc(t.name)+'<small>'+esc(t.host)+'</small></td>'+
        '<td class="hide-sm"><span class="sector-pill">'+esc(t.sectorName||t.sector)+'</span></td>'+
        '<td>'+hybrid+'<div class="proto">'+esc(kex)+'</div>'+debt+'</td>'+
        '<td class="hide-sm proto">'+esc(t.protocol||'—')+'</td>'+
        '<td><div class="score-cell"><div class="bar"><span style="width:'+(score==='—'?0:score)+'%;background:'+color+'"></span></div><span class="score-num">'+esc(String(score))+'</span></div></td>'+
        '<td><span class="badge" style="color:'+color+'">'+esc(g.grade)+'</span></td>'+
      '</tr>';
    }).join('');
    var body=document.getElementById('leaderboard-body');
    if(body) body.innerHTML=rows;
    var empty=document.getElementById('empty');
    if(empty) empty.style.display=list.length?'none':'block';
  }

  function renderSectors(){
    var sectors=DATA.sectors.slice();
    if(state.sector!=='all') sectors=sectors.filter(function(s){return s.id===state.sector;});
    var html=sectors.map(function(s){
      var targets=DATA.targets.filter(function(t){return t.sector===s.id;});
      var obs=observed(targets);
      var exposure=hndlPct(targets);
      var g=gradeFor(s.qri);
      return '<div class="sector-row">'+
        '<div class="name">'+esc(s.name||s.id)+'<small>'+s.observed+' of '+s.total+' observed · '+s.dataLifetimeYears+'-year data lifetime</small></div>'+
        '<div class="num"><span class="badge" style="color:'+g.color+'">'+esc(s.grade)+'</span></div>'+
        '<div class="num">'+esc(String(s.qri))+'/100</div>'+
        '<div class="num" style="color:'+(exposure>0?'#f87171':'#34d399')+'">'+exposure+'% HNDL</div>'+
      '</div>';
    }).join('');
    var table=document.getElementById('sector-table');
    if(table) table.innerHTML=html||'<div class="empty">No sector data in this filter.</div>';
  }

  function renderInsights(){
    var list=visible(), obs=observed(list);
    var hybrid=obs.filter(function(t){return t.hybrid;}).length;
    var el=document.getElementById('insight-1');
    if(el) el.textContent=pct(hybrid,obs.length)+'% hybrid';
    var sorted=DATA.sectors.filter(function(s){return s.observed>0;});
    if(sorted.length){
      var best=sorted[0], worst=sorted[sorted.length-1];
      var gap=Math.round((best.qri-worst.qri)*10)/10;
      var big=document.getElementById('insight-3');
      if(big) big.textContent=best.grade+' vs '+worst.grade;
      var note=document.getElementById('insight-3-note');
      if(note) note.textContent=best.name+' leads at '+best.qri+'; '+worst.name+' trails at '+worst.qri+'. A global average hides a '+gap+'-point gap.';
    }
  }

  function renderAll(){renderKpis();renderLeaderboard();renderSectors();renderInsights();}

  document.querySelectorAll('.chip').forEach(function(chip){
    chip.addEventListener('click',function(){
      document.querySelectorAll('.chip').forEach(function(c){c.classList.remove('active');});
      chip.classList.add('active');
      state.sector=chip.getAttribute('data-sector');
      renderAll();
    });
  });

  var range=document.getElementById('crqc');
  if(range){
    range.addEventListener('input',function(){
      state.crqc=Number(range.value);
      var label=document.getElementById('crqc-year');
      if(label) label.textContent=range.value;
      renderAll();
    });
  }

  document.querySelectorAll('thead th[data-sort]').forEach(function(th){
    th.addEventListener('click',function(){
      var key=th.getAttribute('data-sort');
      if(key==='rank') key='score';
      if(state.sort===key) state.dir*=-1; else {state.sort=key;state.dir=key==='name'?1:-1;}
      renderAll();
    });
  });

  document.querySelectorAll('.copy').forEach(function(button){
    button.addEventListener('click',function(){
      var id=button.getAttribute('data-copy');
      var big=document.getElementById(id);
      var note=document.getElementById(id+'-note');
      var text=(big?big.textContent:'')+(note?' — '+note.textContent:'');
      var done=function(){button.textContent='copied';setTimeout(function(){button.textContent='copy';},1400);};
      if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(text).then(done,done);}
      else{var area=document.createElement('textarea');area.value=text;document.body.appendChild(area);area.select();try{document.execCommand('copy');}catch(e){}document.body.removeChild(area);done();}
    });
  });

  renderAll();
})();
</script>
</body>
</html>
`;
}

/**
 * Render a 1200×630 social card from benchmark data. The card is a static
 * snapshot: the interactive page is the place to move the CRQC slider.
 */
export function buildBenchmarkCardSvg({ benchmark, title = 'The State of Post-Quantum Readiness' }) {
  const overall = benchmark.overall || {};
  const score = Number.isFinite(Number(overall.qri)) ? Number(overall.qri) : 0;
  const grade = overall.grade || gradeFor(score).grade;
  const color = overall.gradeColor || gradeFor(score).color;
  const sectors = (benchmark.sectors || []).filter((sector) => sector.observed > 0).slice(0, 6);
  const rowHeight = 34;
  const chartTop = 402;
  const maxBar = 470;
  const bars = sectors
    .map((sector, index) => {
      const y = chartTop + index * rowHeight;
      const width = Math.max(2, Math.round((Number(sector.qri) / 100) * maxBar));
      const barColor = sector.gradeColor || gradeFor(sector.qri).color;
      return `<g>
    <text x="74" y="${y + 12}" fill="#8b9ab5" font-size="13" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace">${esc(sector.name || sector.id)}</text>
    <rect x="300" y="${y + 1}" width="${maxBar}" height="12" rx="6" fill="#ffffff" fill-opacity="0.05"/>
    <rect x="300" y="${y + 1}" width="${width}" height="12" rx="6" fill="${barColor}"/>
    <text x="${300 + maxBar + 18}" y="${y + 12}" fill="${barColor}" font-size="13" font-weight="700" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace">${esc(sector.grade)}</text>
  </g>`;
    })
    .join('\n');

  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630" role="img" aria-labelledby="bench-title bench-desc">
  <title id="bench-title">${esc(title)}</title>
  <desc id="bench-desc">Global QRI ${score} out of 100, grade ${grade}. Hybrid adoption ${overall.pqcHybridAdoption}%. Harvest-now-decrypt-later exposure ${overall.hndlExposure}%.</desc>
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#22d3ee"/><stop offset="1" stop-color="#a78bfa"/>
    </linearGradient>
    <radialGradient id="glow" cx="0.5" cy="0.5" r="0.5">
      <stop offset="0" stop-color="#22d3ee" stop-opacity="0.18"/><stop offset="1" stop-color="#22d3ee" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <rect width="1200" height="630" fill="#05070c"/>
  <ellipse cx="1050" cy="90" rx="420" ry="260" fill="url(#glow)"/>
  <rect x="0" y="0" width="1200" height="4" fill="url(#g)"/>
  <g font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace">
    <text x="74" y="78" fill="#22d3ee" font-size="14" letter-spacing="5">MOSCA · GLOBAL BENCHMARK</text>
    <text x="74" y="168" fill="#e8eefb" font-size="58" font-weight="700" letter-spacing="-1">${esc(title)}</text>
    <text x="74" y="210" fill="#8b9ab5" font-size="17">What ${esc(overall.observed ?? 0)} publicly reachable endpoints actually negotiate — sector by sector.</text>
  </g>

  <g font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace">
    <text x="74" y="292" fill="#5d6a82" font-size="11" letter-spacing="2">GLOBAL QRI</text>
    <text x="74" y="352" fill="${color}" font-size="56" font-weight="700">${esc(String(score))}<tspan fill="#5d6a82" font-size="22">/100</tspan></text>
    <text x="330" y="292" fill="#5d6a82" font-size="11" letter-spacing="2">GRADE</text>
    <text x="330" y="352" fill="${color}" font-size="56" font-weight="700">${esc(grade)}</text>
    <text x="520" y="292" fill="#5d6a82" font-size="11" letter-spacing="2">HYBRID ADOPTION</text>
    <text x="520" y="352" fill="#22d3ee" font-size="56" font-weight="700">${esc(String(overall.pqcHybridAdoption ?? 0))}<tspan fill="#5d6a82" font-size="22">%</tspan></text>
    <text x="850" y="292" fill="#5d6a82" font-size="11" letter-spacing="2">HNDL EXPOSURE</text>
    <text x="850" y="352" fill="${Number(overall.hndlExposure || 0) > 0 ? '#f87171' : '#34d399'}" font-size="56" font-weight="700">${esc(String(overall.hndlExposure ?? 0))}<tspan fill="#5d6a82" font-size="22">%</tspan></text>
  </g>

  ${bars}

  <g font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace">
    <text x="74" y="596" fill="#5d6a82" font-size="12">CRQC ${esc(String(benchmark.crqcYear))} · generated ${esc(fmtDate(benchmark.generatedAt))} · zero runtime dependencies</text>
    <text x="1126" y="596" text-anchor="end" fill="#8b9ab5" font-size="12">sultanbajamil.github.io/mosca/state-of-pqc.html</text>
  </g>
</svg>
`;
}
