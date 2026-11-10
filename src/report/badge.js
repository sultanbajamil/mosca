/**
 * MOSCA — local SVG badges
 * ========================
 *
 * Repositories advertise the tools that produce evidence. These badges are
 * generated from the scan itself, never fetched from a third-party service:
 * no token, no network call, no telemetry. A QRI badge that says 94/100 is a
 * claim the pipeline can reproduce on every commit.
 */

import fs from 'node:fs';
import path from 'node:path';

const GRADE_SCALE = [
  { min: 90, grade: 'A+', label: 'Quantum-ready', color: '#22c55e' },
  { min: 80, grade: 'A', label: 'Strong', color: '#34d399' },
  { min: 70, grade: 'B', label: 'Progressing', color: '#22d3ee' },
  { min: 60, grade: 'C', label: 'Partial', color: '#fbbf24' },
  { min: 50, grade: 'D', label: 'Exposed', color: '#fb923c' },
  { min: 40, grade: 'E', label: 'Weak', color: '#f97316' },
  { min: 0, grade: 'F', label: 'Critical', color: '#ef4444' },
];

/** Map a 0–100 QRI onto an A+–F grade. */
export function gradeFor(score) {
  const value = Number.isFinite(Number(score)) ? Math.max(0, Math.min(100, Number(score))) : 0;
  return GRADE_SCALE.find((entry) => value >= entry.min) || GRADE_SCALE[GRADE_SCALE.length - 1];
}

function escapeXml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function badgeSvg({ label, value, valueColor = '#e8eefb', labelWidth = 132, valueWidth = 176, accent = '#22d3ee' }) {
  const width = labelWidth + valueWidth;
  const height = 28;
  const mid = labelWidth;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" role="img" aria-label="${escapeXml(`${label}: ${value}`)}">
  <title>${escapeXml(`${label}: ${value}`)}</title>
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#0a1020"/>
      <stop offset="1" stop-color="#060911"/>
    </linearGradient>
    <linearGradient id="accent" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="${accent}"/>
      <stop offset="1" stop-color="#a78bfa"/>
    </linearGradient>
    <clipPath id="round"><rect width="${width}" height="${height}" rx="6"/></clipPath>
  </defs>
  <g clip-path="url(#round)">
    <rect width="${width}" height="${height}" fill="url(#bg)"/>
    <rect width="${mid}" height="${height}" fill="#101827"/>
    <rect x="${mid}" width="${valueWidth}" height="${height}" fill="#0b1220"/>
    <rect y="${height - 2}" width="${width}" height="2" fill="url(#accent)" opacity=".85"/>
    <rect x="${mid}" width="1" height="${height}" fill="#ffffff" opacity=".12"/>
  </g>
  <g font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-size="11" font-weight="600" fill="#8b9ab5">
    <text x="12" y="18">${escapeXml(label)}</text>
  </g>
  <g font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-size="11.5" font-weight="700" fill="${valueColor}">
    <text x="${mid + 12}" y="18">${escapeXml(value)}</text>
  </g>
</svg>
`;
}

/** Build the QRI shield: `MOSCA QRI | 94/100 (A+)`. */
export function buildQriBadge({ score = 0, grade = null } = {}) {
  const rounded = Math.round(Number(score) * 10) / 10;
  const resolved = grade || gradeFor(rounded);
  const shown = Number.isInteger(rounded) ? String(rounded) : rounded.toFixed(1);
  return badgeSvg({
    label: 'MOSCA QRI',
    value: `${shown}/100 (${resolved.grade})`,
    valueColor: resolved.color,
    accent: resolved.color,
  });
}

/**
 * Build the HNDL shield. `exposure` is the classical-only share of the
 * inspected surface; `null` means nothing applicable was inspected.
 */
export function buildHndlBadge({ exposure = null, applicable = true, captured = false } = {}) {
  if (!applicable || exposure == null) {
    return badgeSvg({
      label: 'HNDL EXPOSURE',
      value: 'N/A',
      valueColor: '#8b9ab5',
      accent: '#8b9ab5',
    });
  }
  const value = Math.round(Number(exposure) * 10) / 10;
  const safe = value <= 0;
  return badgeSvg({
    label: captured ? 'CAPTURED HNDL' : 'HNDL EXPOSURE',
    value: safe ? '0% SAFE' : `${value}% EXPOSED`,
    valueColor: safe ? '#34d399' : value >= 50 ? '#f87171' : '#fbbf24',
    accent: safe ? '#34d399' : value >= 50 ? '#f87171' : '#fbbf24',
  });
}

/**
 * Write both badges from an analysis summary.
 * @param {{dir:string, analysis:object}} input
 * @returns {{qri:string, hndl:string, grade:object}}
 */
export function writeBadges({ dir, analysis }) {
  if (!dir) throw new Error('badge output directory is required');
  const outDir = path.resolve(dir);
  fs.mkdirSync(outDir, { recursive: true });
  const summary = analysis?.summary || {};
  const score = Number(summary.quantumReadinessIndex) || 0;
  const grade = gradeFor(score);
  const liveApplicable = Boolean(summary.hndlApplicable);
  const capturedApplicable = Boolean(summary.capturedHndlApplicable);
  const exposure = liveApplicable
    ? Number(summary.hndlExposure) || 0
    : capturedApplicable
      ? Number(summary.hndlCapturedRatio) || 0
      : null;

  const qriFile = path.join(outDir, 'mosca-qri-badge.svg');
  const hndlFile = path.join(outDir, 'mosca-hndl-badge.svg');
  fs.writeFileSync(qriFile, buildQriBadge({ score, grade }), 'utf8');
  fs.writeFileSync(
    hndlFile,
    buildHndlBadge({
      exposure,
      applicable: exposure != null,
      captured: !liveApplicable && capturedApplicable,
    }),
    'utf8',
  );
  return { qri: qriFile, hndl: hndlFile, grade };
}
