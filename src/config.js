/**
 * MOSCA — configuration
 * =====================
 *
 * Every number that shapes the risk model is configurable, because the
 * right answer depends on the organisation: how long its data must stay
 * secret, when it believes a CRQC will arrive, and how much migration
 * capacity it has.
 */

import fs from 'node:fs';
import path from 'node:path';

/** CRQC arrival scenarios, in years. These are planning assumptions, not predictions. */
export const CRQC_SCENARIOS = {
  aggressive: { year: 2029, label: 'Aggressive', note: 'A cryptographically relevant quantum computer by 2029.' },
  moderate: { year: 2033, label: 'Moderate', note: 'A CRQC by 2033. The default planning horizon.' },
  conservative: { year: 2038, label: 'Conservative', note: 'A CRQC by 2038.' },
};

export const DEFAULT_CONFIG = {
  scenario: 'moderate',
  crqcYear: CRQC_SCENARIOS.moderate.year,
  /** Years a piece of data must remain confidential. */
  defaultShelfLife: 7,
  /**
   * Path-based data classification. The first matching pattern wins.
   * `years` is the confidentiality lifetime.
   */
  dataClasses: [
    { pattern: '**/health/**', years: 25, label: 'health records' },
    { pattern: '**/medical/**', years: 25, label: 'medical records' },
    { pattern: '**/genomic/**', years: 50, label: 'genomic data' },
    { pattern: '**/pii/**', years: 15, label: 'personal data' },
    { pattern: '**/personal/**', years: 15, label: 'personal data' },
    { pattern: '**/finance/**', years: 10, label: 'financial records' },
    { pattern: '**/billing/**', years: 10, label: 'billing records' },
    { pattern: '**/payment/**', years: 10, label: 'payment data' },
    { pattern: '**/auth/**', years: 10, label: 'authentication secrets' },
    { pattern: '**/identity/**', years: 15, label: 'identity data' },
    { pattern: '**/backup/**', years: 20, label: 'backups' },
    { pattern: '**/archive/**', years: 20, label: 'archives' },
  ],
  /** Weight of each factor in the Mosca score. Must sum to 1. */
  weights: {
    quantum: 0.4,
    durability: 0.2,
    breadth: 0.15,
    classical: 0.15,
    surface: 0.1,
  },
  /** Files and directories to ignore, in addition to .moscaignore. */
  ignore: [],
  /** Endpoints to inspect on every scan. */
  endpoints: [],
  /** Exit non-zero when a finding at or above this severity exists. */
  failOn: null,
};

/** Recursively merge plain objects; arrays are replaced, not concatenated. */
export function mergeConfig(base, override) {
  if (!override || typeof override !== 'object') return base;
  const out = { ...base };
  for (const [key, value] of Object.entries(override)) {
    if (value && typeof value === 'object' && !Array.isArray(value) && typeof base[key] === 'object' && !Array.isArray(base[key])) {
      out[key] = mergeConfig(base[key], value);
    } else if (value !== undefined) {
      out[key] = value;
    }
  }
  return out;
}

/**
 * Load a JSON config file. Supports `mosca.json`, `.mosca.json` and
 * `mosca.config.json`.
 * @param {string} [file]
 */
export function loadConfig(file) {
  const candidates = file
    ? [file]
    : ['mosca.json', '.mosca.json', 'mosca.config.json', path.join('.mosca', 'config.json')];

  for (const candidate of candidates) {
    try {
      const raw = fs.readFileSync(candidate, 'utf8');
      const parsed = JSON.parse(raw);
      const merged = mergeConfig(DEFAULT_CONFIG, parsed);
      if (merged.scenario && CRQC_SCENARIOS[merged.scenario] && !parsed.crqcYear) {
        merged.crqcYear = CRQC_SCENARIOS[merged.scenario].year;
      }
      return { config: merged, path: candidate };
    } catch (err) {
      if (err.code === 'ENOENT') continue;
      if (err instanceof SyntaxError) {
        throw new Error(`Invalid JSON in ${candidate}: ${err.message}`);
      }
      throw err;
    }
  }
  return { config: { ...DEFAULT_CONFIG }, path: null };
}

/** Resolve the CRQC year from a scenario name or explicit year. */
export function resolveCrqcYear({ scenario, crqcYear }) {
  if (crqcYear) return Number(crqcYear);
  if (scenario && CRQC_SCENARIOS[scenario]) return CRQC_SCENARIOS[scenario].year;
  return DEFAULT_CONFIG.crqcYear;
}

/**
 * Return the confidentiality lifetime for a file path.
 * @param {string} relPath
 * @param {Array<{pattern:string, years:number, label:string}>} dataClasses
 * @param {number} fallback
 */
export function shelfLifeFor(relPath, dataClasses, fallback) {
  const normalised = String(relPath || '').replace(/\\/g, '/');
  for (const dc of dataClasses || []) {
    if (matchesGlob(normalised, dc.pattern)) return { years: dc.years, label: dc.label };
  }
  return { years: fallback, label: 'general' };
}

/** Minimal glob matcher supporting `**` and `*`. */
export function matchesGlob(text, glob) {
  const re = new RegExp(
    '^' +
      glob
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*\*/g, '\u0000')
        .replace(/\*/g, '[^/]*')
        .replace(/\u0000/g, '.*') +
      '$',
  );
  return re.test(text);
}
