/**
 * Configuration and data-classification tests. These values shape every
 * score, so they are tested as behaviour, not as implementation details.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  DEFAULT_CONFIG,
  CRQC_SCENARIOS,
  mergeConfig,
  loadConfig,
  resolveCrqcYear,
  shelfLifeFor,
  matchesGlob,
} from '../src/config.js';

test('CRQC scenarios resolve to planning years', () => {
  assert.equal(CRQC_SCENARIOS.aggressive.year, 2029);
  assert.equal(CRQC_SCENARIOS.moderate.year, 2033);
  assert.equal(CRQC_SCENARIOS.conservative.year, 2038);

  assert.equal(resolveCrqcYear({ scenario: 'aggressive' }), 2029);
  assert.equal(resolveCrqcYear({ scenario: 'conservative' }), 2038);
  assert.equal(resolveCrqcYear({ scenario: 'aggressive', crqcYear: 2041 }), 2041);
  assert.equal(resolveCrqcYear({}), DEFAULT_CONFIG.crqcYear);
});

test('mergeConfig merges objects and replaces arrays', () => {
  const merged = mergeConfig(DEFAULT_CONFIG, {
    scenario: 'aggressive',
    weights: { quantum: 0.5 },
    dataClasses: [{ pattern: '**/secret/**', years: 42, label: 'secrets' }],
  });
  assert.equal(merged.scenario, 'aggressive');
  assert.equal(merged.weights.quantum, 0.5);
  assert.equal(merged.weights.durability, DEFAULT_CONFIG.weights.durability);
  assert.equal(merged.dataClasses.length, 1);
  assert.equal(merged.dataClasses[0].years, 42);
  // The base must not be mutated.
  assert.equal(DEFAULT_CONFIG.weights.quantum, 0.4);
});

test('shelfLifeFor applies the first matching data class', () => {
  const classes = [
    { pattern: '**/billing/**', years: 10, label: 'billing records' },
    { pattern: '**/health/**', years: 25, label: 'health records' },
  ];
  assert.deepEqual(shelfLifeFor('services/billing/invoice.js', classes, 7), {
    years: 10,
    label: 'billing records',
  });
  assert.deepEqual(shelfLifeFor('apps/health/records.js', classes, 7), {
    years: 25,
    label: 'health records',
  });
  assert.deepEqual(shelfLifeFor('src/app.js', classes, 7), { years: 7, label: 'general' });
  // Windows separators are normalised.
  assert.equal(shelfLifeFor('services\\health\\x.js', classes, 7).years, 25);
});

test('glob matching handles ** and ordinary wildcards', () => {
  assert.equal(matchesGlob('a/b/c.js', '**/b/**'), true);
  assert.equal(matchesGlob('a/b/c.js', 'a/*/c.js'), true);
  assert.equal(matchesGlob('a/b/d/c.js', 'a/*/c.js'), false);
  assert.equal(matchesGlob('app.js', '*.js'), true);
});

test('loadConfig reads a file, merges defaults and applies the scenario', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mosca-config-'));
  const file = path.join(dir, 'mosca.json');
  fs.writeFileSync(file, JSON.stringify({ scenario: 'conservative', defaultShelfLife: 12 }));

  const { config, path: loadedPath } = loadConfig(file);
  assert.equal(loadedPath, file);
  assert.equal(config.scenario, 'conservative');
  assert.equal(config.crqcYear, 2038);
  assert.equal(config.defaultShelfLife, 12);
  assert.equal(config.weights.quantum, DEFAULT_CONFIG.weights.quantum);
});

test('loadConfig rejects malformed JSON with a useful message', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mosca-config-'));
  const file = path.join(dir, 'mosca.json');
  fs.writeFileSync(file, '{ "scenario": ');
  assert.throws(() => loadConfig(file), /Invalid JSON/);
});
