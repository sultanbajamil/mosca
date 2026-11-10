/**
 * SVG badges are output artefacts: deterministic, self-contained and free of
 * any third-party branding service. These tests pin the grading thresholds and
 * the exact strings that end up on a README.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { gradeFor, buildQriBadge, buildHndlBadge, writeBadges } from '../src/report/badge.js';

test('gradeFor maps the full A+–F scale', () => {
  assert.equal(gradeFor(96).grade, 'A+');
  assert.equal(gradeFor(90).grade, 'A+');
  assert.equal(gradeFor(89.9).grade, 'A');
  assert.equal(gradeFor(80).grade, 'A');
  assert.equal(gradeFor(70).grade, 'B');
  assert.equal(gradeFor(60).grade, 'C');
  assert.equal(gradeFor(50).grade, 'D');
  assert.equal(gradeFor(40).grade, 'E');
  assert.equal(gradeFor(12).grade, 'F');
  assert.equal(gradeFor(NaN).grade, 'F');
});

test('the QRI badge carries the score, grade and a stable SVG shape', () => {
  const svg = buildQriBadge({ score: 94.2 });
  assert.match(svg, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg"/);
  assert.match(svg, />94\.2\/100 \(A\+\)<\/text>/);
  assert.match(svg, /MOSCA QRI/);
  assert.match(svg, /aria-label="MOSCA QRI: 94\.2\/100 \(A\+\)"/);
  assert.match(svg, /<\/svg>/);
});

test('the HNDL badge distinguishes safe, exposed and not-applicable', () => {
  assert.match(buildHndlBadge({ exposure: 0, applicable: true }), /0% SAFE/);
  assert.match(buildHndlBadge({ exposure: 62.5, applicable: true }), /62\.5% EXPOSED/);
  assert.match(buildHndlBadge({ exposure: null, applicable: false }), /N\/A/);
  assert.match(buildHndlBadge({ exposure: 40, applicable: true, captured: true }), /CAPTURED HNDL/);
});

test('writeBadges writes both files into the requested directory', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mosca-badges-'));
  try {
    const written = writeBadges({
      dir,
      analysis: {
        summary: {
          quantumReadinessIndex: 82,
          hndlApplicable: true,
          hndlExposure: 16.7,
          capturedHndlApplicable: false,
          hndlCapturedRatio: 0,
        },
      },
    });
    assert.equal(fs.existsSync(written.qri), true);
    assert.equal(fs.existsSync(written.hndl), true);
    assert.equal(path.basename(written.qri), 'mosca-qri-badge.svg');
    assert.equal(path.basename(written.hndl), 'mosca-hndl-badge.svg');
    assert.equal(written.grade.grade, 'A');
    assert.match(fs.readFileSync(written.qri, 'utf8'), /82\/100 \(A\)/);
    assert.match(fs.readFileSync(written.hndl, 'utf8'), /16\.7% EXPOSED/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('writeBadges falls back to the captured ratio when no live endpoint was probed', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mosca-badges-capture-'));
  try {
    const written = writeBadges({
      dir,
      analysis: {
        summary: {
          quantumReadinessIndex: 58,
          hndlApplicable: false,
          hndlExposure: 0,
          capturedHndlApplicable: true,
          hndlCapturedRatio: 75,
        },
      },
    });
    const svg = fs.readFileSync(written.hndl, 'utf8');
    assert.match(svg, /CAPTURED HNDL/);
    assert.match(svg, /75% EXPOSED/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
