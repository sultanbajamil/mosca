#!/usr/bin/env node
/**
 * Validate the artefacts a demo scan produced. CI runs this after the scan so
 * a reporter regression fails the build even when the process exit code is 0.
 */

import fs from 'node:fs';
import path from 'node:path';

const dir = path.resolve(process.argv[2] || 'out');
const failures = [];

function readJson(name) {
  const file = path.join(dir, name);
  if (!fs.existsSync(file)) {
    failures.push(`${name} is missing`);
    return null;
  }
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    failures.push(`${name} is not valid JSON: ${err.message}`);
    return null;
  }
}

const json = readJson('mosca.json');
const cbom = readJson('bom.cdx.json');
const sarif = readJson('mosca.sarif');

if (json) {
  if (!json.analysis?.summary) failures.push('mosca.json has no analysis.summary');
  if (!Array.isArray(json.analysis?.items)) failures.push('mosca.json has no analysis.items');
  if (json.analysis.summary.totalFindings !== json.analysis.items.length) {
    failures.push('summary.totalFindings does not match the item count');
  }
  if (!Array.isArray(json.analysis.summary.sensitivity) || json.analysis.summary.sensitivity.length !== 4) {
    failures.push('summary.sensitivity must contain four CRQC scenarios');
  }
  for (const item of json.analysis.items) {
    if (!item.positive && !item.fingerprint) failures.push(`finding ${item.id} has no stable fingerprint`);
  }
  for (const ep of json.sshEndpoints || []) {
    if (ep.reachable && !Array.isArray(ep.kexAlgorithms)) {
      failures.push(`SSH endpoint ${ep.host} has no kexAlgorithms`);
    }
  }
  if (json.analysis.summary.baseline?.supplied) {
    const b = json.analysis.summary.baseline;
    if (typeof b.newFindings !== 'number' || typeof b.resolvedFindings !== 'number') {
      failures.push('baseline summary is incomplete');
    }
  }
}

if (cbom) {
  if (cbom.bomFormat !== 'CycloneDX') failures.push('CBOM bomFormat must be CycloneDX');
  if (cbom.specVersion !== '1.6') failures.push('CBOM specVersion must be 1.6');
  if (!Array.isArray(cbom.components) || cbom.components.length === 0) {
    failures.push('CBOM has no components');
  }
  for (const component of cbom.components || []) {
    if (component.type !== 'cryptographic-asset') {
      failures.push(`CBOM component ${component['bom-ref']} is not a cryptographic-asset`);
    }
  }
}

if (sarif) {
  if (sarif.version !== '2.1.0') failures.push('SARIF version must be 2.1.0');
  if (!Array.isArray(sarif.runs) || sarif.runs.length === 0) failures.push('SARIF has no runs');
  const run = sarif.runs?.[0];
  if (run?.tool?.driver?.name !== 'MOSCA') failures.push('SARIF driver name must be MOSCA');
  for (const result of run?.results || []) {
    if (!result.ruleId?.startsWith('mosca/')) failures.push(`SARIF ruleId ${result.ruleId} lacks the mosca/ prefix`);
    if (!result.locations?.[0]?.physicalLocation) failures.push(`SARIF result ${result.ruleId} has no location`);
  }
}

const htmlFile = path.join(dir, 'mosca-report.html');
if (!fs.existsSync(htmlFile)) {
  failures.push('mosca-report.html is missing');
} else {
  const html = fs.readFileSync(htmlFile, 'utf8');
  if (!html.startsWith('<!doctype html>')) failures.push('HTML report has no doctype');
  if (/<script[^>]+\bsrc=/i.test(html)) failures.push('HTML report loads an external script');
  if (/<link[^>]+\bhref=["']https?:/i.test(html)) failures.push('HTML report loads an external stylesheet');
}

if (failures.length > 0) {
  console.error('artefact validation FAILED');
  for (const failure of failures) console.error(`  ✗ ${failure}`);
  process.exit(1);
}

console.log(`artefact validation passed (${dir})`);
