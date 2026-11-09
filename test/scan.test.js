/**
 * End-to-end scan of a tiny synthetic repository, plus the CI exit-code
 * contract. No network access is required.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { scan, exitCode } from '../src/index.js';

function makeRepo() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mosca-scan-'));
  const write = (rel, content) => {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  };
  write('src/app.js', "import crypto from 'node:crypto';\ncrypto.createHash('md5');\n");
  write('infra/nginx.conf', 'ssl_ciphers HIGH:RC4-SHA;\n');
  write('node_modules/vendor/index.js', "crypto.createHash('md5');\n");
  write('legacy/old.js', "crypto.createHash('md5');\n");
  write('.moscaignore', 'legacy/\n');
  return root;
}

test('scan finds source and config findings and skips vendored code', async () => {
  const root = makeRepo();
  const { analysis, meta } = await scan({ root, config: { endpoints: [] }, quiet: true });

  const algorithms = analysis.items.map((i) => i.algorithm);
  assert.ok(algorithms.includes('md5'), 'source finding missing');
  assert.ok(algorithms.includes('rc4'), 'config finding missing');

  const files = analysis.items.map((i) => i.location.file.replace(/\\/g, '/'));
  assert.ok(!files.some((f) => f.startsWith('node_modules/')), 'vendored code was scanned');
  assert.ok(!files.some((f) => f.startsWith('legacy/')), '.moscaignore was ignored');

  assert.equal(meta.sourceStats.filesScanned, 1);
  assert.equal(meta.configStats.filesScanned, 1);
  assert.equal(meta.durationMs >= 0, true);
  assert.equal(analysis.summary.endpointsInspected, 0);
  assert.equal(analysis.summary.hndlApplicable, false);
});

test('analysis is deterministic for a fixed clock', async () => {
  const root = makeRepo();
  const a = await scan({ root, config: { endpoints: [] }, quiet: true });
  const b = await scan({ root, config: { endpoints: [] }, quiet: true });
  assert.deepEqual(
    a.analysis.items.map((i) => `${i.id}:${i.algorithm}:${i.location.file}:${i.location.line}`),
    b.analysis.items.map((i) => `${i.id}:${i.algorithm}:${i.location.file}:${i.location.line}`),
  );
});

test('exitCode gates CI at the configured severity', async () => {
  const root = makeRepo();
  const { analysis } = await scan({ root, config: { endpoints: [] }, quiet: true });

  assert.equal(exitCode(analysis, null), 0);
  assert.equal(exitCode(analysis, 'critical'), 1);
  assert.equal(exitCode(analysis, 'high'), 1);
  assert.equal(exitCode(analysis, 'low'), 1);
  assert.equal(exitCode(analysis, 'not-a-severity'), 0);
});

test('exitCode passes a clean estate', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mosca-clean-'));
  fs.writeFileSync(path.join(root, 'app.js'), "crypto.createHash('sha256');\n");
  const { analysis } = await scan({ root, config: { endpoints: [] }, quiet: true });
  assert.equal(exitCode(analysis, 'critical'), 0);
  assert.equal(analysis.summary.actionable, 0);
});
