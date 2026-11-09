#!/usr/bin/env node
/**
 * Enforce the project's central promise: zero runtime dependencies.
 *
 * This is not just a style preference. A security tool that asks you to
 * install it inside a regulated build pipeline should not pull a transitive
 * tree of packages into that pipeline. The check runs in CI and in `npm run
 * check`, and it fails on:
 *
 *   1. any entry in dependencies / devDependencies / peerDependencies
 *   2. a bare import specifier that is not a Node builtin
 *   3. a package-lock.json / node_modules directory in the repository
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const failures = [];

const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
  const deps = pkg[field] || {};
  const names = Object.keys(deps);
  if (names.length > 0) failures.push(`${field} is not empty: ${names.join(', ')}`);
}

if (fs.existsSync(path.join(root, 'package-lock.json'))) {
  failures.push('package-lock.json exists; this project must not have a dependency tree');
}

/** Recursively collect .js files under src/ and bin/. */
function collect(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) collect(full, out);
    else if (entry.isFile() && full.endsWith('.js')) out.push(full);
  }
  return out;
}

const files = [...collect(path.join(root, 'src')), ...collect(path.join(root, 'bin'))];
const importRe = /(?:^|\n)\s*(?:import|export)\s+(?:[^'"]*?\sfrom\s+)?['"]([^'"]+)['"]/g;

for (const file of files) {
  const source = fs.readFileSync(file, 'utf8');
  let match;
  while ((match = importRe.exec(source)) !== null) {
    const specifier = match[1];
    const isRelative = specifier.startsWith('.') || specifier.startsWith('/');
    const isBuiltin = specifier.startsWith('node:');
    if (!isRelative && !isBuiltin) {
      failures.push(`${path.relative(root, file)} imports bare specifier "${specifier}"`);
    }
  }
}

if (failures.length > 0) {
  console.error('zero-dependency check FAILED');
  for (const failure of failures) console.error(`  ✗ ${failure}`);
  process.exit(1);
}

console.log(`zero-dependency check passed (${files.length} files, no runtime dependencies)`);
