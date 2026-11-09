/**
 * Filesystem helpers: the walker must skip vendored code, honour
 * `.moscaignore`, and never read binaries as source.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  globToRegExp,
  createIgnore,
  loadIgnoreFile,
  walk,
  readTextFile,
  stripComments,
} from '../src/util/fs.js';
import { COMMENT_SYNTAX } from '../src/rules/source.js';

function tempTree(spec) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mosca-fs-'));
  for (const [rel, content] of Object.entries(spec)) {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return root;
}

test('globToRegExp supports stars and double stars', () => {
  assert.equal(globToRegExp('**/billing/**').test('services/billing/invoice.js'), true);
  assert.equal(globToRegExp('**/billing/**').test('services/payments/invoice.js'), false);
  assert.equal(globToRegExp('*.min.js').test('app.min.js'), true);
  assert.equal(globToRegExp('src/*.js').test('src/deep/app.js'), false);
  assert.equal(globToRegExp('src/**/*.js').test('src/deep/nested/app.js'), true);
});

test('createIgnore combines defaults with user patterns', () => {
  const ignore = createIgnore(['generated/**', '*.snap']);
  assert.equal(ignore('app.min.js'), true, 'default minified-file pattern');
  assert.equal(ignore('package-lock.json'), true);
  assert.equal(ignore('generated/client.js'), true);
  assert.equal(ignore('src/__snapshots__/a.snap'), true);
  assert.equal(ignore('src/app.js'), false);
});

test('walk skips vendored directories and honours .moscaignore', () => {
  const root = tempTree({
    '.moscaignore': '# comment\nlegacy/\n',
    'src/app.js': 'const x = 1;',
    'src/deep/util.js': 'const y = 2;',
    'node_modules/pkg/index.js': 'const z = 3;',
    'legacy/old.js': 'const w = 4;',
    '.git/config': 'ignored',
  });

  const files = walk(root, { ignore: createIgnore(loadIgnoreFile(root)) });
  const rels = files.map((f) => f.rel.replace(/\\/g, '/')).sort();
  assert.deepEqual(rels, ['.moscaignore', 'src/app.js', 'src/deep/util.js']);
  for (const file of files) {
    assert.equal(fs.existsSync(file.path), true);
    assert.ok(file.size > 0);
  }
});

test('readTextFile refuses binary and oversized files', () => {
  const root = tempTree({
    'ok.js': 'const ok = true;',
    'binary.bin': 'abc\0def',
    'big.js': 'x'.repeat(200),
  });
  assert.equal(readTextFile(path.join(root, 'ok.js')), 'const ok = true;');
  assert.equal(readTextFile(path.join(root, 'binary.bin')), null);
  assert.equal(readTextFile(path.join(root, 'big.js'), 100), null);
  assert.equal(readTextFile(path.join(root, 'missing.js')), null);
});

test('stripComments blanks comments without moving code', () => {
  const source = ['const a = 1; // trailing', '/* block', 'comment */ const b = 2;'].join('\n');
  const stripped = stripComments(source, COMMENT_SYNTAX.javascript);
  assert.equal(stripped.split('\n').length, source.split('\n').length);
  assert.ok(stripped.includes('const a = 1;'));
  assert.ok(stripped.includes('const b = 2;'));
  assert.ok(!stripped.includes('trailing'));
  assert.ok(!stripped.includes('block'));
});

test('stripComments does not treat a URL as a comment', () => {
  const source = "const url = 'https://example.com/path'; const t = 1;";
  const stripped = stripComments(source, COMMENT_SYNTAX.javascript);
  assert.ok(stripped.includes('https://example.com/path'));
  assert.ok(stripped.includes('const t = 1;'));
});
