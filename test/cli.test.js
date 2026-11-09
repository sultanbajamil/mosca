/**
 * CLI grammar tests. The parser is hand-written, so the edge cases are worth
 * pinning: comma lists, --flag=value, boolean flags and `--` terminators.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { parseArgs } from '../src/cli.js';

test('parses positionals and value flags', () => {
  const args = parseArgs([
    'scan',
    '.',
    '--tls',
    'example.com,github.com',
    '--out',
    'report',
    '--fail-on',
    'high',
    '--top',
    '30',
  ]);
  assert.deepEqual(args._, ['scan', '.']);
  assert.equal(args.tls, 'example.com,github.com');
  assert.equal(args.out, 'report');
  assert.equal(args['fail-on'], 'high');
  assert.equal(args.top, '30');
});

test('supports --flag=value and repeated flags', () => {
  const args = parseArgs(['scan', '--format=html,json', '--tls=a.example', '--tls=b.example']);
  assert.equal(args.format, 'html,json');
  assert.equal(args.tls, 'a.example,b.example');
});

test('boolean flags do not consume the next positional', () => {
  const args = parseArgs(['scan', '--quiet', 'src', '--json']);
  assert.deepEqual(args._, ['scan', 'src']);
  assert.equal(args.quiet, true);
  assert.equal(args.json, true);
});

test('a value flag at the end is treated as boolean', () => {
  const args = parseArgs(['scan', '--out']);
  assert.equal(args.out, true);
});

test('-- stops flag parsing', () => {
  const args = parseArgs(['scan', '--', '--not-a-flag', 'file.js']);
  assert.deepEqual(args._, ['scan', '--not-a-flag', 'file.js']);
});

test('short flags are accepted', () => {
  const args = parseArgs(['-h']);
  assert.equal(args.h, true);
});
