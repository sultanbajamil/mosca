/**
 * MOSCA — configuration scanner
 * =============================
 * Applies infrastructure rules to nginx, Apache, sshd, OpenSSL and
 * Kubernetes configuration files.
 */

import path from 'node:path';
import { CONFIG_RULES, isConfigFile } from '../rules/config.js';
import { lookup, rsaVariant } from '../rules/algorithms.js';
import { walk, readTextFile, createIgnore, loadIgnoreFile } from '../util/fs.js';

const MAX_SNIPPET = 180;

function resolveAlgorithm(rule, match) {
  try {
    const id = typeof rule.algo === 'function' ? rule.algo(match) : rule.algo;
    const algo = lookup(id);
    if (algo.id === 'rsa' && typeof rule.bits === 'function') {
      const bits = rule.bits(match);
      if (bits) return rsaVariant(bits);
    }
    return algo;
  } catch {
    return lookup('unknown');
  }
}

/**
 * Scan one config file's content.
 * @param {{content:string, rel:string}} input
 */
export function scanConfigContent({ content, rel }) {
  const normalised = rel.replace(/\\/g, '/');
  const lines = content.split(/\r?\n/);
  const findings = [];
  const seen = new Set();

  for (const rule of CONFIG_RULES) {
    let applies = false;
    try {
      applies = rule.appliesTo(normalised);
    } catch {
      applies = false;
    }
    if (!applies) continue;

    const re = new RegExp(rule.re.source, rule.re.flags.includes('g') ? rule.re.flags : `${rule.re.flags}g`);
    re.lastIndex = 0;
    let match;
    while ((match = re.exec(content)) !== null) {
      const before = content.slice(0, match.index);
      const line = before.split('\n').length - 1;
      const key = `${rule.id}:${line}`;
      if (!seen.has(key)) {
        seen.add(key);
        const algo = resolveAlgorithm(rule, match);
        findings.push({
          id: rule.id,
          kind: 'config',
          title: `${algo.label} — ${describe(rule.primitive)}`,
          algorithm: algo.id,
          algorithmLabel: algo.label,
          primitive: rule.primitive,
          location: { file: rel, line: line + 1, column: 1 },
          snippet: (lines[line] || '').trim().slice(0, MAX_SNIPPET),
          matched: match[0].slice(0, MAX_SNIPPET),
          confidence: rule.confidence || 'high',
          note: rule.note || algo.note || null,
          configKind: rule.id.split('-')[0],
        });
      }
      if (match[0].length === 0) re.lastIndex++;
    }
  }

  return findings;
}

function describe(primitive) {
  switch (primitive) {
    case 'protocol': return 'protocol policy';
    case 'key-agreement': return 'key exchange policy';
    case 'symmetric': return 'cipher policy';
    case 'signature': return 'signature policy';
    case 'hash': return 'digest policy';
    case 'mac': return 'MAC policy';
    default: return primitive;
  }
}

/**
 * Scan a directory for insecure configuration.
 * @param {string} root
 * @param {{ignore?:string[], maxFiles?:number}} [opts]
 */
export function scanConfigDirectory(root, opts = {}) {
  const { ignore: extraIgnore = [], maxFiles = 50000 } = opts;
  const ignore = createIgnore([...loadIgnoreFile(root), ...extraIgnore]);
  const files = walk(root, { ignore, maxFiles });

  const findings = [];
  const byFile = {};
  let filesScanned = 0;

  for (const file of files) {
    if (!isConfigFile(file.path)) continue;
    // Skip the project's own configuration noise.
    const base = path.basename(file.path).toLowerCase();
    if (base === 'package.json' || base === '.eslintrc' || base === 'tsconfig.json') continue;
    const content = readTextFile(file.path, 512 * 1024);
    if (content == null) continue;
    filesScanned++;
    const found = scanConfigContent({ content, rel: file.rel });
    if (found.length) {
      byFile[file.rel] = found.length;
      findings.push(...found);
    }
  }

  return { findings, stats: { filesScanned, byFile } };
}
