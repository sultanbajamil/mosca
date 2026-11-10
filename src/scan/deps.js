/**
 * MOSCA — cryptographic supply-chain scanner
 * ==========================================
 *
 * You do not need to install a dependency to know what it does. Lockfiles
 * already contain the resolved name and version of every package in the
 * build. This module parses eight lockfile dialects with plain text and
 * regular expressions, matches the result against the cryptographic package
 * table, and emits one unified finding per package.
 *
 * Nothing is executed, downloaded or resolved. The scan is offline by design,
 * which is the only acceptable model for a CI gate.
 */

import path from 'node:path';
import { walk, readTextFile, createIgnore, loadIgnoreFile } from '../util/fs.js';
import { lookup } from '../rules/algorithms.js';
import { packageRule, versionLessThan } from '../rules/crypto-packages.js';

const MAX_LOCKFILE_BYTES = 8 * 1024 * 1024;

function lineAt(content, index) {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) {
    if (content[i] === '\n') line += 1;
  }
  return line;
}

function addPackage(list, { name, version, ecosystem, file, content, needle }) {
  if (!name) return;
  const index = needle ? content.indexOf(needle) : -1;
  list.push({
    name,
    version: String(version || '').trim(),
    ecosystem,
    file,
    line: index >= 0 ? lineAt(content, index) : 1,
  });
}

// ---------------------------------------------------------------------------
// Lockfile parsers
// ---------------------------------------------------------------------------

/** package-lock.json v1/v2/v3 and npm-shrinkwrap.json. */
export function parsePackageLock(content, rel = 'package-lock.json') {
  let doc;
  try {
    doc = JSON.parse(content);
  } catch {
    return [];
  }
  const packages = [];

  if (doc.packages && typeof doc.packages === 'object') {
    for (const [key, info] of Object.entries(doc.packages)) {
      if (!key || !info || !info.version) continue;
      const name = info.name || key.replace(/^.*node_modules\//, '');
      if (!name) continue;
      addPackage(packages, {
        name,
        version: info.version,
        ecosystem: 'npm',
        file: rel,
        content,
        needle: `"node_modules/${name}"`,
      });
    }
  }

  const walkDeps = (deps) => {
    if (!deps || typeof deps !== 'object') return;
    for (const [name, info] of Object.entries(deps)) {
      if (!info || typeof info !== 'object') continue;
      if (info.version) {
        addPackage(packages, {
          name,
          version: info.version,
          ecosystem: 'npm',
          file: rel,
          content,
          needle: `"${name}"`,
        });
      }
      walkDeps(info.dependencies);
    }
  };
  walkDeps(doc.dependencies);

  return packages;
}

/** yarn.lock v1 and Yarn Berry. */
export function parseYarnLock(content, rel = 'yarn.lock') {
  const packages = [];
  const lines = content.split(/\r?\n/);
  let current = null;
  const header = /^"?((?:@[^/"]+\/)?[^@":\s]+)@[^"]*"?:\s*$/;
  const versionLine = /^\s+version:?\s+"?([^"\s]+)"?/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!/^\s/.test(line)) {
      const match = header.exec(line);
      current = match ? { name: match[1], line: i + 1 } : null;
      continue;
    }
    if (!current) continue;
    const version = versionLine.exec(line);
    if (version) {
      packages.push({
        name: current.name,
        version: version[1],
        ecosystem: 'npm',
        file: rel,
        line: current.line,
      });
      current = null;
    }
  }
  return packages;
}

/** pnpm-lock.yaml v6 and v9 layouts. */
export function parsePnpmLock(content, rel = 'pnpm-lock.yaml') {
  const packages = [];
  const lines = content.split(/\r?\n/);
  const entry = /^\s{2,}'?\/?((?:@[^/']+\/)?[^@'\s]+)@([^:'\s(]+)'?:/;
  for (let i = 0; i < lines.length; i++) {
    const match = entry.exec(lines[i]);
    if (!match) continue;
    const name = match[1];
    if (!name || name.startsWith('.')) continue;
    packages.push({
      name,
      version: match[2],
      ecosystem: 'npm',
      file: rel,
      line: i + 1,
    });
  }
  return packages;
}

/** Cargo.lock and poetry.lock share the TOML [[package]] shape. */
export function parseTomlLock(content, rel, ecosystem) {
  const packages = [];
  const lines = content.split(/\r?\n/);
  let inPackage = false;
  let name = null;
  let version = '';
  let start = 1;
  const flush = () => {
    if (inPackage && name) packages.push({ name, version, ecosystem, file: rel, line: start });
    name = null;
    version = '';
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s*\[\[package\]\]/.test(line)) {
      flush();
      inPackage = true;
      start = i + 1;
      continue;
    }
    if (!inPackage) continue;
    if (/^\s*\[/.test(line) && !/^\s*\[\[package\]\]/.test(line)) {
      flush();
      inPackage = false;
      continue;
    }
    const n = /^\s*name\s*=\s*"([^"]+)"/.exec(line);
    if (n) name = n[1];
    const v = /^\s*version\s*=\s*"([^"]+)"/.exec(line);
    if (v) version = v[1];
  }
  flush();
  return packages;
}

export function parseCargoLock(content, rel = 'Cargo.lock') {
  return parseTomlLock(content, rel, 'cargo');
}

export function parsePoetryLock(content, rel = 'poetry.lock') {
  return parseTomlLock(content, rel, 'pypi');
}

/** go.sum: module version hash, with a /go.mod duplicate per version. */
export function parseGoSum(content, rel = 'go.sum') {
  const packages = [];
  const seen = new Set();
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const match = /^(\S+)\s+(v[^\s/]+)(?:\/go\.mod)?\s+\S+/.exec(lines[i]);
    if (!match) continue;
    const key = `${match[1]}@${match[2]}`;
    if (seen.has(key)) continue;
    seen.add(key);
    packages.push({ name: match[1], version: match[2], ecosystem: 'go', file: rel, line: i + 1 });
  }
  return packages;
}

/** requirements.txt and requirements-*.txt. */
export function parseRequirements(content, rel = 'requirements.txt') {
  const packages = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) continue;
    const match = /^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(?:(?:==|>=|<=|~=|!=|>|<)\s*([^;#\s]+))?/.exec(line);
    if (!match) continue;
    packages.push({
      name: match[1],
      version: match[2] || '',
      ecosystem: 'pypi',
      file: rel,
      line: i + 1,
    });
  }
  return packages;
}

/** pom.xml dependency blocks. */
export function parsePomXml(content, rel = 'pom.xml') {
  const packages = [];
  const block = /<dependency>([\s\S]*?)<\/dependency>/g;
  let match;
  while ((match = block.exec(content)) !== null) {
    const body = match[1];
    const groupId = /<groupId>\s*([^<\s]+)\s*<\/groupId>/.exec(body)?.[1] || '';
    const artifactId = /<artifactId>\s*([^<\s]+)\s*<\/artifactId>/.exec(body)?.[1] || '';
    const version = /<version>\s*([^<\s]+)\s*<\/version>/.exec(body)?.[1] || '';
    if (!artifactId) continue;
    packages.push({
      name: groupId ? `${groupId}:${artifactId}` : artifactId,
      version,
      ecosystem: 'maven',
      file: rel,
      line: lineAt(content, match.index),
    });
  }
  return packages;
}

// ---------------------------------------------------------------------------
// Matching and findings
// ---------------------------------------------------------------------------

/**
 * Convert one package into a finding, or null when it is not cryptographic.
 * @param {object} pkg
 */
export function packageFinding(pkg) {
  const rule = packageRule(pkg.name);
  if (!rule) return null;
  if (rule.maxVersion && pkg.version && !versionLessThan(pkg.version, rule.maxVersion)) return null;

  const algo = lookup(rule.algorithm);
  const status = rule.status;
  const id =
    status === 'quantum-safe'
      ? 'dependency-pqc-ready'
      : status === 'classically-broken'
        ? 'dependency-classically-broken'
        : status === 'deprecated'
          ? 'dependency-deprecated'
          : status === 'mixed'
            ? 'dependency-mixed-crypto'
            : 'dependency-quantum-vulnerable';

  return {
    id,
    kind: 'dependency',
    title: `${pkg.name}${pkg.version ? `@${pkg.version}` : ''} — ${algo.label}`,
    algorithm: algo.id,
    algorithmLabel: algo.label,
    primitive: rule.primitive,
    location: { file: pkg.file, line: pkg.line || 1, column: 1 },
    snippet: null,
    matched: null,
    confidence: 'high',
    positive: status === 'quantum-safe',
    note: rule.note,
    replacement: rule.replacement || null,
    package: {
      name: pkg.name,
      version: pkg.version || null,
      ecosystem: pkg.ecosystem || rule.ecosystem,
      status,
    },
    evidence: {
      package: pkg.name,
      version: pkg.version || null,
      ecosystem: pkg.ecosystem || rule.ecosystem,
      packageStatus: status,
      replacement: rule.replacement || null,
    },
  };
}

/**
 * Scan dependency content from one lockfile.
 * @param {{content:string, rel:string}} input
 */
export function scanDependencyContent({ content, rel }) {
  const base = path.basename(rel).toLowerCase();
  let packages;
  if (base === 'package-lock.json' || base === 'npm-shrinkwrap.json') packages = parsePackageLock(content, rel);
  else if (base === 'yarn.lock') packages = parseYarnLock(content, rel);
  else if (base === 'pnpm-lock.yaml') packages = parsePnpmLock(content, rel);
  else if (base === 'cargo.lock') packages = parseCargoLock(content, rel);
  else if (base === 'go.sum') packages = parseGoSum(content, rel);
  else if (base === 'poetry.lock') packages = parsePoetryLock(content, rel);
  else if (base === 'pom.xml') packages = parsePomXml(content, rel);
  else if (/^requirements.*\.txt$/i.test(base)) packages = parseRequirements(content, rel);
  else packages = [];

  const seen = new Set();
  const findings = [];
  const mapped = [];
  for (const pkg of packages) {
    const finding = packageFinding(pkg);
    if (!finding) continue;
    const key = `${pkg.name}@${pkg.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    mapped.push({
      ...pkg,
      status: finding.package.status,
      algorithm: finding.algorithm,
      algorithmLabel: finding.algorithmLabel,
    });
    findings.push(finding);
  }
  return { findings, packages: mapped, parsed: packages };
}

/** Files treated as dependency manifests. */
export function isDependencyFile(file) {
  const base = path.basename(file).toLowerCase();
  if (['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'cargo.lock', 'go.sum', 'poetry.lock', 'pom.xml'].includes(base)) {
    return true;
  }
  return /^requirements.*\.txt$/i.test(base);
}

/**
 * Scan a directory for cryptographic dependencies.
 * @param {string} root
 * @param {{ignore?:string[], maxFiles?:number}} [opts]
 */
export function scanDependenciesDirectory(root, opts = {}) {
  const { ignore: extraIgnore = [], maxFiles = 50000 } = opts;
  const ignore = createIgnore([...loadIgnoreFile(root), ...extraIgnore], { defaults: false });
  const files = walk(root, { ignore, maxFiles });

  const findings = [];
  const packages = [];
  let filesScanned = 0;

  for (const file of files) {
    if (!isDependencyFile(file.rel)) continue;
    if (file.size > MAX_LOCKFILE_BYTES) continue;
    const content = readTextFile(file.path, MAX_LOCKFILE_BYTES);
    if (content == null) continue;
    filesScanned += 1;
    const result = scanDependencyContent({ content, rel: file.rel });
    findings.push(...result.findings);
    packages.push(...result.packages.map((p) => ({ ...p, rel: file.rel })));
  }

  return {
    findings,
    packages,
    stats: {
      filesScanned,
      packagesMatched: packages.length,
      totalFiles: files.length,
    },
  };
}

export { MAX_LOCKFILE_BYTES };
