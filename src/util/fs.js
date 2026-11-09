/**
 * MOSCA — filesystem helpers
 * ==========================
 *
 * A small, predictable directory walker. It never follows symlinks (avoids
 * loops), skips vendored dependencies and build output by default, and
 * refuses to read files that look binary or are unreasonably large.
 */

import fs from 'node:fs';
import path from 'node:path';

/** Directories that never contain first-party code worth auditing. */
export const DEFAULT_IGNORE_DIRS = new Set([
  '.git',
  '.hg',
  '.svn',
  'node_modules',
  'bower_components',
  'vendor',
  'dist',
  'build',
  'out',
  'target',
  'bin',
  'obj',
  '.next',
  '.nuxt',
  '.svelte-kit',
  'coverage',
  '.nyc_output',
  '__pycache__',
  '.venv',
  'venv',
  'env',
  '.tox',
  '.mypy_cache',
  '.pytest_cache',
  '.gradle',
  '.idea',
  '.vscode',
  '.terraform',
  'Pods',
  'DerivedData',
  '.cache',
]);

const DEFAULT_IGNORE_FILE_PATTERNS = [
  '*.min.js',
  '*.min.css',
  '*.map',
  '*.lock',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'poetry.lock',
  'Cargo.lock',
  'go.sum',
  '*.pem',
  '*.key',
  '*.crt',
  '*.der',
  '*.p12',
  '*.pfx',
  '*.jks',
  '*.keystore',
];

/** Convert a simple glob (supports * and **) into a RegExp. */
export function globToRegExp(glob) {
  let out = '^';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        out += '.*';
        i++;
        if (glob[i + 1] === '/') i++;
      } else {
        out += '[^/]*';
      }
    } else if (c === '?') {
      out += '[^/]';
    } else if ('\\^$.|+()[]{}'.includes(c)) {
      out += `\\${c}`;
    } else {
      out += c;
    }
  }
  return new RegExp(`${out}$`);
}

/**
 * Build an ignore predicate from glob patterns plus the built-in defaults.
 * @param {string[]} patterns
 */
export function createIgnore(patterns = []) {
  const regexes = [...DEFAULT_IGNORE_FILE_PATTERNS, ...patterns]
    .filter((p) => p && !p.startsWith('#'))
    .map((p) => globToRegExp(p.replace(/\\/g, '/')));
  return (relPath) => {
    const normalised = relPath.replace(/\\/g, '/');
    const base = normalised.split('/').pop() || '';
    return regexes.some((re) => re.test(normalised) || re.test(base));
  };
}

/**
 * Read a `.moscaignore` file if present.
 * @param {string} root
 */
export function loadIgnoreFile(root) {
  const file = path.join(root, '.moscaignore');
  try {
    return fs
      .readFileSync(file, 'utf8')
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'));
  } catch {
    return [];
  }
}

/**
 * Recursively list files under `root`.
 * @param {string} root
 * @param {{ignore?:(rel:string)=>boolean, maxFiles?:number, maxDepth?:number}} [opts]
 * @returns {Array<{path:string, rel:string, size:number}>}
 */
export function walk(root, opts = {}) {
  const { ignore = () => false, maxFiles = 200000, maxDepth = 40 } = opts;
  const out = [];

  const visit = (dir, depth) => {
    if (out.length >= maxFiles || depth > maxDepth) return;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (out.length >= maxFiles) return;
      const full = path.join(dir, entry.name);
      const rel = path.relative(root, full);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (DEFAULT_IGNORE_DIRS.has(entry.name)) continue;
        if (ignore(`${rel}/`)) continue;
        visit(full, depth + 1);
      } else if (entry.isFile()) {
        if (ignore(rel)) continue;
        let size = 0;
        try {
          size = fs.statSync(full).size;
        } catch {
          continue;
        }
        out.push({ path: full, rel, size });
      }
    }
  };

  visit(root, 0);
  return out;
}

/**
 * Read a file as UTF-8, returning null when it is binary or too large.
 * @param {string} file
 * @param {number} maxBytes
 */
export function readTextFile(file, maxBytes = 2 * 1024 * 1024) {
  let fd;
  try {
    const stat = fs.statSync(file);
    if (!stat.isFile() || stat.size > maxBytes) return null;
    fd = fs.openSync(file, 'r');
    const buf = Buffer.alloc(Math.min(stat.size, 8192));
    const read = fs.readSync(fd, buf, 0, buf.length, 0);
    // A NUL byte in the first 8 KiB is the classic binary heuristic.
    for (let i = 0; i < read; i++) {
      if (buf[i] === 0) return null;
    }
    return fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  } finally {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {
        /* ignore */
      }
    }
  }
}

/** True when `p` is an existing directory. */
export function isDirectory(p) {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
}

/** True when `p` exists. */
export function exists(p) {
  try {
    fs.accessSync(p);
    return true;
  } catch {
    return false;
  }
}

/**
 * Blank out comments while preserving line numbers and column offsets, so
 * that documentation examples do not become findings.
 * @param {string} source
 * @param {{line:string[], block:Array<[string,string]>}} syntax
 */
export function stripComments(source, syntax) {
  if (!syntax) return source;
  const chars = source.split('');
  const n = chars.length;
  const blank = (from, to) => {
    for (let i = from; i < to && i < n; i++) {
      if (chars[i] !== '\n') chars[i] = ' ';
    }
  };

  // Block comments first.
  for (const [open, close] of syntax.block || []) {
    let idx = 0;
    while (true) {
      const start = source.indexOf(open, idx);
      if (start === -1) break;
      const end = source.indexOf(close, start + open.length);
      if (end === -1) {
        blank(start, n);
        break;
      }
      blank(start, end + close.length);
      idx = end + close.length;
    }
  }

  // Then line comments, skipping anything inside string literals (rough).
  let i = 0;
  let quote = null;
  let escaped = false;
  while (i < n) {
    const c = source[i];
    if (quote) {
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === quote) quote = null;
      i++;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      quote = c;
      i++;
      continue;
    }
    let matched = null;
    for (const marker of syntax.line || []) {
      if (source.startsWith(marker, i)) {
        matched = marker;
        break;
      }
    }
    if (matched) {
      const eol = source.indexOf('\n', i);
      const end = eol === -1 ? n : eol;
      blank(i, end);
      i = end;
      continue;
    }
    i++;
  }

  return chars.join('');
}

/** Split a source into lines, keeping original line numbers. */
export function toLines(source) {
  return source.split(/\r?\n/);
}
