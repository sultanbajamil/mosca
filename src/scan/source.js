/**
 * MOSCA — source code scanner
 * ===========================
 *
 * Applies the language rules to every file it is given and produces
 * normalised findings with file/line/column, a snippet and a confidence.
 */

import path from 'node:path';
import { RULES, LANGUAGE_BY_EXT, LANGUAGE_LABELS, COMMENT_SYNTAX } from '../rules/source.js';
import { lookup, rsaVariant } from '../rules/algorithms.js';
import { stripComments, walk, readTextFile, createIgnore, loadIgnoreFile } from '../util/fs.js';
import { collectConstants, resolveConstantAlgorithm, INDIRECT_RULES } from './constants.js';

/** Longest snippet we keep, to keep reports readable. */
const MAX_SNIPPET = 180;

/**
 * Detect the language of a file from its extension.
 * @param {string} file
 */
export function detectLanguage(file) {
  const ext = path.extname(file).toLowerCase();
  return LANGUAGE_BY_EXT[ext] || null;
}

/** Precompute line-start offsets for fast index -> line conversion. */
function lineIndex(source) {
  const starts = [0];
  for (let i = 0; i < source.length; i++) {
    if (source[i] === '\n') starts.push(i + 1);
  }
  return starts;
}

/** Binary search: character offset -> 0-based line number. */
function offsetToLine(starts, offset) {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

/**
 * Resolve the algorithm for a rule match, including key-size refinement.
 */
function resolveAlgorithm(rule, match) {
  let algoId;
  try {
    algoId = typeof rule.algo === 'function' ? rule.algo(match) : rule.algo;
  } catch {
    return lookup('unknown');
  }
  if (!algoId) return lookup('unknown');
  let algo = lookup(algoId);
  // Refine RSA by declared key size where the rule captured one.
  if (algo.id === 'rsa' && typeof rule.bits === 'function') {
    try {
      const bits = rule.bits(match);
      if (bits) algo = rsaVariant(bits);
    } catch {
      /* keep the generic entry */
    }
  }
  return algo;
}

/** Matches an inline suppression directive in any comment syntax. */
const SUPPRESSION = /\bmosca-ignore-(line|next-line|file)\b(?:[:\s-]+(.*))?/i;

/**
 * Read suppression directives from the original text.
 *
 * Comments are stripped before rules run, so a directive is deliberately read
 * from `content` rather than from `stripped`. Any comment spelling works
 * (`//`, `#`, `--`, `/* … *\/`), because only the directive itself is matched.
 *
 *   // mosca-ignore-line -- reason
 *   // mosca-ignore-next-line -- reason
 *   // mosca-ignore-file -- reason
 *
 * @param {string} content
 * @returns {{file:boolean, lines:Map<number,string>, next:Map<number,string>, count:number}}
 */
export function readSuppressions(content) {
  const lines = content.split(/\r?\n/);
  const result = { file: false, lines: new Map(), next: new Map(), count: 0 };
  for (let i = 0; i < lines.length; i++) {
    const match = SUPPRESSION.exec(lines[i]);
    if (!match) continue;
    const reason = (match[2] || '').replace(/\s*(?:\*\/|-->)\s*$/, '').trim();
    if (match[1].toLowerCase() === 'file') {
      result.file = true;
      result.fileReason = reason || null;
      result.count++;
    } else if (match[1].toLowerCase() === 'next-line') {
      result.next.set(i + 1, reason || null);
      result.count++;
    } else {
      result.lines.set(i, reason || null);
      result.count++;
    }
  }
  return result;
}

/** True when a 0-based line is covered by a suppression directive. */
function isSuppressed(suppressions, line) {
  return suppressions.file || suppressions.lines.has(line) || suppressions.next.has(line);
}

/**
 * Scan a single in-memory source file.
 * @param {{content:string, rel:string, language:string}} input
 * @returns {Array<object>} findings
 */
export function scanSourceContent(input) {
  return scanSourceContentDetailed(input).findings;
}

/**
 * Same as `scanSourceContent`, but also reports how many findings were
 * suppressed. The scan pipeline uses this so the total is auditable: a
 * suppression is a decision someone made, not a silent deletion.
 *
 * @param {{content:string, rel:string, language:string}} input
 * @returns {{findings:Array<object>, suppressed:number}}
 */
export function scanSourceContentDetailed({ content, rel, language }) {
  const rules = RULES[language];
  if (!rules) return { findings: [], suppressed: 0 };
  const syntax = COMMENT_SYNTAX[language];
  const stripped = stripComments(content, syntax);
  const lines = content.split(/\r?\n/);
  const starts = lineIndex(stripped);
  const findings = [];
  const seen = new Set();
  const suppressions = readSuppressions(content);
  let suppressed = 0;

  // -------------------------------------------------- literal API arguments
  for (const rule of rules) {
    let match;
    const re = new RegExp(rule.re.source, rule.re.flags.includes('g') ? rule.re.flags : `${rule.re.flags}g`);
    re.lastIndex = 0;
    while ((match = re.exec(stripped)) !== null) {
      const line = offsetToLine(starts, match.index);
      const column = match.index - starts[line] + 1;
      const key = `${rule.id}:${line}`;
      if (seen.has(key)) {
        if (match[0].length === 0) re.lastIndex++;
        continue;
      }
      seen.add(key);
      if (isSuppressed(suppressions, line)) {
        suppressed++;
        if (match[0].length === 0) re.lastIndex++;
        continue;
      }

      const algo = resolveAlgorithm(rule, match);
      const rawLine = (lines[line] || '').trim().slice(0, MAX_SNIPPET);
      findings.push({
        id: rule.id,
        kind: 'source',
        title: `${algo.label} — ${describePrimitive(rule.primitive)}`,
        algorithm: algo.id,
        algorithmLabel: algo.label,
        primitive: rule.primitive,
        location: { file: rel, line: line + 1, column },
        snippet: rawLine,
        matched: match[0].slice(0, MAX_SNIPPET),
        confidence: rule.confidence || 'medium',
        note: rule.note || algo.note || null,
        language,
      });

      if (match[0].length === 0) re.lastIndex++;
    }
  }

  // ------------------------------------- identifiers resolved from constants
  const constants = collectConstants(stripped, language);
  if (constants.size) {
    suppressed += scanIndirect({
      stripped,
      starts,
      lines,
      language,
      rel,
      constants,
      suppressions,
      seen,
      findings,
    });
  }

  return { findings: mergeRefinements(findings), suppressed };
}

/**
 * Resolve `createHash(ALGORITHM)` style calls using file-local constants.
 * Only the argument position is considered, so a constant named `md5` used
 * as a variable elsewhere cannot manufacture a finding.
 *
 * @returns {number} number of suppressed findings
 */
function scanIndirect({ stripped, starts, lines, language, rel, constants, suppressions, seen, findings }) {
  const rules = INDIRECT_RULES[language] || [];
  let suppressed = 0;

  for (const rule of rules) {
    const re = new RegExp(rule.re.source, rule.re.flags.includes('g') ? rule.re.flags : `${rule.re.flags}g`);
    re.lastIndex = 0;
    let match;
    while ((match = re.exec(stripped)) !== null) {
      const line = offsetToLine(starts, match.index);
      const column = match.index - starts[line] + 1;
      const name = match[1];
      if (!constants.has(name)) {
        if (match[0].length === 0) re.lastIndex++;
        continue;
      }
      const value = constants.get(name);
      const algo = resolveConstantAlgorithm(value, rule.transform);
      if (!algo) {
        if (match[0].length === 0) re.lastIndex++;
        continue;
      }

      const key = `${rule.id}:${line}`;
      if (seen.has(key)) {
        if (match[0].length === 0) re.lastIndex++;
        continue;
      }
      seen.add(key);

      if (isSuppressed(suppressions, line)) {
        suppressed++;
        if (match[0].length === 0) re.lastIndex++;
        continue;
      }

      findings.push({
        id: rule.id,
        kind: 'source',
        title: `${algo.label} — ${describePrimitive(rule.primitive)}`,
        algorithm: algo.id,
        algorithmLabel: algo.label,
        primitive: rule.primitive,
        location: { file: rel, line: line + 1, column },
        snippet: (lines[line] || '').trim().slice(0, MAX_SNIPPET),
        matched: match[0].slice(0, MAX_SNIPPET),
        confidence: 'medium',
        note: `Algorithm resolved from the file-local constant ${name} = '${value}'. Confirm that the constant is not reassigned at runtime.`,
        language,
        evidence: { constant: name, value },
      });

      if (match[0].length === 0) re.lastIndex++;
    }
  }
  return suppressed;
}

/**
 * Two rules often describe the same call: one sees `generateKeyPair('rsa')`,
 * the other sees `modulusLength: 2048`. Reporting both doubles the finding
 * count for a single defect and sends the reader to the same line twice.
 * Keep the first finding (it usually names the primitive) and adopt the more
 * specific algorithm id from the refinement.
 */
function mergeRefinements(findings) {
  const out = [];
  for (const finding of findings) {
    const existing = out.find(
      (o) => o.location.line === finding.location.line && related(o.algorithm, finding.algorithm),
    );
    if (!existing) {
      out.push(finding);
      continue;
    }
    if (finding.algorithm.length > existing.algorithm.length) {
      existing.algorithm = finding.algorithm;
      existing.algorithmLabel = finding.algorithmLabel;
      existing.title = finding.title;
    }
  }
  return out;
}

/** True when one algorithm id is a generic or refined form of the other. */
function related(a, b) {
  return a === b || a.startsWith(`${b}-`) || b.startsWith(`${a}-`);
}

function describePrimitive(primitive) {
  switch (primitive) {
    case 'key-agreement': return 'key exchange';
    case 'signature': return 'digital signature';
    case 'pke': return 'public-key encryption';
    case 'symmetric': return 'symmetric encryption';
    case 'hash': return 'hashing';
    case 'mac': return 'message authentication';
    case 'kdf': return 'key derivation';
    case 'protocol': return 'protocol configuration';
    default: return primitive;
  }
}

/**
 * Scan a directory tree for cryptographic API usage.
 * @param {string} root
 * @param {{ignore?:string[], maxFiles?:number, onProgress?:(n:number)=>void}} [opts]
 */
export function scanSourceDirectory(root, opts = {}) {
  const { ignore: extraIgnore = [], maxFiles = 50000, onProgress } = opts;
  const patterns = [...loadIgnoreFile(root), ...extraIgnore];
  const ignore = createIgnore(patterns);
  const files = walk(root, { ignore, maxFiles });

  const findings = [];
  const byLanguage = {};
  const byFile = {};
  let filesScanned = 0;
  let bytesScanned = 0;
  let suppressed = 0;

  for (const file of files) {
    const language = detectLanguage(file.path);
    if (!language) continue;
    const content = readTextFile(file.path);
    if (content == null) continue;
    filesScanned++;
    bytesScanned += content.length;
    byLanguage[language] = (byLanguage[language] || 0) + 1;
    const result = scanSourceContentDetailed({ content, rel: file.rel, language });
    suppressed += result.suppressed;
    if (result.findings.length) {
      byFile[file.rel] = result.findings.length;
      findings.push(...result.findings);
    }
    if (onProgress && filesScanned % 200 === 0) onProgress(filesScanned);
  }

  return {
    findings,
    stats: {
      filesScanned,
      bytesScanned,
      byLanguage,
      byFile,
      totalFiles: files.length,
      suppressed,
    },
  };
}

export { LANGUAGE_LABELS };
