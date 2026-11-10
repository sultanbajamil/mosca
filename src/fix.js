/**
 * MOSCA — `mosca fix`
 * ==================
 *
 * A scanner that only complains is easy to ignore. This module turns a scan
 * into a *reviewable* change set:
 *
 *   - hashes, MACs and AES key-size upgrades become textual hunks that a human
 *     can read in a diff and apply deliberately;
 *   - signatures, key agreement, certificates, configuration, lockfiles and
 *     live listeners become numbered advisories, because those changes are
 *     protocol or trust-chain migrations, not find-and-replace.
 *
 * Nothing here writes to disk and nothing here applies a patch. The CLI prints
 * the plan or writes a `.patch` file; the operator decides.
 */

import fs from 'node:fs';
import path from 'node:path';
import { lookup, replacementFor } from './rules/algorithms.js';

/** Primitives whose argument is a literal we can safely rewrite in place. */
const AUTO_PRIMITIVES = new Set(['hash', 'mac', 'symmetric']);

/**
 * Human-readable migration notes. A patch that says only "MD5 → SHA-256" is
 * dangerous because the operator may not realise that stored digests must be
 * re-computed.
 */
const NOTES = {
  hash: 'Changing a hash makes every previously stored digest incompatible. Re-compute stored digests or keep a verification-only legacy path until the data is migrated.',
  mac: 'Changing the MAC digest invalidates stored MACs. Rotate the key and re-issue MACs for persisted data.',
  symmetric: 'Changing the symmetric algorithm requires re-encrypting data and rotating keys. The patch only changes the identifier, not the key material.',
};

/** Algorithm aliases as they appear in source, longest first. */
const ALIASES = {
  md5: ['md5'],
  sha1: ['sha-1', 'sha1'],
  'hmac-md5': ['md5'],
  'hmac-sha1': ['sha-1', 'sha1'],
  rc4: ['arcfour', 'rc4'],
  des: ['3des', 'tripledes', 'des3', 'des'],
  '3des': ['3des', 'tripledes', 'des3'],
  'aes-128': ['aes-128', 'aes128', 'aes_128'],
  'aes-128-cbc': ['aes-128-cbc', 'aes128cbc'],
  'aes-128-gcm': ['aes-128-gcm', 'aes128gcm'],
  'aes-128-ctr': ['aes-128-ctr', 'aes128ctr'],
  'aes-192': ['aes-192', 'aes192', 'aes_192'],
  'aes-192-cbc': ['aes-192-cbc', 'aes192cbc'],
  'aes-192-gcm': ['aes-192-gcm', 'aes192gcm'],
};

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Aliases for an algorithm id, most specific first. */
function aliasesFor(id) {
  if (ALIASES[id]) return ALIASES[id];
  if (/^aes-/.test(id)) return [id, id.replace(/-/g, ''), id.replace(/-/g, '_')];
  return [id.replace(/^hmac-/, '')];
}

/** True when the original spelling is SCREAMING_CASE. */
function isUpper(original) {
  const letters = original.replace(/[^A-Za-z]/g, '');
  return letters.length > 0 && letters === letters.toUpperCase();
}

/**
 * Format the replacement using the separators and case of the original token,
 * so `MD5` becomes `SHA256`, `SHA-1` becomes `SHA-256` and `aes-128-cbc`
 * becomes `aes-256-cbc`.
 */
function formatToken(original, target, primitive, language) {
  let base = target;
  if (primitive === 'mac') base = base.replace(/^hmac-/, '');

  // Keep the AES mode: aes-128-cbc upgrades to aes-256-cbc, not to GCM.
  const aes = /^aes-(\d+)((?:-[a-z0-9]+)*)$/i.exec(original);
  if (aes && /^aes-\d+/.test(base)) {
    const targetSize = /^aes-(\d+)/.exec(base)[1];
    const mode = aes[2];
    base = `aes-${targetSize}${mode}`;
  }

  // Java and Kotlin require the dashed form ("SHA-256"); C# and Node do not.
  const dashed = original.includes('-') || ['java', 'kotlin'].includes(language);
  if (/^sha(256|384|512)$/.test(base)) {
    base = dashed ? `${base.slice(0, 3)}-${base.slice(3)}` : base;
  }

  if (isUpper(original)) return base.toUpperCase();
  // Java/Kotlin literals are often "AES/CBC/PKCS5Padding"; leave those alone.
  if (/^[A-Z]/.test(original) && original === original.replace(/[a-z]/g, (ch) => ch)) {
    return base.charAt(0).toUpperCase() + base.slice(1);
  }
  return base;
}

/** Files where an algorithm choice is fixed by a protocol or a test vector. */
const SENSITIVE_PATH = /(^|[\\/])(net|protocol|protocols|tls|quic|ssh|ikev2?|ipsec|test|tests|spec|fixtures)([\\/]|[-_.])/i;

function isProtocolSensitive(file) {
  return Boolean(file) && SENSITIVE_PATH.test(file);
}

/**
 * Find the exact token inside a matched string and build the replacement.
 * Returns null when the algorithm cannot be rewritten in place.
 *
 * @param {object} item enriched finding
 */
export function buildAutoReplace(item) {
  if (!AUTO_PRIMITIVES.has(item.primitive)) return null;
  if (item.positive) return null;

  const original = String(item.matched || item.snippet || '');
  if (!original) return null;

  const algo = lookup(item.algorithm);
  const target = replacementFor(algo, item.primitive) || algo.replacement;
  if (!target || target === item.algorithm) return null;

  // A symmetric family change (RC4/DES → AES-GCM) is not a literal swap: the
  // IV, tag and key schedule all change. Keep it as an advisory.
  if (item.primitive === 'symmetric' && !/^aes-/.test(item.algorithm)) return null;

  // A protocol implementation or a test vector pins the algorithm. Rewriting
  // `aes-128-gcm` in a QUIC Initial or a TLS test would break the wire format,
  // so it is a deliberate change rather than a literal swap.
  if (item.primitive === 'symmetric' && isProtocolSensitive(item.location?.file)) return null;

  const candidates = aliasesFor(item.algorithm)
    .filter(Boolean)
    .sort((a, b) => b.length - a.length);

  for (const alias of candidates) {
    const re = new RegExp(escapeRegExp(alias), 'i');
    const match = re.exec(original);
    if (!match) continue;
    const replacement = formatToken(match[0], target, item.primitive, item.language);
    if (!replacement || replacement.toLowerCase() === match[0].toLowerCase()) continue;
    const resolved = lookup(replacement.toLowerCase());
    const targetId = resolved.id !== 'unknown' ? resolved.id : target;
    return { match: match[0], replacement, target: targetId };
  }
  return null;
}

/** Advisory text for findings that need a human migration. */
function advisoryFor(item) {
  switch (item.primitive) {
    case 'signature':
      return 'Replace the classical signature with ML-DSA-65 (FIPS 204) or ML-DSA-87. Key format, token size and trust chain all change; run a dual-signing period rather than a drop-in replacement.';
    case 'key-agreement':
    case 'pke':
      return 'Enable hybrid X25519MLKEM768 (or ML-KEM-768) at the listener, library or protocol layer. The wire format and certificate size change; test middleboxes and session resumption.';
    case 'certificate':
      return 'Re-issue the certificate hierarchy with a post-quantum or hybrid signature. Root and intermediate rotation is the long pole; start cross-signing before the leaf change.';
    case 'protocol':
      return 'Raise the protocol floor to TLS 1.3 (or TLS 1.2 with approved suites) and enable hybrid key exchange. Validate clients before removing legacy versions.';
    case 'symmetric':
      return isProtocolSensitive(item.location?.file)
        ? 'The algorithm is fixed by a protocol profile or a test vector. Do not edit the literal in place: this is a wire-format or interoperability decision. Change the protocol profile, or keep the vector and document the exception.'
        : 'This cipher is not a literal swap: the IV, authentication tag and key schedule change. Re-encrypt the data under AES-256-GCM with a rotated key.';
    default:
      break;
  }
  if (item.kind === 'config') {
    return `Edit the configuration at ${item.location?.file || 'the reported file'}, line ${item.location?.line || '?'}. Configuration changes need a rollback plan and a maintenance window.`;
  }
  if (item.kind === 'dependency') {
    return 'Upgrade the dependency to a release that provides the post-quantum or fixed primitive. Check the changelog for API changes before bumping.';
  }
  if (item.kind === 'chain') {
    return 'The certificate hierarchy must migrate as a unit. Audit intermediates and roots, then plan a cross-signed transition.';
  }
  if (item.kind === 'artifact') {
    return 'Rotate the on-disk key or certificate material and re-issue dependants. Do not edit key files in place.';
  }
  if (item.kind === 'endpoint') {
    return `Change the listener policy on ${item.location?.host || 'the endpoint'}${item.location?.port ? `:${item.location.port}` : ''}, then re-scan to confirm the negotiated primitive.`;
  }
  return `Migrate ${item.algorithmLabel || item.algorithm} manually after reviewing the call site.`;
}

function locationOf(item) {
  const location = item.location || {};
  return {
    file: location.file || null,
    line: location.line || null,
    column: location.column || null,
    host: location.host || null,
    port: location.port || null,
  };
}

function siteKey(item) {
  const loc = locationOf(item);
  return `${loc.file || loc.host || 'unknown'}|${loc.line || ''}|${item.algorithm}|${item.primitive}`;
}

/**
 * Build a fix plan from an analysis object (or an array of enriched items).
 *
 * @param {object|object[]} analysis
 * @returns {{automatic:object[], manual:object[], summary:object}}
 */
export function buildFixPlan(analysis) {
  const items = Array.isArray(analysis) ? analysis : analysis.items || [];
  const automatic = [];
  const manual = [];
  const seen = new Set();
  const manualSeen = new Set();

  for (const item of items) {
    if (item.positive) continue;
    if (item.severity === 'info') continue;

    const key = siteKey(item);
    if (seen.has(key)) continue;
    seen.add(key);

    const edit = buildAutoReplace(item);
    if (edit) {
      automatic.push({
        id: item.id,
        kind: item.kind,
        algorithm: item.algorithm,
        algorithmLabel: item.algorithmLabel || lookup(item.algorithm).label,
        primitive: item.primitive,
        location: locationOf(item),
        automatic: true,
        match: edit.match,
        replacement: edit.replacement,
        target: edit.target,
        before: item.matched || item.snippet || edit.match,
        note: NOTES[item.primitive] || NOTES.symmetric,
        reason: `${item.algorithmLabel || item.algorithm} → ${lookup(edit.target).label || edit.target}`,
      });
      continue;
    }

    // Collapse repeated advisories for the same algorithm so the plan reads
    // like a migration checklist rather than a finding dump.
    const advisoryKey = `${item.algorithm}|${item.primitive}`;
    if (manualSeen.has(advisoryKey)) continue;
    manualSeen.add(advisoryKey);

    manual.push({
      id: item.id,
      kind: item.kind,
      algorithm: item.algorithm,
      algorithmLabel: item.algorithmLabel || lookup(item.algorithm).label,
      primitive: item.primitive,
      location: locationOf(item),
      automatic: false,
      occurrences: items.filter(
        (other) => !other.positive && other.algorithm === item.algorithm && other.primitive === item.primitive,
      ).length,
      advisory: advisoryFor(item),
    });
  }

  automatic.sort((a, b) => (a.location.file || '').localeCompare(b.location.file || '') || (a.location.line || 0) - (b.location.line || 0));
  manual.sort((a, b) => b.occurrences - a.occurrences || a.algorithm.localeCompare(b.algorithm));

  return {
    automatic,
    manual,
    summary: {
      automatic: automatic.length,
      manual: manual.length,
      files: new Set(automatic.map((e) => e.location.file).filter(Boolean)).size,
      algorithms: new Set([...automatic, ...manual].map((e) => e.algorithm)).size,
    },
  };
}

/** Render a hunk header and body for one file. */
function renderHunk(lines, changes, context) {
  const out = [];
  let index = 0;
  while (index < changes.length) {
    const first = changes[index];
    let last = first;
    let next = index + 1;
    while (next < changes.length && changes[next].line - last.line <= context * 2 + 1) {
      last = changes[next];
      next += 1;
    }

    const start = Math.max(1, first.line - context);
    const end = Math.min(lines.length, last.line + context);
    const oldCount = end - start + 1;
    const newCount = oldCount + (next - index);
    out.push(`@@ -${start},${oldCount} +${start},${newCount} @@`);

    const byLine = new Map();
    for (let i = index; i < next; i++) byLine.set(changes[i].line, changes[i]);

    for (let line = start; line <= end; line++) {
      const change = byLine.get(line);
      if (!change) {
        out.push(` ${lines[line - 1]}`);
      } else {
        out.push(`-${change.before}`);
        out.push(`+${change.after}`);
      }
    }
    index = next;
  }
  return out;
}

/**
 * Turn a plan into a unified diff. Files are read through `readFile`, which
 * makes the builder testable and keeps the module free of hidden I/O.
 *
 * @param {object} plan output of buildFixPlan
 * @param {{root?:string, readFile?:(p:string)=>string|null, context?:number}} [opts]
 */
export function buildPatch(plan, { root = process.cwd(), readFile, context = 3 } = {}) {
  const reader = readFile || ((absolute) => fs.readFileSync(absolute, 'utf8'));
  const byFile = new Map();
  for (const edit of plan.automatic || []) {
    if (!edit.location.file) continue;
    if (!byFile.has(edit.location.file)) byFile.set(edit.location.file, []);
    byFile.get(edit.location.file).push(edit);
  }

  const chunks = [];
  const applied = [];
  const skipped = [];

  for (const [file, edits] of [...byFile.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const absolute = path.isAbsolute(file) ? file : path.join(root, file);
    let content;
    try {
      content = reader(absolute);
    } catch {
      skipped.push({ file, reason: 'file not readable' });
      continue;
    }
    if (typeof content !== 'string') {
      skipped.push({ file, reason: 'file not readable' });
      continue;
    }

    const eol = content.includes('\r\n') ? '\r\n' : '\n';
    const lines = content.split(/\r?\n/);
    const changes = [];
    let appliedHere = 0;

    for (const edit of [...edits].sort((a, b) => a.location.line - b.location.line)) {
      const lineNo = edit.location.line;
      const original = lines[lineNo - 1];
      if (typeof original !== 'string') {
        skipped.push({ file, line: lineNo, reason: 'line out of range' });
        continue;
      }
      const at = original.indexOf(edit.match);
      if (at === -1) {
        skipped.push({ file, line: lineNo, reason: `literal "${edit.match}" not found` });
        continue;
      }
      const after = original.slice(0, at) + edit.replacement + original.slice(at + edit.match.length);
      if (after === original) continue;
      changes.push({ line: lineNo, before: original, after });
      appliedHere += 1;
    }

    if (!changes.length) continue;

    const resolvedFile = path.relative(root, absolute).replace(/\\/g, '/') || file;
    chunks.push(`--- a/${resolvedFile}${eol}+++ b/${resolvedFile}${eol}${renderHunk(lines, changes, context).join(eol)}${eol}`);
    applied.push({ file: resolvedFile, edits: appliedHere });
  }

  return { patch: chunks.join(''), applied, skipped };
}

/**
 * Plain-text plan, suitable for `--format text` and for terminals that cannot
 * render a diff.
 */
export function renderFixReport(plan) {
  const { automatic, manual, summary } = plan;
  const out = [];
  out.push(`MOSCA fix plan — ${summary.automatic} automatic edit${summary.automatic === 1 ? '' : 's'} in ${summary.files} file${summary.files === 1 ? '' : 's'}, ${summary.manual} manual advisor${summary.manual === 1 ? 'y' : 'ies'}`);
  out.push('Nothing is applied automatically. Review the patch or the advisory, then edit by hand.');

  out.push('');
  out.push('AUTOMATIC (safe literal swaps, review the diff)');
  if (!automatic.length) out.push('  (none)');
  for (const edit of automatic) {
    const at = edit.location.file ? `${edit.location.file}:${edit.location.line}` : 'unknown location';
    out.push(`  ${at}  ${edit.reason}`);
    out.push(`      ${edit.match} -> ${edit.replacement}`);
    if (edit.note) out.push(`      note: ${edit.note}`);
  }

  out.push('');
  out.push('MANUAL (protocol, key or configuration change)');
  if (!manual.length) out.push('  (none)');
  for (const item of manual) {
    const at = item.location.file
      ? `${item.location.file}:${item.location.line}`
      : item.location.host
        ? `${item.location.host}:${item.location.port ?? ''}`
        : 'estate';
    out.push(`  ${at}  ${item.algorithmLabel} (${item.occurrences} finding${item.occurrences === 1 ? '' : 's'})`);
    out.push(`      ${item.advisory}`);
  }
  return out.join('\n');
}

export { AUTO_PRIMITIVES };
