/**
 * MOSCA — file-local constant propagation
 * =======================================
 *
 * Crypto APIs are rarely called with a literal. Real code looks like:
 *
 *     const HASH = 'md5';
 *     crypto.createHash(HASH).update(payload);
 *
 * or:
 *
 *     private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
 *     Cipher.getInstance(TRANSFORMATION);
 *
 * A CWE-class scanner that only matches literals misses the majority of
 * production call sites. This module collects single-assignment string
 * constants from one file and resolves them only in the argument position of
 * a known cryptographic API. It is deliberately not a general evaluator:
 *
 *   - one file only;
 *   - declaration and use must agree on one literal value;
 *   - interpolation, concatenation and reassignment are ignored;
 *   - the resolved value must map to a registry entry.
 *
 * Anything else stays unresolved, which keeps confidence honest.
 */

import { lookup } from '../rules/algorithms.js';

/** Identity transform for constants that already name the algorithm. */
const identity = (value) => value;

/** createHmac takes a digest name; the registry id is `hmac-<digest>`. */
const hmac = (value) => (/^hmac-/i.test(value) ? value : `hmac-${value}`);

/**
 * Constant-declaration patterns by language. Every pattern captures the
 * identifier first and the single-quoted or double-quoted literal second.
 * @type {Record<string, RegExp[]>}
 */
const CONSTANT_PATTERNS = {
  javascript: [
    /(?:^|[^\w$])(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[A-Za-z_$][\w$<>[\]| ]*)?=\s*['"`]([^'"`\n]+)['"`]/g,
  ],
  typescript: [
    /(?:^|[^\w$])(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[A-Za-z_$][\w$<>[\]| ]*)?=\s*['"`]([^'"`\n]+)['"`]/g,
  ],
  python: [/^[ \t]*([A-Za-z_]\w*)\s*(?::\s*[^=\n]+)?=\s*['"]([^'"\n]+)['"]/gm],
  java: [
    /(?:^|[^\w$])(?:(?:public|private|protected|static|final|readonly|const)\s+)*(?:String|string|val|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"([^"\n]+)"/g,
  ],
  kotlin: [
    /(?:^|[^\w$])(?:(?:public|private|protected|internal|const|val|var)\s+)*(?:val|var)\s+([A-Za-z_]\w*)\s*(?::\s*String)?\s*=\s*"([^"\n]+)"/g,
  ],
  csharp: [
    /(?:^|[^\w$])(?:(?:public|private|protected|internal|static|readonly|const)\s+)*(?:string|String)\s+([A-Za-z_]\w*)\s*=\s*"([^"\n]+)"/g,
  ],
  c: [
    /(?:^|[^\w$])#define\s+([A-Za-z_]\w*)\s+"([^"\n]+)"/g,
    /(?:^|[^\w$])(?:static\s+)?const\s+char\s*\*?\s*([A-Za-z_]\w*)\s*=\s*"([^"\n]+)"/g,
  ],
  cpp: [
    /(?:^|[^\w$])#define\s+([A-Za-z_]\w*)\s+"([^"\n]+)"/g,
    /(?:^|[^\w$])(?:static\s+)?const\s+char\s*\*?\s*([A-Za-z_]\w*)\s*=\s*"([^"\n]+)"/g,
  ],
  rust: [/(?:^|[^\w$])(?:const|static)\s+([A-Za-z_]\w*)\s*:\s*&(?:'static\s+)?str\s*=\s*"([^"\n]+)"/g],
  php: [/\$([A-Za-z_]\w*)\s*=\s*['"]([^'"\n]+)['"]/g],
  ruby: [/(?:^|[^\w$])([A-Z]\w*)\s*=\s*['"]([^'"\n]+)['"]/g],
};

/**
 * Collect file-local string constants.
 *
 * A name declared twice with different values is discarded: the scanner must
 * not guess which branch runs.
 *
 * @param {string} source comment-stripped source, so commented declarations do not count
 * @param {string} language
 * @returns {Map<string,string>}
 */
export function collectConstants(source, language) {
  const patterns = CONSTANT_PATTERNS[language];
  const constants = new Map();
  if (!patterns) return constants;

  const seen = new Map(); // name -> Set<value>
  const declarations = new Map(); // name -> declaration count
  for (const pattern of patterns) {
    const re = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`);
    re.lastIndex = 0;
    let match;
    while ((match = re.exec(source)) !== null) {
      const name = match[1];
      const value = match[2].trim();
      if (!name || !value || value.length > 120) continue;
      // Template placeholders and computed expressions are not constants.
      if (value.includes('${')) continue;
      const after = source.slice(re.lastIndex).match(/^[ \t]*(.)/);
      if (after && ['.', '(', '+', '['].includes(after[1])) continue;
      if (!seen.has(name)) seen.set(name, new Set());
      seen.get(name).add(value);
      declarations.set(name, (declarations.get(name) || 0) + 1);
      if (match[0].length === 0) re.lastIndex++;
    }
  }

  // A constant that is reassigned is not a constant. Count every assignment
  // of the candidate name; anything beyond the declaration is a write.
  const assignments = new Map();
  for (const name of seen.keys()) {
    const re = new RegExp(`(?:^|[^\\w$.])${escapeRegExp(name)}\\s*=(?!=|>)`, 'g');
    const count = (source.match(re) || []).length;
    assignments.set(name, count);
  }

  for (const [name, values] of seen) {
    const declared = declarations.get(name) || 0;
    const assigned = assignments.get(name) || 0;
    if (values.size === 1 && assigned <= declared) constants.set(name, [...values][0]);
  }
  return constants;
}

/** Escape a string for use inside a RegExp. */
function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Resolve a constant value to a registry entry.
 *
 * Java and .NET transformation strings carry mode and padding after a slash
 * (`AES/CBC/PKCS5Padding`); the algorithm is the first segment. Everything
 * else is handed to the registry's normaliser, which already tolerates case,
 * spaces and underscores.
 *
 * @param {string} value
 * @param {(v:string)=>string} [transform]
 */
export function resolveConstantAlgorithm(value, transform = identity) {
  if (!value) return null;
  const candidates = new Set([String(value).trim()]);
  if (value.includes('/')) candidates.add(value.split('/')[0].trim());
  if (value.includes(':')) candidates.add(value.split(':')[0].trim());
  for (const candidate of candidates) {
    if (!candidate) continue;
    const algo = lookup(transform(candidate));
    if (algo.id && algo.id !== 'unknown') return algo;
  }
  return null;
}

/**
 * Indirect-call rules: the argument is an identifier, not a literal.
 * The literal rules in `src/rules/source.js` never fire on these, so the two
 * sets cannot double-report the same call.
 *
 * @type {Record<string, Array<{id:string,re:RegExp,primitive:string,transform?:(v:string)=>string}>>}
 */
export const INDIRECT_RULES = {
  javascript: [
    { id: 'js-indirect-createHash', re: /\bcreateHash\s*\(\s*([A-Za-z_$][\w$]*)\s*\)/g, primitive: 'hash' },
    { id: 'js-indirect-createHmac', re: /\bcreateHmac\s*\(\s*([A-Za-z_$][\w$]*)\s*,/g, primitive: 'mac', transform: hmac },
    {
      id: 'js-indirect-createCipher',
      re: /\bcreate(?:Cipher|Decipher)(?:iv)?\s*\(\s*([A-Za-z_$][\w$]*)\s*,/g,
      primitive: 'symmetric',
    },
    { id: 'js-indirect-createSign', re: /\bcreate(?:Sign|Verify)\s*\(\s*([A-Za-z_$][\w$]*)\s*,/g, primitive: 'signature' },
    {
      id: 'js-indirect-generateKeyPair',
      re: /\bgenerateKeyPair(?:Sync)?\s*\(\s*([A-Za-z_$][\w$]*)\s*,/g,
      primitive: 'signature',
    },
  ],
  typescript: [
    { id: 'js-indirect-createHash', re: /\bcreateHash\s*\(\s*([A-Za-z_$][\w$]*)\s*\)/g, primitive: 'hash' },
    { id: 'js-indirect-createHmac', re: /\bcreateHmac\s*\(\s*([A-Za-z_$][\w$]*)\s*,/g, primitive: 'mac', transform: hmac },
    {
      id: 'js-indirect-createCipher',
      re: /\bcreate(?:Cipher|Decipher)(?:iv)?\s*\(\s*([A-Za-z_$][\w$]*)\s*,/g,
      primitive: 'symmetric',
    },
    { id: 'js-indirect-createSign', re: /\bcreate(?:Sign|Verify)\s*\(\s*([A-Za-z_$][\w$]*)\s*,/g, primitive: 'signature' },
    {
      id: 'js-indirect-generateKeyPair',
      re: /\bgenerateKeyPair(?:Sync)?\s*\(\s*([A-Za-z_$][\w$]*)\s*,/g,
      primitive: 'signature',
    },
  ],
  python: [
    { id: 'py-indirect-hashlib-new', re: /\bhashlib\.new\s*\(\s*([A-Za-z_]\w*)\s*[,)]/g, primitive: 'hash' },
    { id: 'py-indirect-hmac-new', re: /\bhmac\.new\s*\([^)]*digestmod\s*=\s*([A-Za-z_]\w*)/g, primitive: 'mac', transform: hmac },
  ],
  java: [
    { id: 'java-indirect-messageDigest', re: /\bMessageDigest\.getInstance\s*\(\s*([A-Za-z_]\w*)\s*\)/g, primitive: 'hash' },
    { id: 'java-indirect-cipher', re: /\bCipher\.getInstance\s*\(\s*([A-Za-z_]\w*)\s*\)/g, primitive: 'symmetric' },
    { id: 'java-indirect-signature', re: /\bSignature\.getInstance\s*\(\s*([A-Za-z_]\w*)\s*\)/g, primitive: 'signature' },
    {
      id: 'java-indirect-keyPairGenerator',
      re: /\bKeyPairGenerator\.getInstance\s*\(\s*([A-Za-z_]\w*)\s*\)/g,
      primitive: 'signature',
    },
  ],
  kotlin: [
    { id: 'java-indirect-messageDigest', re: /\bMessageDigest\.getInstance\s*\(\s*([A-Za-z_]\w*)\s*\)/g, primitive: 'hash' },
    { id: 'java-indirect-cipher', re: /\bCipher\.getInstance\s*\(\s*([A-Za-z_]\w*)\s*\)/g, primitive: 'symmetric' },
    { id: 'java-indirect-keyPairGenerator', re: /\bKeyPairGenerator\.getInstance\s*\(\s*([A-Za-z_]\w*)\s*\)/g, primitive: 'signature' },
  ],
  csharp: [
    { id: 'cs-indirect-hash-create', re: /\bHashAlgorithm\.Create\s*\(\s*([A-Za-z_]\w*)\s*\)/g, primitive: 'hash' },
    { id: 'cs-indirect-aes-create', re: /\bAes\.Create\s*\(\s*([A-Za-z_]\w*)\s*\)/g, primitive: 'symmetric' },
  ],
};
