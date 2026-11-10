/**
 * MOSCA — Mermaid diagrams
 * ========================
 *
 * A findings table is precise but hard to circulate. Mermaid renders in
 * GitHub, GitLab, Notion and most Markdown viewers, so a scan can publish a
 * diagram that a change-review meeting can read without installing anything.
 *
 * Four views are produced:
 *
 *   risk          algorithms and the files/endpoints that use them
 *   chains        the certificate hierarchy of each inspected TLS endpoint
 *   dependencies  lockfile packages that fix an algorithm on your behalf
 *   markdown      all of the above as fenced ```mermaid blocks
 *
 * The output is deterministic and bounded: diagrams are for humans, and a
 * node for every one of four thousand findings is not.
 */

import { lookup } from '../rules/algorithms.js';

const MAX_ALGORITHMS = 24;
const MAX_FILES = 16;

/** Escape a Mermaid label. */
function label(value) {
  return String(value ?? '')
    .replace(/["<>&{}[\]|`]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 90);
}

/** Stable Mermaid-safe node id. */
function nodeId(prefix, value) {
  const safe = String(value ?? '')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 48);
  return `${prefix}_${safe || 'node'}`;
}

const QUANTUM_CLASS = {
  broken: 'broken',
  weakened: 'weakened',
  safe: 'safe',
  unknown: 'unknown',
};

const CLASS_DEFS = [
  'classDef broken fill:#3b0d12,stroke:#f87171,color:#fecaca',
  'classDef weakened fill:#3b2b0d,stroke:#fbbf24,color:#fde68a',
  'classDef safe fill:#0d2b22,stroke:#34d399,color:#a7f3d0',
  'classDef unknown fill:#1a2233,stroke:#8b9ab5,color:#dbe4f5',
  'classDef file fill:#0b1424,stroke:#3f5b85,color:#dbe4f5',
  'classDef endpoint fill:#0d2230,stroke:#22d3ee,color:#a5f3fc',
];

/**
 * Risk graph: algorithm nodes connected to the files that use them.
 * @param {object} analysis
 */
export function buildMermaidRiskGraph(analysis) {
  const items = (analysis.items || []).filter((i) => !i.positive);
  const algorithms = new Map();
  const files = new Map();

  for (const item of items) {
    const key = item.algorithm;
    const algo = algorithms.get(key) || {
      id: key,
      label: item.algorithmLabel || lookup(key).label,
      quantum: item.quantum || lookup(key).quantum,
      primitive: item.primitive,
      count: 0,
      locations: new Set(),
    };
    algo.count += 1;
    const where = item.location?.file || (item.location?.host ? `${item.location.host}:${item.location.port ?? ''}` : null);
    if (where) algo.locations.add(where);
    algorithms.set(key, algo);
  }

  const topAlgorithms = [...algorithms.values()].sort((a, b) => b.count - a.count).slice(0, MAX_ALGORITHMS);
  const algorithmIds = new Set(topAlgorithms.map((a) => a.id));

  for (const item of items) {
    if (!algorithmIds.has(item.algorithm)) continue;
    const where = item.location?.file || (item.location?.host ? `${item.location.host}:${item.location.port ?? ''}` : null);
    if (!where) continue;
    const isEndpoint = !item.location?.file;
    const entry = files.get(where) || { where, endpoint: isEndpoint, count: 0 };
    entry.count += 1;
    files.set(where, entry);
  }

  const topFiles = [...files.values()].sort((a, b) => b.count - a.count).slice(0, MAX_FILES);
  const fileIds = new Set(topFiles.map((f) => f.where));

  const lines = ['flowchart LR', ...CLASS_DEFS.map((l) => `  ${l}`)];
  if (!items.length) {
    lines.push('  clean["No actionable cryptographic findings"]');
    lines.push('  class clean safe');
    return lines.join('\n');
  }

  lines.push('  subgraph estate["Estate"]');
  for (const file of topFiles) {
    const id = nodeId('F', file.where);
    lines.push(`    ${id}["${label(file.where)}<br/>${file.count} finding${file.count === 1 ? '' : 's'}"]`);
    lines.push(`    class ${id} ${file.endpoint ? 'endpoint' : 'file'}`);
  }
  lines.push('  end');

  lines.push('  subgraph algorithms["Algorithms"]');
  for (const algo of topAlgorithms) {
    const id = nodeId('A', algo.id);
    lines.push(`    ${id}["${label(algo.label)}<br/>${label(algo.primitive)} · ${algo.count} site${algo.count === 1 ? '' : 's'}"]`);
    lines.push(`    class ${id} ${QUANTUM_CLASS[algo.quantum] || 'unknown'}`);
  }
  lines.push('  end');

  const edges = new Set();
  for (const item of items) {
    const where = item.location?.file || (item.location?.host ? `${item.location.host}:${item.location.port ?? ''}` : null);
    if (!where || !fileIds.has(where) || !algorithmIds.has(item.algorithm)) continue;
    const edge = `  ${nodeId('F', where)} --> ${nodeId('A', item.algorithm)}`;
    if (!edges.has(edge)) {
      edges.add(edge);
      lines.push(edge);
    }
  }

  return lines.join('\n');
}

/**
 * Certificate chain tree for live TLS endpoints.
 * @param {object[]} endpoints
 */
export function buildMermaidChainTree(endpoints = []) {
  const withChains = endpoints.filter((ep) => ep.chainAnalysis?.entries?.length);
  if (!withChains.length) {
    return 'flowchart LR\n  none["No certificate chains captured"]\n  class none unknown';
  }

  const lines = ['flowchart LR', ...CLASS_DEFS.map((l) => `  ${l}`)];
  for (const ep of withChains) {
    const host = `${ep.host}:${ep.port}`;
    lines.push(`  subgraph ${nodeId('EP', host)}["${label(host)}"]`);
    const entries = ep.chainAnalysis.entries;
    entries.forEach((entry, index) => {
      const id = nodeId('C', `${host}_${index}`);
      const bits = entry.keyBits ? ` ${entry.keyBits}b` : '';
      lines.push(
        `    ${id}["${label(entry.role)}<br/>${label(entry.subject)}<br/>${label(entry.keyLabel)}${bits}"]`,
      );
      lines.push(`    class ${id} ${QUANTUM_CLASS[entry.quantum] || 'unknown'}`);
    });
    for (let i = 0; i < entries.length - 1; i++) {
      lines.push(`    ${nodeId('C', `${host}_${i}`)} --> ${nodeId('C', `${host}_${i + 1}`)}`);
    }
    const pqc = ep.pqcHandshake;
    if (pqc?.worst) {
      lines.push(
        `    ${nodeId('P', host)}["ML-DSA-65 projection<br/>${pqc.worst.totalBytes} bytes ${pqc.worst.exceeds ? '> 14 KB' : '<= 14 KB'}"]`,
      );
      lines.push(`    class ${nodeId('P', host)} ${pqc.worst.exceeds ? 'weakened' : 'safe'}`);
      lines.push(`    ${nodeId('C', `${host}_${0}`)} -.-> ${nodeId('P', host)}`);
    }
    lines.push('  end');
  }
  return lines.join('\n');
}

/**
 * Cryptographic dependency graph from lockfile packages.
 * @param {object[]} packages packages attached by the dependency scanner
 */
export function buildMermaidDependencyGraph(packages = []) {
  const byName = new Map();
  for (const pkg of packages) {
    const key = `${pkg.name}@${pkg.version || 'unknown'}`;
    if (!byName.has(key)) byName.set(key, pkg);
  }
  if (!byName.size) {
    return 'flowchart LR\n  none["No cryptographic packages matched"]\n  class none unknown';
  }

  const lines = ['flowchart LR', ...CLASS_DEFS.map((l) => `  ${l}`)];
  lines.push('  project["Project"]');
  lines.push('  class project file');
  for (const [key, pkg] of [...byName.entries()].slice(0, MAX_ALGORITHMS)) {
    const id = nodeId('D', key);
    const status = pkg.status || 'quantum-vulnerable';
    const cls = status === 'quantum-safe' ? 'safe' : status === 'classically-broken' ? 'broken' : status === 'deprecated' ? 'weakened' : 'broken';
    lines.push(`  ${id}["${label(pkg.name)}<br/>${label(pkg.version || 'unknown')} · ${label(status)}"]`);
    lines.push(`  class ${id} ${cls}`);
    lines.push(`  project --> ${id}`);
  }
  return lines.join('\n');
}

/**
 * All views as fenced Markdown, ready to paste into a PR or a wiki page.
 * @param {object} analysis
 */
export function buildMermaidMarkdown(analysis) {
  const blocks = [
    ['Cryptographic risk graph', buildMermaidRiskGraph(analysis)],
    ['Certificate chains', buildMermaidChainTree(analysis.endpoints || [])],
  ];
  const packages = analysis.dependencies?.packages || [];
  if (packages.length) blocks.push(['Cryptographic supply chain', buildMermaidDependencyGraph(packages)]);

  return blocks
    .map(([title, diagram]) => `## ${title}\n\n\`\`\`mermaid\n${diagram}\n\`\`\`\n`)
    .join('\n');
}

/** Primary `.mmd` document written by `--format mermaid`. */
export function buildMermaid(analysis) {
  return buildMermaidRiskGraph(analysis);
}

export { MAX_ALGORITHMS, MAX_FILES };
