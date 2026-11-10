/**
 * Mermaid output is a reporting surface, so it is tested for the properties a
 * reader depends on: deterministic bytes, bounded size, valid class
 * declarations, and no way for a finding to inject Mermaid syntax.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildMermaid,
  buildMermaidRiskGraph,
  buildMermaidChainTree,
  buildMermaidDependencyGraph,
  buildMermaidMarkdown,
  MAX_ALGORITHMS,
  MAX_FILES,
} from '../src/report/mermaid.js';
import { analyse } from '../src/analysis/risk.js';
import { DEFAULT_CONFIG } from '../src/config.js';

const config = { ...DEFAULT_CONFIG, crqcYear: 2033, scenario: 'moderate' };
const NOW = new Date('2026-01-01T00:00:00Z');

function finding(index, overrides = {}) {
  return {
    id: `rule-${index}`,
    kind: 'source',
    title: `finding ${index}`,
    algorithm: 'md5',
    primitive: 'hash',
    location: { file: `src/file${index}.js`, line: index + 1, column: 1 },
    confidence: 'high',
    ...overrides,
  };
}

const analysisWith = (findings) => analyse({ findings, config, now: NOW });

test('the risk graph is a bounded, deterministic flowchart', () => {
  const findings = [];
  for (let i = 0; i < 60; i++) {
    findings.push(finding(i, { algorithm: i % 2 ? 'md5' : 'rc4', primitive: i % 2 ? 'hash' : 'symmetric' }));
  }
  const analysis = analysisWith(findings);
  const graph = buildMermaidRiskGraph(analysis);

  assert.match(graph, /^flowchart LR/);
  assert.match(graph, /classDef broken/);
  assert.match(graph, /subgraph algorithms/);
  assert.match(graph, /-->|F_/);

  // Bounded: no more than the declared maxima.
  const fileNodes = graph.match(/^ {4}F_/gm) || [];
  assert.ok(fileNodes.length <= MAX_FILES, `${fileNodes.length} file nodes`);
  assert.ok(fileNodes.length > 0);

  // Deterministic.
  assert.equal(graph, buildMermaidRiskGraph(analysis));
  assert.equal(graph, buildMermaid(analysis));
  assert.equal((graph.match(/classDef/g) || []).length, 6);
});

test('a clean scan renders an explicit clean node', () => {
  const graph = buildMermaidRiskGraph(analysisWith([finding(1, { algorithm: 'sha256', primitive: 'hash' })]));
  assert.match(graph, /No actionable cryptographic findings/);
  assert.match(graph, /class clean safe/);
  assert.doesNotMatch(graph, /subgraph algorithms/);
});

test('labels cannot inject diagram syntax', () => {
  const analysis = analysisWith([
    finding(1, {
      algorithm: 'md5',
      location: { file: 'src/<script>"x"&y].js', line: 1, column: 1 },
    }),
  ]);
  const graph = buildMermaidRiskGraph(analysis);
  assert.doesNotMatch(graph, /<script>/);
  assert.doesNotMatch(graph, /\].js/);
  assert.match(graph, /src\/ script x y \.js/);
});

test('the chain tree shows every certificate and the PQC projection', () => {
  const endpoints = [
    {
      host: 'example.com',
      port: 443,
      chainAnalysis: {
        entries: [
          { role: 'leaf', subject: 'example.com', keyLabel: 'ECDSA P-256', keyBits: 256, quantum: 'broken' },
          { role: 'intermediate', subject: 'Example CA', keyLabel: 'RSA', keyBits: 2048, quantum: 'broken' },
          { role: 'root', subject: 'Example Root', keyLabel: 'RSA', keyBits: 4096, quantum: 'broken' },
        ],
      },
      pqcHandshake: { worst: { totalBytes: 16000, exceeds: true } },
    },
  ];
  const tree = buildMermaidChainTree(endpoints);
  assert.match(tree, /subgraph EP_example_com_443/);
  assert.match(tree, /leaf/);
  assert.match(tree, /intermediate/);
  assert.match(tree, /root/);
  assert.match(tree, /16 000|16000/);
  assert.match(tree, /> 14 KB/);
  // Three certificates and one projection node.
  assert.equal((tree.match(/^ {4}C_[^ ]*\[/gm) || []).length, 3);
  assert.equal((tree.match(/^ {4}P_[^ ]*\[/gm) || []).length, 1);

  assert.match(buildMermaidChainTree([]), /No certificate chains captured/);
});

test('the dependency graph reflects package status', () => {
  const packages = [
    { name: 'node-forge', version: '1.3.0', status: 'quantum-vulnerable' },
    { name: '@noble/post-quantum', version: '0.2.0', status: 'quantum-safe' },
    { name: 'crypto-js', version: '3.1.9', status: 'classically-broken' },
  ];
  const graph = buildMermaidDependencyGraph(packages);
  assert.match(graph, /node_forge/);
  assert.match(graph, /class D_node_forge_1_3_0 broken/);
  assert.match(graph, /class D_noble_post_quantum_0_2_0 safe/);
  assert.match(graph, /crypto_js/);
  assert.match(graph, /project --> D_node_forge_1_3_0/);
  assert.match(buildMermaidDependencyGraph([]), /No cryptographic packages matched/);
});

test('Markdown aggregates fenced diagrams and includes dependencies when present', () => {
  const analysis = analysisWith([finding(1)]);
  analysis.endpoints = [];
  analysis.dependencies = { packages: [{ name: 'node-forge', version: '1.3.0', status: 'quantum-vulnerable' }] };
  const markdown = buildMermaidMarkdown(analysis);

  assert.match(markdown, /^## Cryptographic risk graph/m);
  assert.match(markdown, /^## Certificate chains/m);
  assert.match(markdown, /^## Cryptographic supply chain/m);
  assert.equal((markdown.match(/```mermaid/g) || []).length, 3);
  assert.equal((markdown.match(/```/g) || []).length, 6);
  assert.equal(markdown, buildMermaidMarkdown(analysis));
});
