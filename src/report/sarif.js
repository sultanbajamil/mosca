/**
 * MOSCA — SARIF 2.1.0 output
 * ==========================
 * Lets the scanner gate CI pipelines and surface findings in GitHub code
 * scanning, without a bespoke integration.
 *
 * https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

import path from 'node:path';
import { lookup } from '../rules/algorithms.js';

const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };

/** Convert a Windows path to a SARIF-friendly URI. */
function toUri(file) {
  return String(file).replace(/\\/g, '/');
}

/**
 * @param {{analysis:object, root?:string, toolVersion?:string}} input
 */
export function buildSarif({ analysis, root = process.cwd(), toolVersion = '1.0.0' }) {
  const rules = new Map();
  const results = [];

  // Map each finding fingerprint to the compliance controls it violates, so a
  // code-scanning alert can carry its audit context.
  const complianceByFingerprint = new Map();
  for (const standard of analysis.compliance || []) {
    for (const control of standard.controls || []) {
      for (const violation of control.violations || []) {
        if (!violation.fingerprint) continue;
        if (!complianceByFingerprint.has(violation.fingerprint)) complianceByFingerprint.set(violation.fingerprint, []);
        complianceByFingerprint.get(violation.fingerprint).push({
          standard: standard.id,
          control: control.id,
          severity: control.severity,
        });
      }
    }
  }

  for (const item of analysis.items) {
    if (item.positive) continue;
    if (item.kind === 'endpoint') continue; // endpoints have no file location

    const algo = lookup(item.algorithm);
    const ruleId = `mosca/${item.id}`;
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: item.id.replace(/[^a-zA-Z0-9]/g, ''),
        shortDescription: { text: `${algo.label} usage` },
        fullDescription: {
          text:
            item.note ||
            `${algo.label} is classified ${algo.quantum} against a cryptographically relevant quantum computer.`,
        },
        help: {
          text: [
            `Quantum status: ${item.quantum}`,
            `Classical status: ${item.classical}`,
            item.replacement ? `Recommended replacement: ${lookup(item.replacement).label}` : '',
            item.standard ? `Standard: ${item.standard}` : '',
          ]
            .filter(Boolean)
            .join('\n'),
          markdown: [
            `**Quantum status:** ${item.quantum}`,
            `**Classical status:** ${item.classical}`,
            item.replacement ? `**Recommended replacement:** ${lookup(item.replacement).label}` : '',
            item.standard ? `**Standard:** ${item.standard}` : '',
          ]
            .filter(Boolean)
            .join('\n\n'),
        },
        defaultConfiguration: { level: LEVEL[item.severity] || 'note' },
        properties: {
          tags: ['security', 'cryptography', 'post-quantum'],
          precision: item.confidence === 'high' ? 'very-high' : item.confidence === 'low' ? 'medium' : 'high',
          'security-severity': String(severityScore(item.severity)),
        },
      });
    }

    const file = item.location?.file;
    if (!file) continue;
    const uri = toUri(path.isAbsolute(file) ? path.relative(root, file) : file);
    results.push({
      ruleId,
      level: LEVEL[item.severity] || 'note',
      message: {
        text: `${item.title}. ${item.note || ''}`.trim(),
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri, uriBaseId: '%SRCROOT%' },
            region: {
              startLine: item.location.line || 1,
              startColumn: item.location.column || 1,
            },
          },
        },
      ],
      partialFingerprints: {
        // Line-independent: moving code must not make SARIF treat the same
        // defect as a brand-new alert.
        moscaFingerprint: item.fingerprint || `${item.id}:${uri}`,
      },
      baselineState: item.baselineStatus === 'new' ? 'new' : 'unchanged',
      properties: {
        algorithm: item.algorithm,
        quantum: item.quantum,
        classical: item.classical,
        replacement: item.replacement,
        moscaExposed: item.mosca?.exposed ?? null,
        moscaInequality: item.mosca?.inequality ?? null,
        priority: item.priority,
        baselineStatus: item.baselineStatus || 'not-compared',
        captureTime: item.captureTime || null,
        capturedProtocol: item.capturedProtocol || null,
        compliance: complianceByFingerprint.get(item.fingerprint) || [],
      },
    });
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'MOSCA',
            fullName: 'MOSCA Post-Quantum Cryptography Exposure Scanner',
            version: toolVersion,
            informationUri: 'https://github.com/sultanbajamil/mosca',
            rules: [...rules.values()],
          },
        },
        originalUriBaseIds: {
          '%SRCROOT%': { uri: `file:///${toUri(root).replace(/^\/?/, '')}/` },
        },
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: analysis.summary.generatedAt,
            workingDirectory: { uri: `file:///${toUri(root).replace(/^\/?/, '')}/` },
          },
        ],
        properties: {
          quantumReadinessIndex: analysis.summary.quantumReadinessIndex,
          crqcYear: analysis.summary.crqcYear,
          compliance: (analysis.compliance || []).map((standard) => ({
            standard: standard.id,
            status: standard.status,
            score: standard.score,
            violations: standard.violationCount,
          })),
        },
        results,
      },
    ],
  };
}

function severityScore(severity) {
  switch (severity) {
    case 'critical': return 9.5;
    case 'high': return 8.0;
    case 'medium': return 5.5;
    case 'low': return 3.0;
    default: return 0.0;
  }
}
