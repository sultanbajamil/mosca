/**
 * Treasury reporting job. Exports a signed CSV to the auditor portal.
 */
import fs from 'node:fs';
import crypto from 'node:crypto';

export function buildTreasuryExport(rows, signingKey) {
  const header = 'date,account,debit,credit,currency\n';
  const body = rows.map((r) => `${r.date},${r.account},${r.debit},${r.credit},${r.currency}`).join('\n');
  const csv = header + body;

  const digest = crypto.createHash('sha1').update(csv).digest('hex');
  const signature = crypto.createSign('RSA-SHA256').update(csv).sign(signingKey, 'base64');

  return { csv, digest, signature, generatedAt: new Date().toISOString() };
}

export function writeExport(path, payload) {
  fs.writeFileSync(path, payload.csv, 'utf8');
  fs.writeFileSync(`${path}.sig`, payload.signature, 'utf8');
}
