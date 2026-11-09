import crypto from 'node:crypto';

/**
 * Invoice archives must be retained for ten years for tax purposes. They
 * are encrypted with a key that is rotated every five years, which means
 * ciphertext written today stays readable with the 2021 key until 2031.
 */
export function archiveInvoice(invoice, keyHex) {
  const key = Buffer.from(keyHex, 'hex');
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const body = Buffer.concat([cipher.update(JSON.stringify(invoice), 'utf8'), cipher.final()]);
  return { iv: iv.toString('hex'), body: body.toString('base64') };
}

export function invoiceChecksum(invoice) {
  return crypto.createHash('sha256').update(JSON.stringify(invoice)).digest('hex');
}

/**
 * Legacy export for the auditor portal. The portal only accepts the old
 * signature format.
 */
export function signAuditExport(payload, privateKeyPem) {
  const signer = crypto.createSign('RSA-SHA1');
  signer.update(payload);
  signer.end();
  return signer.sign(privateKeyPem, 'base64');
}
