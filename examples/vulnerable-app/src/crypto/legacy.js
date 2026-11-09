import crypto from 'node:crypto';

/**
 * Bridge to the pre-2019 settlement format. Kept for the monthly
 * reconciliation job, which still reads archives produced by the old
 * mainframe export.
 */
export function legacyDigest(buffer) {
  return crypto.createHash('md5').update(buffer).digest('hex');
}

export function legacyHmac(payload, key) {
  return crypto.createHmac('md5', key).update(payload).digest('hex');
}

export function legacyEncrypt(plaintext, key, iv) {
  const cipher = crypto.createCipheriv('des-ede3-cbc', key, iv);
  return Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
}

/**
 * The reconciliation job still opens a TLS 1.1 socket to the mainframe
 * gateway. It is on the list to replace.
 */
export const mainframeTlsOptions = {
  host: 'mainframe.internal',
  port: 8443,
  minVersion: 'TLSv1.1',
  ciphers: 'DES-CBC3-SHA:RC4-SHA',
};
