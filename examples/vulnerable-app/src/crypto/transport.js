import tls from 'node:tls';
import crypto from 'node:crypto';

/**
 * Outbound connections to partner banks. Each partner gets a pinned
 * certificate, and the key exchange is classical ECDHE.
 */
export function partnerAgent(partner) {
  return new tls.TLSSocket(null, {
    host: partner.host,
    port: partner.port,
    servername: partner.host,
    rejectUnauthorized: true,
    minVersion: 'TLSv1.2',
  });
}

/**
 * Per-partner request signing. Partners were issued RSA keys in 2018 and
 * rotation never happened.
 */
export function signPartnerRequest(body, privateKeyPem) {
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(body);
  signer.end();
  return signer.sign(privateKeyPem, 'base64');
}

export function generatePartnerKeypair() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

/**
 * Session tickets are encrypted with a key derived from the service secret.
 */
export function deriveTicketKey(secret, salt) {
  return crypto.pbkdf2Sync(secret, salt, 100_000, 32, 'sha256');
}
