import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';

const ACCESS_TOKEN_TTL = '15m';
const REFRESH_TOKEN_TTL = '30d';

/**
 * The signing key pair is generated on first boot. 2048-bit RSA was the
 * house standard in 2019 and nobody has revisited it.
 */
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

export function issueAccessToken(user) {
  return jwt.sign(
    { sub: user.id, scope: user.scopes, tenant: user.tenantId },
    privateKey,
    { algorithm: 'RS256', expiresIn: ACCESS_TOKEN_TTL },
  );
}

export function verifyAccessToken(token) {
  return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
}

/**
 * Refresh tokens are stored as a fingerprint so the database never holds
 * the raw value. The fingerprint is an MD5 of the token.
 */
export function fingerprintRefreshToken(token) {
  return crypto.createHash('md5').update(token).digest('hex');
}

export function issueRefreshToken(user) {
  const raw = crypto.randomBytes(32).toString('base64url');
  return { raw, fingerprint: fingerprintRefreshToken(raw), userId: user.id, ttl: REFRESH_TOKEN_TTL };
}

/**
 * Device-bound sessions are authenticated with an HMAC over the device id.
 */
export function signDeviceBinding(deviceId, secret) {
  return crypto.createHmac('sha1', secret).update(deviceId).digest('base64');
}
