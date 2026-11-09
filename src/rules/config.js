/**
 * MOSCA — configuration rules
 * ===========================
 *
 * Source code is only half of the cryptographic estate. The other half lives
 * in text configuration: the TLS policy of a reverse proxy, the KEX list of
 * an SSH daemon, the default digest of an OpenSSL config.
 *
 * Each rule carries an `appliesTo` predicate over the file path so that a
 * `Ciphers` line in an nginx file is not confused with one in sshd_config.
 */

/** @typedef {{id:string, appliesTo:(p:string)=>boolean, re:RegExp, algo:string|Function, primitive:string, confidence?:string, note?:string}} ConfigRule */

import { tlsVersionId } from './algorithms.js';

const isNginx = (p) => /(^|[\\/])nginx[^\\/]*$|\.nginx$|nginx\.conf$/i.test(p) || /(^|[\\/])conf\.d[\\/]/i.test(p) && /\.conf$/i.test(p);
const isApache = (p) => /(^|[\\/])(httpd|apache2?)[^\\/]*$|\.htaccess$|sites-available|sites-enabled|apache2\.conf$|httpd\.conf$/i.test(p);
const isSshd = (p) => /sshd?_config$|sshd_config\.d[\\/]|ssh_config$/i.test(p);
const isOpenssl = (p) => /openssl\.cnf$|openssl\.conf$|\.cnf$/i.test(p);
const isJavaSecurity = (p) => /java\.security$/i.test(p);
const isK8s = (p) => /\.ya?ml$/i.test(p);

/** @type {ConfigRule[]} */
export const CONFIG_RULES = [
  // ------------------------------------------------------------------ nginx
  {
    id: 'nginx-ssl-protocols-legacy',
    appliesTo: isNginx,
    re: /ssl_protocols\s+([^;]*\b(?:TLSv1(?:\.1)?(?![\d.])|SSLv[23])\b[^;]*);/gi,
    algo: (m) => {
      const tokens = m[1].toLowerCase().split(/\s+/).filter(Boolean);
      if (tokens.includes('tlsv1.1') && !tokens.includes('tlsv1')) return 'tls-1.1';
      return 'tls-1.0';
    },
    primitive: 'protocol',
    confidence: 'high',
    note: 'Legacy TLS versions enabled in the server block.',
  },
  {
    id: 'nginx-rc4',
    appliesTo: isNginx,
    re: /ssl_ciphers\s+([^;]*\bRC4[^;]*);/gi,
    algo: 'rc4',
    primitive: 'symmetric',
    confidence: 'high',
  },
  {
    id: 'nginx-3des',
    appliesTo: isNginx,
    re: /ssl_ciphers\s+([^;]*\b(?:3DES|DES-CBC3)[^;]*);/gi,
    algo: '3des',
    primitive: 'symmetric',
    confidence: 'high',
  },
  {
    id: 'nginx-null',
    appliesTo: isNginx,
    re: /ssl_ciphers\s+([^;]*?(?<!!)\b(?:NULL|eNULL|aNULL)\b[^;]*);/gi,
    algo: 'none',
    primitive: 'symmetric',
    confidence: 'high',
  },
  {
    id: 'nginx-export',
    appliesTo: isNginx,
    re: /ssl_ciphers\s+([^;]*\bEXPORT[^;]*);/gi,
    algo: 'rc4',
    primitive: 'symmetric',
    confidence: 'high',
    note: 'EXPORT-grade ciphers are 40-bit and breakable in seconds.',
  },
  {
    id: 'nginx-static-rsa',
    appliesTo: isNginx,
    re: /ssl_ciphers\s+([^;]*\b(?:AES\d+-(?:SHA|CBC-SHA)\b)[^;]*);/gi,
    algo: 'rsa',
    primitive: 'key-agreement',
    confidence: 'medium',
    note: 'Static-RSA key exchange: no forward secrecy, and the session key is protected only by RSA.',
  },
  {
    id: 'nginx-ecdh-curve',
    appliesTo: isNginx,
    re: /ssl_ecdh_curve\s+([^;]+);/gi,
    algo: (m) => (/x25519/i.test(m[1]) ? 'x25519' : 'ecdh'),
    primitive: 'key-agreement',
    confidence: 'high',
    note: 'No hybrid post-quantum group configured.',
  },
  {
    id: 'nginx-no-hybrid',
    appliesTo: isNginx,
    re: /ssl_conf_command\s+Groups\s+([^;]+);/gi,
    algo: (m) => (/MLKEM|X25519MLKEM768|kyber/i.test(m[1]) ? 'x25519mlkem768' : 'ecdh'),
    primitive: 'key-agreement',
    confidence: 'high',
    note: 'OpenSSL group list; add X25519MLKEM768 for hybrid key exchange.',
  },

  // ----------------------------------------------------------------- apache
  {
    id: 'apache-sslprotocol-legacy',
    appliesTo: isApache,
    re: /SSLProtocol\s+([^\n]*\b(?:TLSv1(?:\.1)?(?![\d.])|SSLv[23]|all)\b[^\n]*)/gi,
    algo: 'tls-1.0',
    primitive: 'protocol',
    confidence: 'high',
  },
  {
    id: 'apache-sslcipher-weak',
    appliesTo: isApache,
    re: /SSLCipherSuite\s+([^\n]*\b(?:RC4|3DES|DES|NULL|EXPORT|MD5)\b[^\n]*)/gi,
    algo: (m) => (/RC4/i.test(m[1]) ? 'rc4' : /3DES|DES-CBC3/i.test(m[1]) ? '3des' : /NULL/i.test(m[1]) ? 'none' : 'md5'),
    primitive: 'symmetric',
    confidence: 'high',
  },
  {
    id: 'apache-sslhonor',
    appliesTo: isApache,
    re: /SSLHonorCipherOrder\s+off/gi,
    algo: 'tls-1.2',
    primitive: 'protocol',
    confidence: 'medium',
    note: 'Client chooses the cipher suite; a legacy client can downgrade the session.',
  },

  // ------------------------------------------------------------------- sshd
  {
    id: 'sshd-hostkey-rsa',
    appliesTo: isSshd,
    re: /^\s*HostKey\s+\S*ssh_host_(rsa|dsa|ecdsa)_key\S*/gim,
    algo: (m) => (m[1] === 'rsa' ? 'rsa' : m[1] === 'dsa' ? 'dsa' : 'ecdsa'),
    primitive: 'signature',
    confidence: 'high',
    note: 'Host key type. RSA and ECDSA host keys are quantum-vulnerable.',
  },
  {
    id: 'sshd-hostkeyalgorithms-legacy',
    appliesTo: isSshd,
    re: /^\s*HostKeyAlgorithms\s+([^\n#]+)/gim,
    algo: (m) => {
      const v = m[1];
      if (/ml-dsa|sntrup|mlkem/i.test(v)) return 'ml-dsa-65';
      if (/ssh-rsa[^-]|ssh-rsa$/i.test(v)) return 'ssh-rsa';
      if (/ecdsa-sha2/i.test(v)) return 'ecdsa-sha2-nistp256';
      if (/ssh-ed25519/i.test(v)) return 'ssh-ed25519';
      return 'rsa-sha2-256';
    },
    primitive: 'signature',
    confidence: 'high',
  },
  {
    id: 'sshd-kex-legacy',
    appliesTo: isSshd,
    re: /^\s*KexAlgorithms\s+([^\n#]+)/gim,
    algo: (m) => {
      const v = m[1].toLowerCase();
      if (/mlkem|sntrup/.test(v)) return 'sntrup761x25519-sha512';
      if (/diffie-hellman-group1-sha1|group14-sha1/.test(v)) return 'dh';
      return 'ecdh';
    },
    primitive: 'key-agreement',
    confidence: 'high',
    note: 'SSH key exchange list; hybrid sntrup761x25519 or mlkem768x25519 is the post-quantum option.',
  },
  {
    id: 'sshd-ciphers-weak',
    appliesTo: isSshd,
    re: /^\s*Ciphers\s+([^\n#]*\b(?:3des|des|arcfour|rc4|blowfish|cast128)\b[^\n#]*)/gim,
    algo: (m) => (/3des|des-cbc/i.test(m[1]) ? '3des' : /arcfour|rc4/i.test(m[1]) ? 'rc4' : 'blowfish'),
    primitive: 'symmetric',
    confidence: 'high',
  },
  {
    id: 'sshd-macs-weak',
    appliesTo: isSshd,
    re: /^\s*MACs\s+([^\n#]*\b(?:hmac-md5|hmac-sha1|umac-64)\b[^\n#]*)/gim,
    algo: (m) => (/md5/i.test(m[1]) ? 'hmac-md5' : 'hmac-sha1'),
    primitive: 'mac',
    confidence: 'high',
  },

  // ---------------------------------------------------------------- openssl
  {
    id: 'openssl-default-md',
    appliesTo: isOpenssl,
    re: /default_md\s*=\s*(md5|sha1|sha224|sha256|sha512)/gi,
    algo: (m) => m[1].toLowerCase(),
    primitive: 'hash',
    confidence: 'high',
  },
  {
    id: 'openssl-min-protocol',
    appliesTo: isOpenssl,
    re: /MinProtocol\s*=\s*(TLSv1\.1|TLSv1(?![\d.]))/gi,
    algo: (m) => tlsVersionId(m[1]),
    primitive: 'protocol',
    confidence: 'high',
    note: 'A TLS 1.0/1.1 floor. Raise it to TLS 1.2 and let the server prefer 1.3.',
  },
  {
    id: 'openssl-cipherstring',
    appliesTo: isOpenssl,
    re: /CipherString\s*=\s*([^\n]*\b(?:RC4|3DES|DES|NULL|EXPORT|MD5)\b[^\n]*)/gi,
    algo: (m) => (/RC4/i.test(m[1]) ? 'rc4' : /3DES/i.test(m[1]) ? '3des' : /NULL/i.test(m[1]) ? 'none' : 'md5'),
    primitive: 'symmetric',
    confidence: 'high',
  },
  {
    id: 'openssl-groups',
    appliesTo: isOpenssl,
    re: /Groups\s*=\s*([^\n]+)/gi,
    algo: (m) => (/MLKEM|kyber/i.test(m[1]) ? 'x25519mlkem768' : 'ecdh'),
    primitive: 'key-agreement',
    confidence: 'medium',
    note: 'Group list. Add X25519MLKEM768 to negotiate hybrid key exchange.',
  },

  // ----------------------------------------------------------- java.security
  {
    id: 'java-security-disabled',
    appliesTo: isJavaSecurity,
    re: /jdk\.tls\.disabledAlgorithms\s*=\s*([^\n]+)/gi,
    algo: 'tls-1.2',
    primitive: 'protocol',
    confidence: 'low',
    note: 'Disabled-algorithm policy. Verify TLSv1, TLSv1.1, MD5, SHA1 and 3DES are listed.',
  },

  // --------------------------------------------------------------- kubernetes
  {
    id: 'k8s-ingress-tls-annotation',
    appliesTo: isK8s,
    re: /nginx\.ingress\.kubernetes\.io\/ssl-protocols\s*:\s*["']?([^"'\n]+)/gi,
    algo: (m) => (/TLSv1(?:\.1)?(?![\d.])/.test(m[1]) ? 'tls-1.0' : 'tls-1.2'),
    primitive: 'protocol',
    confidence: 'medium',
  },
  {
    id: 'k8s-ingress-ciphers',
    appliesTo: isK8s,
    re: /nginx\.ingress\.kubernetes\.io\/ssl-ciphers\s*:\s*["']?([^"'\n]*\b(?:RC4|3DES|DES|NULL|EXPORT)\b[^"'\n]*)/gi,
    algo: (m) => (/RC4/i.test(m[1]) ? 'rc4' : /3DES/i.test(m[1]) ? '3des' : 'none'),
    primitive: 'symmetric',
    confidence: 'high',
  },
];

/** Config file extensions we are willing to read as text. */
export const CONFIG_EXTENSIONS = ['.conf', '.cnf', '.cfg', '.ini', '.yaml', '.yml', '.config', '.properties'];

/** Files with no extension that are still configuration. */
export const CONFIG_FILENAMES = [
  'nginx.conf',
  'httpd.conf',
  'apache2.conf',
  'sshd_config',
  'ssh_config',
  'openssl.cnf',
  'java.security',
  'Dockerfile',
  '.htaccess',
];

/**
 * Decide whether a file should be treated as a config file worth scanning.
 * @param {string} path
 */
export function isConfigFile(path) {
  const base = path.split(/[\\/]/).pop() || '';
  if (CONFIG_FILENAMES.includes(base)) return true;
  const lower = base.toLowerCase();
  if (CONFIG_EXTENSIONS.some((e) => lower.endsWith(e))) {
    // Do not treat every YAML in a repo as a TLS policy, but the rules are
    // anchored on specific keys so false positives stay rare.
    return true;
  }
  return false;
}
