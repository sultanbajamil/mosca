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
const isTerraform = (p) => /\.tf$/i.test(p);
const isTlsManifest = (p) => /\.ya?ml$/i.test(p) && /(cert|issuer|tls|ingress|gateway|istio|mesh)/i.test(p);
const isIstio = (p) => /\.ya?ml$/i.test(p) && /istio|peer.?auth|destination.?rule|gateway|virtual.?service/i.test(p);
const isHAProxy = (p) => /(^|[\\/])haproxy[^\\/]*\.cfg$|(^|[\\/])haproxy\.conf$/i.test(p);
const isEnvoy = (p) => /(^|[\\/])envoy[^\\/]*\.(?:ya?ml|conf|json)$/i.test(p);
const isCaddy = (p) => /(^|[\\/])Caddyfile(?:\.[^\\/]*)?$/i.test(p);
const isTraefik = (p) => /(^|[\\/])traefik[^\\/]*\.(?:ya?ml|toml)$/i.test(p);
const isWrangler = (p) => /(^|[\\/])(?:wrangler|cloudflare)[^\\/]*\.(?:toml|jsonc?|json)$/i.test(p);
const isDockerfile = (p) => /(^|[\\/])Dockerfile(?:\.[^\\/]*)?$|\.dockerfile$/i.test(p);

/** Parse an RSA size out of a matched token such as RSA_2048. */
const rsaBits = (m) => {
  const bits = Number((m[1] || '').match(/2048|3072|4096|1024/)?.[0]);
  return Number.isFinite(bits) ? bits : 2048;
};

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

  // ---------------------------------------------------------------- terraform
  {
    id: 'tf-aws-kms-rsa',
    appliesTo: isTerraform,
    re: /key_spec\s*=\s*"(RSA_(?:1024|2048|3072|4096))"/gi,
    algo: 'rsa',
    bits: rsaBits,
    primitive: 'signature',
    confidence: 'high',
    note: 'AWS KMS asymmetric key. RSA falls to Shor regardless of size; plan an ML-DSA or ML-KEM migration.',
  },
  {
    id: 'tf-aws-kms-ecc',
    appliesTo: isTerraform,
    re: /key_spec\s*=\s*"(ECC_(?:NIST_P256|NIST_P384|NIST_P521|SECG_P256K1))"/gi,
    algo: 'ecdsa',
    primitive: 'signature',
    confidence: 'high',
    note: 'AWS KMS elliptic-curve key. ECDSA is broken by Shor; ML-DSA-65 is the FIPS 204 replacement.',
  },
  {
    id: 'tf-aws-acm-key-algorithm',
    appliesTo: isTerraform,
    re: /key_algorithm\s*=\s*"(RSA_1024|RSA_2048|EC_prime256v1|EC_secp384r1)"/gi,
    algo: (m) => (/^RSA/.test(m[1]) ? 'rsa' : 'ecdsa'),
    bits: (m) => (/^RSA/.test(m[1]) ? rsaBits(m) : null),
    primitive: 'signature',
    confidence: 'high',
  },
  {
    id: 'tf-alb-legacy-ssl-policy',
    appliesTo: isTerraform,
    re: /ssl_policy\s*=\s*"(ELBSecurityPolicy-(?:2014-10|2015-05|2016-08|TLS-1-0[^"]*|TLS-1-1[^"]*))"/gi,
    algo: (m) => (/TLS-1-1|2016-08/i.test(m[1]) ? 'tls-1.1' : 'tls-1.0'),
    primitive: 'protocol',
    confidence: 'high',
    note: 'Legacy AWS load-balancer security policy. Use ELBSecurityPolicy-TLS13-1-3 or a current PQ-capable policy.',
  },
  {
    id: 'tf-cloudfront-min-tls',
    appliesTo: isTerraform,
    re: /minimum_protocol_version\s*=\s*"(TLSv1(?:\.1)?)"/gi,
    algo: (m) => tlsVersionId(m[1]),
    primitive: 'protocol',
    confidence: 'high',
  },
  {
    id: 'tf-google-kms-rsa',
    appliesTo: isTerraform,
    re: /algorithm\s*=\s*"(RSA_(?:SIGN|DECRYPT)_PKCS1_2048[^"]*)"/gi,
    algo: 'rsa-2048',
    primitive: 'signature',
    confidence: 'high',
    note: 'Google Cloud KMS RSA-2048 key. Quantum-vulnerable and below the modern CNSA 2.0 recommendation.',
  },
  {
    id: 'tf-google-kms-ec',
    appliesTo: isTerraform,
    re: /algorithm\s*=\s*"(EC_SIGN_(?:P256|P384|SECP256K1)_SHA256)"/gi,
    algo: 'ecdsa',
    primitive: 'signature',
    confidence: 'high',
  },
  {
    id: 'tf-azure-key-size',
    appliesTo: isTerraform,
    re: /key_size\s*=\s*(1024|2048|3072)\b/gi,
    algo: 'rsa',
    bits: (m) => Number(m[1]),
    primitive: 'signature',
    confidence: 'medium',
    note: 'Azure Key Vault key size. RSA is quantum-vulnerable; CNSA 2.0 requires ML-DSA-87 or ML-KEM-1024.',
  },
  {
    id: 'tf-azure-key-type-rsa',
    appliesTo: isTerraform,
    re: /key_type\s*=\s*"RSA"/gi,
    algo: 'rsa',
    primitive: 'signature',
    confidence: 'medium',
  },
  {
    id: 'tf-cloudflare-min-tls',
    appliesTo: isTerraform,
    re: /min_tls_version\s*=\s*"(1\.[01])"/gi,
    algo: (m) => (m[1] === '1.1' ? 'tls-1.1' : 'tls-1.0'),
    primitive: 'protocol',
    confidence: 'high',
  },

  // -------------------------------------------------------- kubernetes / istio
  {
    id: 'k8s-cert-manager-rsa',
    appliesTo: isTlsManifest,
    re: /privateKey:\s*\n(?:[^\n]*\n){0,6}\s*algorithm:\s*RSA\b/gi,
    algo: 'rsa',
    primitive: 'signature',
    confidence: 'high',
    note: 'cert-manager RSA private key. Move to ML-DSA-65 once the issuer and clients support it.',
  },
  {
    id: 'k8s-cert-manager-key-size',
    appliesTo: isTlsManifest,
    re: /privateKey:\s*\n(?:[^\n]*\n){0,6}\s*size:\s*(1024|2048|3072)\b/gi,
    algo: 'rsa',
    bits: (m) => Number(m[1]),
    primitive: 'signature',
    confidence: 'high',
  },
  {
    id: 'k8s-cert-manager-ecdsa',
    appliesTo: isTlsManifest,
    re: /privateKey:\s*\n(?:[^\n]*\n){0,6}\s*algorithm:\s*ECDSA\b/gi,
    algo: 'ecdsa',
    primitive: 'signature',
    confidence: 'high',
  },
  {
    id: 'istio-min-tls-1-0',
    appliesTo: isIstio,
    re: /minProtocolVersion:\s*TLSV1_0\b/gi,
    algo: 'tls-1.0',
    primitive: 'protocol',
    confidence: 'high',
    note: 'Istio PeerAuthentication / Gateway still permits TLS 1.0.',
  },
  {
    id: 'istio-min-tls-1-1',
    appliesTo: isIstio,
    re: /minProtocolVersion:\s*TLSV1_1\b/gi,
    algo: 'tls-1.1',
    primitive: 'protocol',
    confidence: 'high',
  },
  {
    id: 'istio-weak-cipher-suites',
    appliesTo: isIstio,
    re: /cipherSuites:\s*\[[^\]]*\b(?:RC4|3DES|DES|NULL|EXPORT)[^\]]*\]/gi,
    algo: (m) => (/RC4/i.test(m[0]) ? 'rc4' : /3DES/i.test(m[0]) ? '3des' : 'none'),
    primitive: 'symmetric',
    confidence: 'high',
  },
  {
    id: 'istio-classical-ecdh-curves',
    appliesTo: isIstio,
    re: /ecdhCurves:\s*\[(?![^\]]*(?:MLKEM|X25519MLKEM768|Kyber))[^\]]*\]/gi,
    algo: 'ecdh',
    primitive: 'key-agreement',
    confidence: 'medium',
    note: 'Istio curve list has no hybrid post-quantum group.',
  },
  {
    id: 'k8s-ingress-proxy-ssl-protocols',
    appliesTo: isK8s,
    re: /nginx\.ingress\.kubernetes\.io\/proxy-ssl-protocols\s*:\s*["']?([^"'\n]*\bTLSv1(?:\.1)?(?![\d.])[^"'\n]*)/gi,
    algo: 'tls-1.0',
    primitive: 'protocol',
    confidence: 'medium',
  },

  // ------------------------------------------------------------------ haproxy
  {
    id: 'haproxy-ssl-min-ver-legacy',
    appliesTo: isHAProxy,
    re: /ssl-min-ver\s+(TLSv1(?:\.1)?(?![\d.])|SSLv[23])\b/gi,
    algo: (m) => tlsVersionId(m[1]),
    primitive: 'protocol',
    confidence: 'high',
  },
  {
    id: 'haproxy-ciphers-weak',
    appliesTo: isHAProxy,
    re: /(?:ciphers|ciphersuites)\s+[^\n]*(?:RC4|3DES|DES-CBC3|NULL|EXPORT)[^\n]*/gi,
    algo: (m) => (/RC4/i.test(m[0]) ? 'rc4' : /3DES|DES-CBC3/i.test(m[0]) ? '3des' : 'none'),
    primitive: 'symmetric',
    confidence: 'high',
  },
  {
    id: 'haproxy-classical-curves',
    appliesTo: isHAProxy,
    re: /(?:ssl-default-bind-curves|curves)\s+(?![^\n]*(?:MLKEM|X25519MLKEM768|Kyber))[^\n]*/gi,
    algo: 'ecdh',
    primitive: 'key-agreement',
    confidence: 'medium',
    note: 'HAProxy curve list has no hybrid post-quantum group.',
  },

  // -------------------------------------------------------------------- envoy
  {
    id: 'envoy-min-tls-legacy',
    appliesTo: isEnvoy,
    re: /tls_minimum_protocol_version:\s*TLSv1(?:_[01])?\b/gi,
    algo: (m) => (/TLSv1_1/i.test(m[0]) ? 'tls-1.1' : 'tls-1.0'),
    primitive: 'protocol',
    confidence: 'high',
  },
  {
    id: 'envoy-max-tls-1-2',
    appliesTo: isEnvoy,
    re: /tls_maximum_protocol_version:\s*TLSv1_2\b/gi,
    algo: 'tls-1.2',
    primitive: 'protocol',
    confidence: 'medium',
    note: 'TLS 1.3 is capped off. Remove the maximum so hybrid key exchange can negotiate.',
  },
  {
    id: 'envoy-weak-cipher-suites',
    appliesTo: isEnvoy,
    re: /cipher_suites:\s*\[[^\]]*\b(?:RC4|3DES|DES|NULL|EXPORT)[^\]]*\]/gi,
    algo: (m) => (/RC4/i.test(m[0]) ? 'rc4' : /3DES/i.test(m[0]) ? '3des' : 'none'),
    primitive: 'symmetric',
    confidence: 'high',
  },
  {
    id: 'envoy-classical-ecdh-curves',
    appliesTo: isEnvoy,
    re: /ecdh_curves:\s*\[(?![^\]]*(?:MLKEM|X25519MLKEM768|Kyber))[^\]]*\]/gi,
    algo: 'ecdh',
    primitive: 'key-agreement',
    confidence: 'medium',
  },

  // -------------------------------------------------------------------- caddy
  {
    id: 'caddy-min-version-legacy',
    appliesTo: isCaddy,
    re: /min_version\s+(tls1(?:\.0|\.1))\b/gi,
    algo: (m) => tlsVersionId(m[1]),
    primitive: 'protocol',
    confidence: 'high',
  },
  {
    id: 'caddy-protocols-no-tls13',
    appliesTo: isCaddy,
    re: /protocols\s+(?![^\n}]*tls1\.3)[^\n}]*tls1\.[0-2][^\n}]*/gi,
    algo: 'tls-1.2',
    primitive: 'protocol',
    confidence: 'medium',
  },
  {
    id: 'caddy-weak-ciphers',
    appliesTo: isCaddy,
    re: /(?:ciphers|cipher_suites)\s+[^\n]*(?:RC4|3DES|DES-CBC3|NULL|EXPORT)[^\n]*/gi,
    algo: (m) => (/RC4/i.test(m[0]) ? 'rc4' : /3DES|DES-CBC3/i.test(m[0]) ? '3des' : 'none'),
    primitive: 'symmetric',
    confidence: 'high',
  },
  {
    id: 'caddy-classical-curves',
    appliesTo: isCaddy,
    re: /curves\s+(?![^\n]*(?:MLKEM|X25519MLKEM768|Kyber))[^\n]*/gi,
    algo: 'ecdh',
    primitive: 'key-agreement',
    confidence: 'medium',
  },

  // ------------------------------------------------------------------ traefik
  {
    id: 'traefik-min-version-legacy',
    appliesTo: isTraefik,
    re: /minVersion:\s*"?VersionTLS1(?:\.0|\.1|0|1)?"?/gi,
    algo: (m) => (/TLS1\.1|TLS11/i.test(m[0]) ? 'tls-1.1' : 'tls-1.0'),
    primitive: 'protocol',
    confidence: 'high',
  },
  {
    id: 'traefik-max-version-1-2',
    appliesTo: isTraefik,
    re: /maxVersion:\s*"?VersionTLS12"?/gi,
    algo: 'tls-1.2',
    primitive: 'protocol',
    confidence: 'medium',
  },
  {
    id: 'traefik-weak-cipher-suites',
    appliesTo: isTraefik,
    re: /cipherSuites:\s*\[[^\]]*\bTLS_(?:RSA|ECDHE_RSA)[^\]]*\]/gi,
    algo: 'rsa',
    primitive: 'key-agreement',
    confidence: 'high',
    note: 'Static-RSA cipher suites in Traefik: no forward secrecy.',
  },
  {
    id: 'traefik-classical-curves',
    appliesTo: isTraefik,
    re: /curvePreferences:\s*\[(?![^\]]*(?:MLKEM|X25519MLKEM768|Kyber))[^\]]*\]/gi,
    algo: 'ecdh',
    primitive: 'key-agreement',
    confidence: 'medium',
  },

  // -------------------------------------------------------- cloudflare / edge
  {
    id: 'cloudflare-min-tls-legacy',
    appliesTo: isWrangler,
    re: /min_tls_version\s*=\s*"?(1\.[01])"?/gi,
    algo: (m) => (m[1] === '1.1' ? 'tls-1.1' : 'tls-1.0'),
    primitive: 'protocol',
    confidence: 'high',
  },
  {
    id: 'cloudflare-tls-1-0-enabled',
    appliesTo: isWrangler,
    re: /tls_1_0\s*=\s*"?(?:on|true)"?/gi,
    algo: 'tls-1.0',
    primitive: 'protocol',
    confidence: 'high',
  },

  // --------------------------------------------------------------- dockerfile
  {
    id: 'dockerfile-base-old-openssl',
    appliesTo: isDockerfile,
    re: /FROM\s+\S*(?:node:(?:1[0-9]|2[0-2])(?:[.-]|$)|ubuntu:(?:18\.04|20\.04|22\.04)|debian:(?:buster|bullseye|bookworm)|alpine:3\.(?:1[0-9]|2[0-1])|python:3\.(?:8|9|10|11))/gi,
    algo: 'x25519',
    primitive: 'key-agreement',
    confidence: 'medium',
    note: 'The base image ships OpenSSL older than 3.5, so ML-KEM / ML-DSA are not available by default. Rebuild on a current image before enabling hybrid TLS.',
  },
  {
    id: 'dockerfile-openssl-1-x',
    appliesTo: isDockerfile,
    re: /(?:openssl[=:\s]+1\.[01]\.|libssl1\.[01])/gi,
    algo: 'x25519',
    primitive: 'key-agreement',
    confidence: 'high',
    note: 'OpenSSL 1.0/1.1 has no ML-KEM or ML-DSA support.',
  },

  // -------------------------------------------------------------- ssh / openssl
  {
    id: 'sshd-pubkey-accepted-ssh-rsa',
    appliesTo: isSshd,
    re: /^\s*PubkeyAcceptedAlgorithms\s+([^\n#]*\bssh-rsa\b[^\n#]*)/gim,
    algo: 'ssh-rsa',
    primitive: 'signature',
    confidence: 'high',
    note: 'ssh-rsa uses SHA-1 and is disabled by default in OpenSSH 8.8+. Remove it from the accepted list.',
  },
  {
    id: 'openssl-max-protocol-legacy',
    appliesTo: isOpenssl,
    re: /MaxProtocol\s*=\s*(TLSv1\.1|TLSv1(?![\d.]))/gi,
    algo: (m) => tlsVersionId(m[1]),
    primitive: 'protocol',
    confidence: 'high',
    note: 'A TLS 1.0/1.1 ceiling prevents TLS 1.3 and hybrid key exchange from ever negotiating.',
  },
];

/** Config file extensions we are willing to read as text. */
export const CONFIG_EXTENSIONS = [
  '.conf',
  '.cnf',
  '.cfg',
  '.ini',
  '.yaml',
  '.yml',
  '.config',
  '.properties',
  '.tf',
  '.hcl',
  '.toml',
];

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
  'Caddyfile',
  'haproxy.cfg',
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
  // Dockerfile.dev / Dockerfile.prod / app.dockerfile, and Caddyfile.<suffix>
  if (/^dockerfile([.-]|$)/i.test(lower) || lower.endsWith('.dockerfile')) return true;
  if (/^caddyfile([.-]|$)/i.test(lower)) return true;
  if (CONFIG_EXTENSIONS.some((e) => lower.endsWith(e))) {
    // Do not treat every YAML in a repo as a TLS policy, but the rules are
    // anchored on specific keys so false positives stay rare.
    return true;
  }
  return false;
}
