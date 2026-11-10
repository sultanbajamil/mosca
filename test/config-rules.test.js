/**
 * v3 IaC and edge-proxy rules. Each case is a realistic fragment of the file
 * the rule targets, so the test proves both the pattern and the file-type
 * predicate that guards it.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { scanConfigContent } from '../src/scan/config.js';
import { CONFIG_RULES, CONFIG_EXTENSIONS, isConfigFile } from '../src/rules/config.js';

const ids = (findings) => findings.map((f) => f.id);
const algorithms = (findings) => findings.map((f) => f.algorithm);
const scan = (rel, content) => scanConfigContent({ rel, content });

test('the v3 rule inventory has grown past fifty rules', () => {
  assert.ok(CONFIG_RULES.length >= 50, `only ${CONFIG_RULES.length} config rules`);
  for (const ext of ['.tf', '.hcl', '.toml', '.yaml']) {
    assert.ok(CONFIG_EXTENSIONS.includes(ext), `missing extension ${ext}`);
  }
  // Every rule must carry the fields the scanner depends on.
  for (const rule of CONFIG_RULES) {
    assert.equal(typeof rule.id, 'string');
    assert.equal(rule.appliesTo instanceof Function, true);
    assert.equal(rule.re instanceof RegExp, true);
  }
});

test('config detection recognises IaC and proxy filenames', () => {
  assert.equal(isConfigFile('infra/main.tf'), true);
  assert.equal(isConfigFile('deploy/variables.hcl'), true);
  assert.equal(isConfigFile('Caddyfile'), true);
  assert.equal(isConfigFile('haproxy.cfg'), true);
  assert.equal(isConfigFile('deploy/Dockerfile.prod'), true);
  assert.equal(isConfigFile('build/app.dockerfile'), true);
  assert.equal(isConfigFile('traefik.toml'), true);
  assert.equal(isConfigFile('src/app.ts'), false);
});

test('terraform: AWS KMS key specs and ALB policies are classified', () => {
  const rsa = scan('infra/kms.tf', 'resource "aws_kms_key" "a" {\n  key_spec = "RSA_2048"\n}');
  assert.ok(ids(rsa).includes('tf-aws-kms-rsa'));
  assert.ok(algorithms(rsa).includes('rsa-2048'));

  const ecc = scan('infra/kms.tf', 'key_spec = "ECC_NIST_P384"');
  assert.ok(algorithms(ecc).includes('ecdsa'));

  const policy = scan('infra/alb.tf', 'ssl_policy = "ELBSecurityPolicy-2016-08"');
  assert.ok(ids(policy).includes('tf-alb-legacy-ssl-policy'));
  assert.ok(algorithms(policy).includes('tls-1.1'));

  const cloudfront = scan('infra/cdn.tf', 'minimum_protocol_version = "TLSv1"');
  assert.ok(algorithms(cloudfront).includes('tls-1.0'));
});

test('terraform: cloud KMS algorithms and sizes map to the registry', () => {
  const google = scan('infra/gcp.tf', 'algorithm = "RSA_SIGN_PKCS1_2048_SHA256"');
  assert.ok(algorithms(google).includes('rsa-2048'));

  const azure = scan('infra/azure.tf', 'key_size = 2048');
  assert.ok(ids(azure).includes('tf-azure-key-size'));
  assert.ok(algorithms(azure).includes('rsa-2048'));

  const cloudflare = scan('infra/cf.tf', 'min_tls_version = "1.0"');
  assert.ok(ids(cloudflare).includes('tf-cloudflare-min-tls'));
});

test('cert-manager manifests flag RSA issuance', () => {
  const content = ['privateKey:', '  algorithm: RSA', '  size: 2048'].join('\n');
  const found = scan('deploy/cert-issuer.yaml', content);
  assert.ok(ids(found).includes('k8s-cert-manager-rsa'));
  assert.ok(ids(found).includes('k8s-cert-manager-key-size'));
  assert.ok(algorithms(found).includes('rsa-2048'));
});

test('istio manifests flag legacy protocol floors and classical curves', () => {
  const content = [
    'minProtocolVersion: TLSV1_0',
    'cipherSuites: [RC4-SHA]',
    'ecdhCurves: [P-256]',
  ].join('\n');
  const found = scan('deploy/istio-gateway.yaml', content);
  assert.ok(ids(found).includes('istio-min-tls-1-0'));
  assert.ok(ids(found).includes('istio-weak-cipher-suites'));
  assert.ok(ids(found).includes('istio-classical-ecdh-curves'));
});

test('haproxy: legacy minimum version and weak ciphers are found', () => {
  const content = ['global', '  ssl-min-ver TLSv1', '  ciphers RC4-SHA:ECDHE-RSA-AES128-GCM-SHA256'].join('\n');
  const found = scan('infra/haproxy.cfg', content);
  assert.ok(ids(found).includes('haproxy-ssl-min-ver-legacy'));
  assert.ok(ids(found).includes('haproxy-ciphers-weak'));
  assert.ok(algorithms(found).includes('tls-1.0'));
});

test('haproxy: a hybrid curve list is not flagged as classical', () => {
  const hybrid = scan('infra/haproxy.cfg', 'ssl-default-bind-curves X25519MLKEM768:X25519');
  assert.ok(!ids(hybrid).includes('haproxy-classical-curves'));

  const classical = scan('infra/haproxy.cfg', 'ssl-default-bind-curves P-256:X25519');
  assert.ok(ids(classical).includes('haproxy-classical-curves'));
});

test('envoy: protocol floor, ceiling and cipher suites are found', () => {
  const content = [
    'tls_minimum_protocol_version: TLSv1_1',
    'tls_maximum_protocol_version: TLSv1_2',
    'cipher_suites: [RC4-SHA]',
    'ecdh_curves: [X25519]',
  ].join('\n');
  const found = scan('config/envoy.yaml', content);
  assert.ok(ids(found).includes('envoy-min-tls-legacy'));
  assert.ok(ids(found).includes('envoy-max-tls-1-2'));
  assert.ok(ids(found).includes('envoy-weak-cipher-suites'));
  assert.ok(ids(found).includes('envoy-classical-ecdh-curves'));
});

test('caddy: legacy protocols and classical curves are found', () => {
  const found = scan('Caddyfile', ['tls {', '  protocols tls1.0 tls1.2', '  curves X25519', '}'].join('\n'));
  assert.ok(ids(found).includes('caddy-protocols-no-tls13'));
  assert.ok(ids(found).includes('caddy-classical-curves'));

  assert.ok(ids(scan('Caddyfile', 'min_version tls1.1')).includes('caddy-min-version-legacy'));
});

test('traefik: version bounds, classical curves and RSA suites are found', () => {
  const content = [
    'tls:',
    '  options:',
    '    minVersion: VersionTLS11',
    '    maxVersion: VersionTLS12',
    '    curvePreferences: [CurveP256]',
    '    cipherSuites: [TLS_RSA_WITH_AES_128_CBC_SHA]',
  ].join('\n');
  const found = scan('traefik.yml', content);
  assert.ok(ids(found).includes('traefik-min-version-legacy'));
  assert.ok(ids(found).includes('traefik-max-version-1-2'));
  assert.ok(ids(found).includes('traefik-classical-curves'));
  assert.ok(ids(found).includes('traefik-weak-cipher-suites'));
});

test('cloudflare configuration flags TLS 1.0', () => {
  const found = scan('wrangler.toml', ['min_tls_version = "1.0"', 'tls_1_0 = "on"'].join('\n'));
  assert.ok(ids(found).includes('cloudflare-min-tls-legacy'));
  assert.ok(ids(found).includes('cloudflare-tls-1-0-enabled'));
});

test('dockerfiles flag pre-PQC base images and OpenSSL 1.x', () => {
  const content = ['FROM node:18-alpine', 'RUN apk add openssl=1.1.1'].join('\n');
  const found = scan('Dockerfile', content);
  assert.ok(ids(found).includes('dockerfile-base-old-openssl'));
  assert.ok(ids(found).includes('dockerfile-openssl-1-x'));
});

test('a modern config stays silent across proxy rules', () => {
  const caddy = scan(
    'Caddyfile',
    ['tls {', '  protocols tls1.2 tls1.3', '  curves X25519MLKEM768 X25519', '}'].join('\n'),
  );
  assert.deepEqual(ids(caddy), []);

  const haproxy = scan(
    'infra/haproxy.cfg',
    ['global', '  ssl-min-ver TLSv1.3', '  ssl-default-bind-curves X25519MLKEM768'].join('\n'),
  );
  assert.deepEqual(ids(haproxy), []);
});
