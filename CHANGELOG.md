# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.0] — 2026-11-09

The release that turns MOSCA from a scanner into a CI-native platform.

### Added

- **Baseline and differential mode.** `--write-baseline` records a run;
  `--baseline` compares against it. Findings are matched with stable,
  line-independent fingerprints, marked `new` or `existing`, and `--fail-on`
  gates only on regressions when a baseline is supplied.
- **Raw SSH prober.** A minimal RFC 4253 exchange sends `SSH_MSG_KEXINIT` and
  parses the server's advertised KEX, host-key, cipher and MAC name-lists.
  Detects `mlkem768x25519-sha256` and
  `sntrup761x25519-sha512@openssh.com`, plus `ssh-rsa`, `ssh-dss`, SHA-1 KEX,
  CBC ciphers and MD5/SHA-1 MACs. New `mosca ssh` command and
  `scan --ssh`.
- **Composite GitHub Action** (`action.yml`) with inputs for TLS, SSH,
  baseline, formats and severity gate.
- **`mosca explain <algorithm>`** — registry-backed migration brief with an
  optional `--json` form.
- **CRQC sensitivity analysis** across 2029, 2033, 2038 and 2045 in the JSON,
  terminal and HTML report.
- **SSH findings in HNDL exposure** — TLS and SSH key exchange now share one
  internet-facing exposure ratio.
- **SSH protocol assets in the CBOM**, and SSH cards in the HTML report.
- **`new` badges and a "new since baseline" filter** in the HTML findings
  table; SARIF results carry `baselineState`.
- **34 new tests** (112 total) for baseline behaviour, SSH wire parsing and
  classification, sensitivity, SSH-aware HNDL, SARIF and CBOM.

### Changed

- SARIF `partialFingerprints.moscaFingerprint` is now line-independent, so
  moving code does not re-open an alert.
- The terminal summary splits inspected endpoints into TLS and SSH.
- `--fail-on` evaluates only new findings when a baseline is present.

## [1.0.0] — 2026-11-04

First release.

### Added

- **Raw TLS ClientHello prober** that offers `X25519MLKEM768` (0x11EC),
  `X25519Kyber768Draft00` (0x11EB and 0x6399), classical ECDHE and FFDHE
  groups, and reports the group selected by the server. Includes canonical
  ML-KEM-768 encapsulation keys and the correct ML-KEM-then-X25519 share order.
- **Dependency-free DER/X.509 parser** classifying signature algorithm, public
  key algorithm, curve, SAN, key usage and validity.
- **Endpoint inspection** combining a real Node handshake with the raw probe,
  plus a legacy TLS 1.0/1.1 acceptance check.
- **148 source rules** across JavaScript, TypeScript, Python, Java, Kotlin, Go,
  C, C++, C#, Rust, PHP, Ruby, Shell, PowerShell, Swift and Scala.
- **23 configuration rules** for nginx, Apache, OpenSSH, OpenSSL,
  `java.security` and Kubernetes ingress annotations.
- **91-entry algorithm registry** with quantum and classical classifications,
  NIST levels, aliases, standards and primitive-aware replacements.
- **Mosca-inequality risk engine**: shelf life, migration lead time, weighted
  score, severity bands, Quantum Readiness Index, HNDL exposure and a phased
  migration roadmap.
- **Interactive HTML report** — single file, no network requests, CRQC slider,
  findings filters, endpoint cards, algorithm inventory, roadmap.
- **CycloneDX 1.6 CBOM** with `cryptographic-asset` components, certificates
  and protocols.
- **SARIF 2.1.0** output with stable fingerprints for GitHub code scanning.
- **CLI** with `scan`, `tls`, `demo`, `init` and `rules`, plus `--fail-on` for
  CI gating.
- **Zero runtime and development dependencies**, enforced by
  `scripts/check-zero-deps.js` and CI.
- **Inline suppressions** (`mosca-ignore-line`, `mosca-ignore-next-line`,
  `mosca-ignore-file`) with mandatory-reason convention and an auditable
  suppressed count in the terminal report.
- **91 tests** covering the registry, rules, wire format, DER parsing, risk
  model, report schemas and end-to-end scans.
- Synthetic vulnerable estate in `examples/vulnerable-app/` for evaluation.

### Fixed

- TLS 1.2 `minVersion` no longer reported as a legacy floor.
- `!aNULL` in an nginx cipher list no longer reported as a NULL cipher.
- `MinProtocol = TLSv1.3` no longer reported as a legacy floor.
- Go and C TLS rules distinguish a minimum-version floor from a maximum-version
  cap.
- `HelloRetryRequest` detection now uses the actual
  `SHA-256("HelloRetryRequest")` value.
- Node's `TLSv1.3` protocol spelling is normalised before comparison, so a
  modern endpoint is not labelled legacy.
- RSA replacements are chosen by usage: ML-KEM-768 for encryption, ML-DSA-65
  for signatures.
- A key-generation call is reported once, with the more specific key size.
- The HTML report's CBOM download now embeds the real CycloneDX document
  instead of producing an empty object.

[Unreleased]: https://github.com/sultanbajamil/mosca/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/sultanbajamil/mosca/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/sultanbajamil/mosca/releases/tag/v1.0.0
